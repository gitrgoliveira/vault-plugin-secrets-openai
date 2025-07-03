// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

// Package openaisecrets implements a HashiCorp Vault secrets engine plugin
// for managing OpenAI API keys and credentials. The plugin provides dynamic
// credential generation, admin key rotation, and secure credential management
// for OpenAI services.
package openaisecrets

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-metrics"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// ClientAPI defines the interface for OpenAI client operations used by the backend
// This allows for mocking in tests.
type ClientAPI interface {
	CreateServiceAccount(ctx context.Context, projectID string, req CreateServiceAccountRequest) (*ServiceAccount, *APIKey, error)
	DeleteServiceAccount(ctx context.Context, id string, projectID ...string) error
	SetConfig(config *Config) error
	ListServiceAccounts(ctx context.Context, projectID string) ([]*ServiceAccount, error)
	GetServiceAccount(ctx context.Context, serviceAccountID, projectID string) (*ServiceAccount, error)
	ValidateProject(ctx context.Context, projectID string) error
	GetProject(ctx context.Context, projectID string) (*ProjectInfo, error)
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	// Create a new OpenAI client with the logger from the backend config
	openaiClient := NewClient("", conf.Logger)
	b := Backend(openaiClient)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend(client ClientAPI) *backend {
	// Extract logger from the client if possible
	var logger hclog.Logger
	if c, ok := client.(*Client); ok && c != nil {
		logger = c.logger
	} else {
		logger = hclog.NewNullLogger()
	}

	b := &backend{
		client:       client,
		roleLocks:    locksutil.CreateLocks(),
		managedUsers: make(map[string]struct{}),
		logger:       logger,
	}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				configPath,
				// Add any other sensitive storage paths here
			},
		},
		Paths: framework.PathAppend(
			b.pathAdminConfig(),
			b.pathDynamicSvcAccount(),
			b.pathDynamicCredsCreate(),
		),
		InitializeFunc: b.initialize,
		Secrets: []*framework.Secret{
			dynamicSecretCreds(b),
		},
		Clean:            b.clean,
		BackendType:      logical.TypeLogical,
		RotateCredential: b.rotateRootCredential,
	}

	return b
}

func (b *backend) Setup(ctx context.Context, conf *logical.BackendConfig) error {
	// Call the parent Setup method to ensure system view is properly set
	if err := b.Backend.Setup(ctx, conf); err != nil {
		return err
	}

	// Update the logger from the config if provided
	if conf.Logger != nil {
		// Update both the backend logger and the client logger if possible
		b.logger = conf.Logger
		if c, ok := b.client.(*Client); ok && c != nil {
			c.logger = conf.Logger
		}
	}
	return nil
}

func (b *backend) initialize(ctx context.Context, initRequest *logical.InitializationRequest) error {
	// Store the storage view for later use with cleanup manager
	b.storageView = initRequest.Storage

	// Load configuration from storage
	config, err := getConfig(ctx, initRequest.Storage)
	if err != nil {
		return err
	}

	// Initialize the client if config exists
	if config != nil {
		b.client = NewClient(config.AdminAPIKey, b.Logger())

		// Configure the client with full config including organization ID
		clientConfig := &Config{
			AdminAPIKey:    config.AdminAPIKey,
			APIEndpoint:    config.APIEndpoint,
			OrganizationID: config.OrganizationID,
		}

		if err := b.client.SetConfig(clientConfig); err != nil {
			return err
		}
	}

	return nil
}

func (b *backend) clean(_ context.Context) {
	// Cleanup any resources
}

type backend struct {
	*framework.Backend
	sync.RWMutex

	// client is the OpenAI API client used to interact with the OpenAI API
	client ClientAPI

	// logger stores the plugin's logger
	logger hclog.Logger

	// roleLocks is used to lock modifications to roles in the queue, to ensure
	// concurrent requests are not modifying the same role and possibly causing
	// issues with the priority queue.
	roleLocks []*locksutil.LockEntry

	// managedUsers contains the set of OpenAI service accounts managed by the secrets engine
	// This is used to ensure that service accounts are not duplicated.
	managedUsers map[string]struct{}
	storageView  logical.Storage
}

// Logger returns the backend's logger
func (b *backend) Logger() hclog.Logger {
	if b.logger != nil {
		return b.logger
	}
	return hclog.NewNullLogger()
}

const backendHelp = `
The OpenAI secrets engine creates dynamic API keys for OpenAI:

 * Create project service accounts in OpenAI projects
 * Generate API keys for those service accounts
 * Automatic cleanup of service accounts and API keys
 
The OpenAI secrets engine requires Admin API keys.

After mounting this secrets engine, configure it using the "openai/config" path.
`

// Label represents a key-value pair for metric labels.
type Label struct {
	Name  string
	Value string
}

// IncrCounterWithLabelsFuncType defines the function signature for metric emission
// so it can be swapped in tests.
type IncrCounterWithLabelsFuncType func(ctx context.Context, name []string, value float32, labels []Label)

// IncrCounterWithLabels is a variable so it can be replaced in tests.
var IncrCounterWithLabels IncrCounterWithLabelsFuncType = func(ctx context.Context, name []string, value float32, labels []Label) {
	var mLabels []metrics.Label
	for _, l := range labels {
		mLabels = append(mLabels, metrics.Label{Name: l.Name, Value: l.Value})
	}
	metrics.IncrCounterWithLabels(name, value, mLabels)
}

// Emit a metric when a credential is issued
func (b *backend) emitCredentialIssuedMetric(role string) {
	b.Logger().Info("emitCredentialIssuedMetric called", "role", role)
	IncrCounterWithLabels(context.Background(), []string{"openai", "creds", "issued"}, 1, []Label{{Name: "role", Value: role}})
}

// Emit a metric when a credential is revoked
func (b *backend) emitCredentialRevokedMetric(role string) {
	b.Logger().Info("emitCredentialRevokedMetric called", "role", role)
	IncrCounterWithLabels(context.Background(), []string{"openai", "creds", "revoked"}, 1, []Label{{Name: "role", Value: role}})
}

// Emit a metric when an API error occurs
func (b *backend) emitAPIErrorMetric(endpoint, code string) {
	IncrCounterWithLabels(context.Background(), []string{"openai", "api", "error"}, 1, []Label{{Name: "endpoint", Value: endpoint}, {Name: "code", Value: code}})
}

// rotateRootCredential implements the RotateCredential interface for Vault's rotation framework
func (b *backend) rotateRootCredential(ctx context.Context, req *logical.Request) error {
	b.Logger().Info("Root credential rotation triggered by Vault's rotation framework")

	// Call the existing rotation implementation
	rotated, err := b.rotateAdminAPIKey(ctx, req.Storage)
	if err != nil {
		return err
	}

	if !rotated {
		return fmt.Errorf("admin API key rotation failed: no API key configured")
	}

	b.Logger().Info("Root credential rotation completed successfully")
	return nil
}
