// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-metrics"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

// ClientAPI defines the interface for OpenAI client operations used by the backend
// This allows for mocking in tests.
type ClientAPI interface {
	CreateServiceAccount(ctx context.Context, req CreateServiceAccountRequest) (*ServiceAccount, error)
	CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (*APIKey, error)
	DeleteServiceAccount(ctx context.Context, id string, projectID ...string) error
	DeleteAPIKey(ctx context.Context, id string) error
	SetConfig(config *Config) error
	ListServiceAccounts(ctx context.Context, projectID string) ([]*ServiceAccount, error)
	GetServiceAccount(ctx context.Context, serviceAccountID, projectID string) (*ServiceAccount, error)
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend() *backend {
	b := &backend{
		client:            nil, // Will be initialized during config
		credRotationQueue: queue.New(),
		roleLocks:         locksutil.CreateLocks(),
		checkOutLocks:     locksutil.CreateLocks(),
		managedUsers:      make(map[string]struct{}),
	}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				configPath,
			},
		},
		Paths: framework.PathAppend(
			// Configuration paths
			b.pathAdminConfig(),
			b.pathProjectConfig(),

			// Dynamic credential paths
			b.pathDynamicSvcAccount(),
			b.pathDynamicCredsCreate(),

			// Static credential paths
			b.pathStaticRoles(),

			// Library and check-in/check-out paths
			b.pathListSets(),
			b.pathSets(),
			b.pathSetCheckOut(),
			b.pathSetCheckIn(),
			b.pathSetManageCheckIn(),
			b.pathSetStatus(),
		),
		InitializeFunc: b.initialize,
		Secrets: []*framework.Secret{
			dynamicSecretCreds(b),
			// Static credentials don't generate secrets as they are persistent
			checkoutSecretCreds(b),
		},
		Clean:       b.clean,
		BackendType: logical.TypeLogical,
	}

	return b
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

		// Initialize and start the cleanup manager if client is configured
		b.cleanupManager = NewCleanupManager(b)
		b.cleanupManager.Start()
		b.Logger().Info("Started cleanup manager for orphaned service accounts")

		// Initialize the rotation queue for static roles
		b.initRotationQueue(ctx, initRequest.Storage)

		// Check if admin key needs immediate rotation first
		if err := b.checkAdminKeyRotation(ctx, initRequest.Storage); err != nil {
			b.Logger().Warn("Admin key rotation check failed", "error", err)
			// Non-fatal error, continue initialization
		}

		// Configure the rotation job if config requests it
		if config.ShouldRegisterRotationJob() {
			b.Logger().Info("Setting up automated admin key rotation with Vault's rotation framework")
			if err := b.setupAdminKeyRotation(ctx, initRequest.Storage); err != nil {
				b.Logger().Error("Failed to setup automated admin key rotation", "error", err)
				// Non-fatal error, continue initialization
			} else {
				b.Logger().Info("Automated admin key rotation successfully configured")
			}
		} else if config.RotationDuration > 0 {
			// Fall back to legacy queue-based rotation if rotation manager isn't available
			b.Logger().Info("Admin key legacy rotation enabled", "period", config.RotationPeriod)
			if err := b.scheduleAdminKeyRotation(ctx, initRequest.Storage); err != nil {
				b.Logger().Error("Failed to schedule admin key rotation", "error", err)
			}
		} else {
			b.Logger().Info("Admin key rotation is disabled")
		}
	}

	return nil
}

func (b *backend) clean(_ context.Context) {
	// Stop the queue first
	b.invalidateQueue()

	// Stop the cleanup manager if it exists
	if b.cleanupManager != nil {
		b.Logger().Info("Stopping cleanup manager")
		b.cleanupManager.Stop()
	}

	// No rotation job to unregister
}

// invalidateQueue cancels any background queue loading and destroys the queue.
func (b *backend) invalidateQueue() {
	b.Lock()
	defer b.Unlock()

	if b.cancelQueue != nil {
		b.cancelQueue()
	}
	b.credRotationQueue = nil
}

type backend struct {
	*framework.Backend
	sync.RWMutex

	// client is the OpenAI API client used to interact with the OpenAI API
	client ClientAPI

	// CredRotationQueue is an in-memory priority queue used to track Static Roles
	// that require periodic rotation. Backends will have a PriorityQueue
	// initialized on setup, but only backends that are mounted by a primary
	// server or mounted as a local mount will perform the rotations.
	//
	// cancelQueue is used to remove the priority queue and terminate the
	// background ticker.
	credRotationQueue *queue.PriorityQueue
	cancelQueue       context.CancelFunc

	// roleLocks is used to lock modifications to roles in the queue, to ensure
	// concurrent requests are not modifying the same role and possibly causing
	// issues with the priority queue.
	roleLocks []*locksutil.LockEntry

	// managedUsers contains the set of OpenAI service accounts managed by the secrets engine
	// This is used to ensure that service accounts are not duplicated.
	managedUsers    map[string]struct{}
	managedUserLock sync.Mutex

	// checkOutLocks are used for avoiding races when working with library sets
	// in the check-in/check-out system.
	checkOutLocks []*locksutil.LockEntry

	// cleanupManager handles periodic cleanup of orphaned service accounts
	cleanupManager *CleanupManager
	storageView    logical.Storage
}

// Logger returns the backend's logger
func (b *backend) Logger() hclog.Logger {
	return b.Backend.Logger()
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
