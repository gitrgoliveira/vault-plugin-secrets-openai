// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// Project represents the OpenAI project details response used in tests.
type Project struct {
	ID     string
	Name   string
	Status string
}

// Advanced mockClient for flexible test mocking
// (replaces the simple mockClient above)
type mockClient struct {
	createServiceAccountFn func(ctx context.Context, projectID string, req CreateServiceAccountRequest) (*ServiceAccount, *APIKey, error)
	deleteServiceAccountFn func(ctx context.Context, id string, projectID ...string) error
	deleteAPIKeyFn         func(ctx context.Context, id string) error
	setConfigFn            func(config *Config) error
	listServiceAccountsFn  func(ctx context.Context, projectID string) ([]*ServiceAccount, error)
	getServiceAccountFn    func(ctx context.Context, serviceAccountID, projectID string) (*ServiceAccount, error)

	lastDeletedAPIKeyID string
}

func (m *mockClient) CreateServiceAccount(ctx context.Context, projectID string, req CreateServiceAccountRequest) (*ServiceAccount, *APIKey, error) {
	if m.createServiceAccountFn != nil {
		return m.createServiceAccountFn(ctx, projectID, req)
	}
	serviceAccount := &ServiceAccount{ID: "svc-123", Name: req.Name, ProjectID: projectID}
	apiKey := &APIKey{ID: "key-123", Value: "sk-test", ServiceAccID: serviceAccount.ID}
	return serviceAccount, apiKey, nil
}
func (m *mockClient) DeleteServiceAccount(ctx context.Context, id string, projectID ...string) error {
	if m.deleteServiceAccountFn != nil {
		return m.deleteServiceAccountFn(ctx, id, projectID...)
	}
	return nil
}
func (m *mockClient) DeleteAPIKey(ctx context.Context, id string) error {
	m.lastDeletedAPIKeyID = id
	if m.deleteAPIKeyFn != nil {
		return m.deleteAPIKeyFn(ctx, id)
	}
	return nil
}
func (m *mockClient) SetConfig(config *Config) error {
	if m.setConfigFn != nil {
		return m.setConfigFn(config)
	}
	return nil
}
func (m *mockClient) ListServiceAccounts(ctx context.Context, projectID string) ([]*ServiceAccount, error) {
	if m.listServiceAccountsFn != nil {
		return m.listServiceAccountsFn(ctx, projectID)
	}
	return []*ServiceAccount{{ID: "svc-123", ProjectID: projectID}}, nil
}
func (m *mockClient) GetServiceAccount(ctx context.Context, serviceAccountID, projectID string) (*ServiceAccount, error) {
	if m.getServiceAccountFn != nil {
		return m.getServiceAccountFn(ctx, serviceAccountID, projectID)
	}
	return &ServiceAccount{ID: serviceAccountID, ProjectID: projectID}, nil
}

// Ensure mockClient implements GetProject to satisfy ClientAPI interface for all test cases.
func (m *mockClient) GetProject(ctx context.Context, projectID string) (*ProjectInfo, error) {
	// Return a dummy project or error as needed for tests
	return &ProjectInfo{ID: projectID, Name: "mock-project", Status: "active"}, nil
}

// Removed unused field getProjectFn to resolve staticcheck error and improve code quality.

func (m *mockClient) ValidateProject(ctx context.Context, projectID string) error {
	// For tests, assume all project IDs are valid unless overridden
	if m != nil && m.listServiceAccountsFn != nil {
		_, err := m.ListServiceAccounts(ctx, projectID)
		return err
	}
	return nil
}

// getTestBackend returns a configured backend for testing.
func getTestBackend(t *testing.T) *backend {
	b := Backend()
	b.client = &mockClient{}
	config := logical.TestBackendConfig()
	config.Logger = hclog.NewNullLogger()
	config.System = &logical.StaticSystemView{
		DefaultLeaseTTLVal: defaultTTL,
		MaxLeaseTTLVal:     maxTTL,
	}

	err := b.Setup(context.Background(), config)
	require.NoError(t, err)

	return b
}

// getTestStorage returns an in-memory storage for testing.
func getTestStorage(t *testing.T) logical.Storage {
	return &logical.InmemStorage{}
}

// insertTestProject creates a test project entry in storage.
func insertTestProject(ctx context.Context, t *testing.T, storage logical.Storage, name string) {
	project := &projectEntry{
		ProjectID: name + "_id",
		Name:      name,
	}

	entry, err := logical.StorageEntryJSON("project/"+name, project)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))
}

// insertTestRole creates a test dynamic role entry in storage.
func insertTestRole(ctx context.Context, t *testing.T, storage logical.Storage, name string, projectName string) {
	role := &dynamicRoleEntry{
		ProjectID:                  projectName,
		ServiceAccountNameTemplate: "vault-{{.RoleName}}-{{.RandomSuffix}}",
		ServiceAccountDescription:  "Test service account for " + name,
		TTL:                        defaultTTL,
		MaxTTL:                     maxTTL,
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, role)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))
}

// Default TTL and MaxTTL for test roles
const (
	defaultTTL = 3600
	maxTTL     = 86400
)
