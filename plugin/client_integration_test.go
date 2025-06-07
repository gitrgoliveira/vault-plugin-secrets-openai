// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientIntegration_CompleteWorkflow tests the complete workflow of:
// 1. Creating a service account (which automatically creates an API key)
// 2. Retrieving the service account
// 3. Listing service accounts
// 4. Deleting the API key
// 5. Deleting the service account
// 6. Verifying deletion and error handling
func TestClientIntegration_CompleteWorkflow(t *testing.T) {
	// Create a mock server
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	// Create a client with the mock server
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "openai-test",
		Level: hclog.Debug,
	})
	client := NewClient("test-key", logger)
	err := client.SetConfig(&Config{
		AdminAPIKey:    "test-key",
		APIEndpoint:    mockServer.URL() + "/v1",
		OrganizationID: "org-123",
	})
	require.NoError(t, err)

	ctx := context.Background()
	projectID := "proj_123"

	// 1. Create a service account (which also creates an API key automatically)
	svcAcc, apiKey, err := client.CreateServiceAccount(ctx, projectID, CreateServiceAccountRequest{
		Name:        "test-service-account",
		Description: "Test service account for integration test",
	})
	require.NoError(t, err)
	require.NotNil(t, svcAcc)
	assert.NotEmpty(t, svcAcc.ID)
	assert.Equal(t, "test-service-account", svcAcc.Name)
	assert.Equal(t, projectID, svcAcc.ProjectID)

	// Verify the API key was created with the service account
	require.NotNil(t, apiKey)
	assert.NotEmpty(t, apiKey.ID)
	assert.NotEmpty(t, apiKey.Value) // API key value should be available on creation
	assert.Equal(t, svcAcc.ID, apiKey.ServiceAccID)

	// 2. Retrieve the service account
	retrievedSvcAcc, err := client.GetServiceAccount(ctx, svcAcc.ID, projectID)
	require.NoError(t, err)
	require.NotNil(t, retrievedSvcAcc)
	assert.Equal(t, svcAcc.ID, retrievedSvcAcc.ID)
	assert.Equal(t, svcAcc.Name, retrievedSvcAcc.Name)
	assert.Equal(t, svcAcc.ProjectID, retrievedSvcAcc.ProjectID)

	// 3. List service accounts
	accounts, err := client.ListServiceAccounts(ctx, projectID)
	require.NoError(t, err)
	assert.Len(t, accounts, 1)
	assert.Equal(t, svcAcc.ID, accounts[0].ID)

	// 4. Delete the API key
	err = client.DeleteAPIKey(ctx, apiKey.ID)
	require.NoError(t, err)

	// 5. Delete the service account
	err = client.DeleteServiceAccount(ctx, svcAcc.ID, projectID)
	require.NoError(t, err)

	// 6. Verify service account was deleted by listing again
	accounts, err = client.ListServiceAccounts(ctx, projectID)
	require.NoError(t, err)
	assert.Len(t, accounts, 0)

	// 7. Attempt to retrieve the deleted service account (should fail)
	retrievedSvcAcc, err = client.GetServiceAccount(ctx, svcAcc.ID, projectID)
	assert.Error(t, err)
	assert.Nil(t, retrievedSvcAcc)
}

// TestClientIntegration_ErrorHandling tests the error handling for different API failures
func TestClientIntegration_ErrorHandling(t *testing.T) {
	// Create a mock server
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	// Create a client with the mock server
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "openai-test",
		Level: hclog.Debug,
	})
	client := NewClient("test-key", logger)
	err := client.SetConfig(&Config{
		AdminAPIKey:    "test-key",
		APIEndpoint:    mockServer.URL() + "/v1",
		OrganizationID: "org-123",
	})
	require.NoError(t, err)

	ctx := context.Background()
	projectID := "proj_456"

	// Set up a successful service account first
	svcAcc, apiKey, err := client.CreateServiceAccount(ctx, projectID, CreateServiceAccountRequest{
		Name:        "test-service-account",
		Description: "Test service account for error handling test",
	})
	require.NoError(t, err)
	require.NotNil(t, svcAcc)
	require.NotNil(t, apiKey)

	// Test 1: Service account deletion failure
	mockServer.SetFailureMode("delete_svc_acc", 429, "Rate limit exceeded")
	err = client.DeleteServiceAccount(ctx, svcAcc.ID, projectID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API error (429)")

	// Clear failure mode
	mockServer.ClearFailureMode()

	// Test 2: Invalid service account ID
	_, err = client.GetServiceAccount(ctx, "nonexistent", projectID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Service account not found")

	// Test 3: Invalid project ID
	accounts, err := client.ListServiceAccounts(ctx, "nonexistent-project")
	require.NoError(t, err) // Should return empty list, not error
	assert.Len(t, accounts, 0)
}

// TestClientIntegration_ServiceAccountNameValidation tests the validation of service account names
func TestClientIntegration_ServiceAccountNameValidation(t *testing.T) {
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "openai-test",
		Level: hclog.Debug,
	})
	client := NewClient("test-key", logger)
	err := client.SetConfig(&Config{
		AdminAPIKey:    "test-key",
		APIEndpoint:    mockServer.URL() + "/v1",
		OrganizationID: "org-123",
	})
	require.NoError(t, err)

	ctx := context.Background()
	projectID := "proj_789"

	// Test cases for service account name validation
	testCases := []struct {
		name        string
		serviceName string
		expectError bool
	}{
		{
			name:        "valid name",
			serviceName: "valid-name",
			expectError: false,
		},
		{
			name:        "empty name",
			serviceName: "",
			expectError: true,
		},
		// Add more test cases when implementing the name validation requirements
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := client.CreateServiceAccount(ctx, projectID, CreateServiceAccountRequest{
				Name: tc.serviceName,
			})

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
