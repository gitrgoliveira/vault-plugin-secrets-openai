// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_SetConfig(t *testing.T) {
	logger := hclog.NewNullLogger()
	client := NewClient("test-key", logger)

	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &Config{
				AdminAPIKey:    "test-key",
				APIEndpoint:    "https://api.test.com/v1",
				OrganizationID: "org-123",
			},
			expectError: false,
		},
		{
			name: "missing admin API key",
			config: &Config{
				AdminAPIKey:    "",
				OrganizationID: "org-123",
			},
			expectError: true,
		},
		{
			name: "missing organization ID",
			config: &Config{
				AdminAPIKey:    "test-key",
				OrganizationID: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.SetConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.config.AdminAPIKey, client.adminAPIKey)
				assert.Equal(t, tt.config.APIEndpoint, client.apiEndpoint)
				assert.Equal(t, tt.config.OrganizationID, client.organizationID)
			}
		})
	}
}

func TestClient_CreateServiceAccount(t *testing.T) {
	// Setup a mock server
	mockSvcAccount := ServiceAccount{
		ID:          "svc_123",
		ProjectID:   "proj_456",
		Name:        "test-svc-account",
		Description: "Test service account",
		CreatedAt:   timePtr(time.Now()),
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method and path
		assert.Equal(t, http.MethodPost, r.Method)
		// Accept only the correct new path
		expectedPath := "/v1/organization/projects/proj_456/service_accounts"
		if r.URL.Path != expectedPath {
			t.Fatalf("unexpected path: got %q, want %q", r.URL.Path, expectedPath)
		}

		// Check headers
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "org-123", r.Header.Get("OpenAI-Organization"))
		assert.Equal(t, "project-service-accounts=v1", r.Header.Get("OpenAI-Beta"))

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(mockSvcAccount); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}))
	defer mockServer.Close()

	// Create client with mock server URL
	logger := hclog.NewNullLogger()
	client := NewClient("test-key", logger)
	err := client.SetConfig(&Config{
		AdminAPIKey:    "test-key",
		APIEndpoint:    mockServer.URL + "/v1",
		OrganizationID: "org-123",
	})
	require.NoError(t, err)

	// Call the function
	ctx := context.Background()
	svcAccount, err := client.CreateServiceAccount(ctx, "proj_456", CreateServiceAccountRequest{
		Name:        "test-svc-account",
		Description: "Test service account",
	})

	// Assert expectations
	require.NoError(t, err)
	assert.Equal(t, mockSvcAccount.ID, svcAccount.ID)
	assert.Equal(t, mockSvcAccount.ProjectID, svcAccount.ProjectID)
	assert.Equal(t, mockSvcAccount.Name, svcAccount.Name)
	assert.Equal(t, mockSvcAccount.Description, svcAccount.Description)
}

func TestClient_TestConnection(t *testing.T) {
	// Start mock OpenAI server
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	logger := hclog.NewNullLogger()
	client := NewClient("test-key", logger)
	err := client.SetConfig(&Config{
		AdminAPIKey:    "test-key",
		APIEndpoint:    mockServer.URL() + "/v1",
		OrganizationID: "org-123",
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = client.TestConnection(ctx)
	assert.NoError(t, err)
}
