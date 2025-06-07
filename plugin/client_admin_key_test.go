// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// TestCreateAdminAPIKeyNew tests the new API response format for admin keys
func TestCreateAdminAPIKeyNew(t *testing.T) {
	// Test the standard response format with the value field
	adminKey := "sk-admin-1234abcd"
	adminKeyID := "key_xyz"
	// Create a test server that simulates the OpenAI API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is correct
		if r.Method != http.MethodPost || r.URL.Path != "/v1/organization/admin_api_keys" {
			// Try the other possible path format
			if r.URL.Path != "/organization/admin_api_keys" {
				http.Error(w, fmt.Sprintf("Unexpected request: %s %s", r.Method, r.URL.Path), http.StatusNotFound)
				return
			}
		}

		// Return a response matching the real OpenAI API format
		resp := map[string]interface{}{
			"object":         "organization.admin_api_key",
			"id":             adminKeyID,
			"name":           "New Admin Key",
			"value":          adminKey,
			"redacted_value": "sk-admin...xyz",
			"created_at":     1711471533,
			"last_used_at":   1711471534,
			"owner": map[string]interface{}{
				"type":       "user",
				"object":     "organization.user",
				"id":         "user_123",
				"name":       "John Doe",
				"created_at": 1711471533,
				"role":       "owner",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create a client using the test server
	client := NewClient("test-key", hclog.NewNullLogger())
	client.SetConfig(&Config{
		AdminAPIKey:    "test-key",
		APIEndpoint:    server.URL,
		OrganizationID: "test-org",
	})

	// Test creating an admin API key
	gotKey, gotID, err := client.CreateAdminAPIKey(context.Background(), "test-key-name")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify the key and ID were correctly extracted
	if gotKey != adminKey {
		t.Errorf("Expected key %q, got %q", adminKey, gotKey)
	}
	if gotID != adminKeyID {
		t.Errorf("Expected key ID %q, got %q", adminKeyID, gotID)
	}
}

// TestCreateAdminAPIKeyMissingValue tests the case where the value field is missing
func TestCreateAdminAPIKeyMissingValue(t *testing.T) { // Create a test server that returns a response with missing value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is correct
		if r.Method != http.MethodPost || r.URL.Path != "/v1/organization/admin_api_keys" {
			// Try the other possible path format
			if r.URL.Path != "/organization/admin_api_keys" {
				http.Error(w, fmt.Sprintf("Unexpected request: %s %s", r.Method, r.URL.Path), http.StatusNotFound)
				return
			}
		}

		// Return a response with missing value field
		resp := map[string]interface{}{
			"object":         "organization.admin_api_key",
			"id":             "key_xyz",
			"name":           "New Admin Key",
			"redacted_value": "sk-admin...xyz",
			"created_at":     1711471533,
			"last_used_at":   1711471534,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create a client using the test server
	client := NewClient("test-key", hclog.NewNullLogger())
	client.SetConfig(&Config{
		AdminAPIKey:    "test-key",
		APIEndpoint:    server.URL,
		OrganizationID: "test-org",
	})

	// Test creating an admin API key
	_, _, err := client.CreateAdminAPIKey(context.Background(), "test-key-name")

	// We should get an error about the missing value
	if err == nil {
		t.Fatal("Expected an error for missing value field, got nil")
	}
}
