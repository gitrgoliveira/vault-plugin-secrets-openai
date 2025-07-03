// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// MockOpenAIServer is a mock server that simulates the OpenAI API for testing purposes
type MockOpenAIServer struct {
	server            *httptest.Server
	serviceAccounts   map[string]map[string]*ServiceAccount // map[projectID]map[svcAccID]*ServiceAccount
	apiKeys           map[string]*APIKey                    // map[apiKeyID]*APIKey
	mutex             sync.RWMutex
	failureMode       string // can be "create_svc_acc", "create_key", "delete_svc_acc", "delete_key"
	failureStatusCode int
	failureMessage    string
}

// NewMockOpenAIServer creates a new instance of the mock OpenAI server
func NewMockOpenAIServer() *MockOpenAIServer {
	m := &MockOpenAIServer{
		serviceAccounts: make(map[string]map[string]*ServiceAccount),
		apiKeys:         make(map[string]*APIKey),
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

// URL returns the base URL of the mock server
func (m *MockOpenAIServer) URL() string {
	return m.server.URL
}

// Close shuts down the mock server
func (m *MockOpenAIServer) Close() {
	m.server.Close()
}

// SetFailureMode configures the server to simulate failures for specific operations
func (m *MockOpenAIServer) SetFailureMode(mode string, statusCode int, message string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.failureMode = mode
	m.failureStatusCode = statusCode
	m.failureMessage = message
}

// ClearFailureMode removes any configured failure modes
func (m *MockOpenAIServer) ClearFailureMode() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.failureMode = ""
	m.failureStatusCode = 0
	m.failureMessage = ""
}

// handler processes all incoming requests to the mock server
func (m *MockOpenAIServer) handler(w http.ResponseWriter, r *http.Request) {
	// Special handling for admin API key endpoints
	if strings.Contains(r.URL.Path, "admin_api_keys") {
		// For admin API rotation, we need to accept any key
		// Since during rotation we use a newly created key to revoke the old one
	} else {
		// Check authorization for all other endpoints
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-key" {
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "Invalid API key")
			return
		}
	}

	// Match URL patterns and dispatch to appropriate handler
	// Only supporting the correct OpenAI API paths with required /organization prefix
	serviceAccountsPattern := regexp.MustCompile(`/v1/organization/projects/([^/]+)/service_accounts(?:/([^/]+))?`)
	adminAPIKeysPattern := regexp.MustCompile(`/v1/organization/admin_api_keys(?:/([^/]+))?`)

	if matches := serviceAccountsPattern.FindStringSubmatch(r.URL.Path); matches != nil {
		projectID := matches[1]
		serviceAccountID := ""
		if len(matches) > 2 {
			serviceAccountID = matches[2]
		}

		switch r.Method {
		case http.MethodGet:
			if serviceAccountID == "" {
				m.listServiceAccounts(w, r, projectID)
			} else {
				m.getServiceAccount(w, r, projectID, serviceAccountID)
			}
		case http.MethodPost:
			m.createServiceAccount(w, r, projectID)
		case http.MethodDelete:
			if serviceAccountID != "" {
				m.deleteServiceAccount(w, r, projectID, serviceAccountID)
			} else {
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			}
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
		return
	}

	if matches := adminAPIKeysPattern.FindStringSubmatch(r.URL.Path); matches != nil {
		keyID := ""
		if len(matches) > 1 {
			keyID = matches[1]
		}

		switch r.Method {
		case http.MethodGet:
			m.listAdminAPIKeys(w, r)
		case http.MethodPost:
			m.createAdminAPIKey(w, r)
		case http.MethodDelete:
			if keyID != "" {
				m.revokeAdminAPIKey(w, r, keyID)
			} else {
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			}
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
		return
	}

	// If no pattern matches
	writeError(w, http.StatusNotFound, "not_found", "Resource not found")
}

// createServiceAccount handles service account creation requests
func (m *MockOpenAIServer) createServiceAccount(w http.ResponseWriter, r *http.Request, projectID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if we should simulate a failure
	if m.failureMode == "create_svc_acc" {
		writeError(w, m.failureStatusCode, "server_error", m.failureMessage)
		return
	}

	var req CreateServiceAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	// Validate required fields
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "Service account name is required")
		return
	}

	// Create a new service account
	now := time.Now()
	nowUnix := UnixTime(now)
	unixTimestamp := now.Unix()

	// Create the service account object according to the new format
	svcAcc := &ServiceAccount{
		ID:        fmt.Sprintf("svc_%s", generateRandomID(10)),
		ProjectID: projectID,
		Name:      req.Name,
		CreatedAt: &nowUnix,
	}

	// Initialize the project's service accounts map if it doesn't exist
	if _, exists := m.serviceAccounts[projectID]; !exists {
		m.serviceAccounts[projectID] = make(map[string]*ServiceAccount)
	}

	// Store the service account
	m.serviceAccounts[projectID][svcAcc.ID] = svcAcc

	// Create an API key for the service account
	apiKey := &APIKey{
		ID:           fmt.Sprintf("key_%s", generateRandomID(10)),
		Value:        fmt.Sprintf("sk-test-%s", generateRandomID(24)),
		Name:         "Secret Key",
		ServiceAccID: svcAcc.ID,
		CreatedAt:    &nowUnix,
	}

	// Store the API key
	m.apiKeys[apiKey.ID] = apiKey

	// Format response to match the actual OpenAI API
	response := map[string]interface{}{
		"object":     "organization.project.service_account",
		"id":         svcAcc.ID,
		"name":       svcAcc.Name,
		"role":       "member",
		"created_at": unixTimestamp,
		"api_key": map[string]interface{}{
			"object":     "organization.project.service_account.api_key",
			"id":         apiKey.ID,
			"value":      apiKey.Value,
			"name":       apiKey.Name,
			"created_at": unixTimestamp,
		},
	}

	// Return the created service account and API key
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// getServiceAccount handles service account retrieval requests
func (m *MockOpenAIServer) getServiceAccount(w http.ResponseWriter, r *http.Request, projectID, serviceAccountID string) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if project exists
	projectAccounts, exists := m.serviceAccounts[projectID]
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "Project not found")
		return
	}

	// Check if service account exists
	svcAcc, exists := projectAccounts[serviceAccountID]
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "Service account not found")
		return
	}

	// Return the service account
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(svcAcc); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// listServiceAccounts handles service account listing requests
func (m *MockOpenAIServer) listServiceAccounts(w http.ResponseWriter, r *http.Request, projectID string) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if project exists
	projectAccounts, exists := m.serviceAccounts[projectID]
	if !exists {
		// Return empty list for non-existent projects
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string][]ServiceAccount{"data": {}}); err != nil {
			m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
			writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
			return
		}
		return
	}

	// Collect all service accounts for the project
	accounts := make([]ServiceAccount, 0, len(projectAccounts))
	for _, acc := range projectAccounts {
		accounts = append(accounts, *acc)
	}

	// Return the list of service accounts
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string][]ServiceAccount{"data": accounts}); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// deleteServiceAccount handles service account deletion requests
func (m *MockOpenAIServer) deleteServiceAccount(w http.ResponseWriter, r *http.Request, projectID, serviceAccountID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if we should simulate a failure
	if m.failureMode == "delete_svc_acc" {
		writeError(w, m.failureStatusCode, "server_error", m.failureMessage)
		return
	}

	// Check if project exists
	projectAccounts, exists := m.serviceAccounts[projectID]
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "Project not found")
		return
	}

	// Check if service account exists
	if _, exists := projectAccounts[serviceAccountID]; !exists {
		writeError(w, http.StatusNotFound, "not_found", "Service account not found")
		return
	}

	// Delete the service account
	delete(projectAccounts, serviceAccountID)

	// Also delete any API keys associated with this service account
	for keyID, key := range m.apiKeys {
		if key.ServiceAccID == serviceAccountID {
			delete(m.apiKeys, keyID)
		}
	}

	// Return success with empty response
	w.WriteHeader(http.StatusNoContent)
}

// Admin API key endpoints for mocking
type adminAPIKey struct {
	Object        string `json:"object"`
	ID            string `json:"id"`
	Value         string `json:"value"`
	Name          string `json:"name"`
	RedactedValue string `json:"redacted_value"`
	CreatedAt     int64  `json:"created_at"`
	LastUsedAt    int64  `json:"last_used_at"`
	Owner         struct {
		Type      string `json:"type"`
		Object    string `json:"object"`
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt int64  `json:"created_at"`
		Role      string `json:"role"`
	} `json:"owner"`
}

// createAdminAPIKey handles admin API key creation requests
func (m *MockOpenAIServer) createAdminAPIKey(w http.ResponseWriter, r *http.Request) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	name, ok := req["name"].(string)
	if !ok || name == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "Name is required")
		return
	}

	now := time.Now()
	nowUnix := now.Unix()
	key := &adminAPIKey{
		Object:        "organization.admin_api_key",
		ID:            fmt.Sprintf("key_%s", generateRandomID(10)),
		Value:         fmt.Sprintf("sk-adminkey%s", generateRandomID(24)),
		Name:          name,
		CreatedAt:     nowUnix,
		LastUsedAt:    nowUnix,
		RedactedValue: "sk-admin...xyz",
	}

	// Set owner data
	key.Owner.Type = "user"
	key.Owner.Object = "organization.user"
	key.Owner.ID = "user_123"
	key.Owner.Name = "Test User"
	key.Owner.CreatedAt = nowUnix
	key.Owner.Role = "owner"

	// Return the created admin API key
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(key); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// listAdminAPIKeys handles admin API key listing requests
func (m *MockOpenAIServer) listAdminAPIKeys(w http.ResponseWriter, r *http.Request) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a sample list of admin API keys
	now := time.Now()
	nowUnix := now.Unix()
	keys := []adminAPIKey{
		{
			Object:        "organization.admin_api_key",
			ID:            "key_sample",
			Name:          "sample-admin-key",
			CreatedAt:     nowUnix,
			LastUsedAt:    nowUnix,
			RedactedValue: "sk-admin...xyz",
		},
	}

	// Set owner data for the sample key
	keys[0].Owner.Type = "user"
	keys[0].Owner.Object = "organization.user"
	keys[0].Owner.ID = "user_123"
	keys[0].Owner.Name = "Test User"
	keys[0].Owner.CreatedAt = nowUnix
	keys[0].Owner.Role = "owner"

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string][]adminAPIKey{"data": keys}); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// revokeAdminAPIKey handles admin API key revocation requests
func (m *MockOpenAIServer) revokeAdminAPIKey(w http.ResponseWriter, r *http.Request, keyID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// In real implementation, we would check if key exists and delete it
	// For mock, we'll just return success
	w.WriteHeader(http.StatusNoContent)
}

// Helper function to generate a random ID string
func generateRandomID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}

// Helper function to write an error response
func writeError(w http.ResponseWriter, statusCode int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error": map[string]interface{}{
			"message": message,
			"type":    errorType,
		},
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// This is a helper function for error responses, so we can't do much if encoding fails
		// Just log to stderr since this is a test utility
		fmt.Fprintf(os.Stderr, "Failed to encode error response: %v", err)
	}
}
