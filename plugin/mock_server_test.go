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
	// The legacy paths without the /organization prefix are invalid and no longer supported
	serviceAccountsPattern := regexp.MustCompile(`/v1/organization/projects/([^/]+)/service_accounts(?:/([^/]+))?`)
	apiKeysPattern := regexp.MustCompile(`/v1/organization/api_keys(?:/([^/]+))?`)
	adminAPIKeysPattern := regexp.MustCompile(`/v1/organization/admin_api_keys(?:/([^/]+))?`)

	// Project direct operations
	projectPattern := regexp.MustCompile(`/v1/organization/projects/([^/]+)/?$`)

	// Handle direct project operations
	if matches := projectPattern.FindStringSubmatch(r.URL.Path); matches != nil && r.Method == http.MethodGet {
		projectID := matches[1]
		m.getProject(w, r, projectID)
		return
	}

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

	if matches := apiKeysPattern.FindStringSubmatch(r.URL.Path); matches != nil {
		keyID := ""
		if len(matches) > 1 {
			keyID = matches[1]
		}

		switch r.Method {
		case http.MethodGet:
			if keyID == "" {
				m.listAPIKeys(w, r)
			} else {
				m.getAPIKey(w, r, keyID)
			}
		case http.MethodPost:
			m.createAPIKey(w, r)
		case http.MethodDelete:
			if keyID != "" {
				m.deleteAPIKey(w, r, keyID)
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
	svcAcc := &ServiceAccount{
		ID:          fmt.Sprintf("svc_%s", generateRandomID(10)),
		ProjectID:   projectID,
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   &now,
	}

	// Initialize the project's service accounts map if it doesn't exist
	if _, exists := m.serviceAccounts[projectID]; !exists {
		m.serviceAccounts[projectID] = make(map[string]*ServiceAccount)
	}

	// Store the service account
	m.serviceAccounts[projectID][svcAcc.ID] = svcAcc

	// Return the created service account
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(svcAcc); err != nil {
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

// createAPIKey handles API key creation requests
func (m *MockOpenAIServer) createAPIKey(w http.ResponseWriter, r *http.Request) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if we should simulate a failure
	if m.failureMode == "create_key" {
		writeError(w, m.failureStatusCode, "server_error", m.failureMessage)
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	// Validate required fields
	if req.Name == "" || req.ServiceAccID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "Name and service account ID are required")
		return
	}

	// Verify that the service account exists
	found := false
	for _, accounts := range m.serviceAccounts {
		if _, exists := accounts[req.ServiceAccID]; exists {
			found = true
			break
		}
	}

	if !found {
		writeError(w, http.StatusNotFound, "not_found", "Service account not found")
		return
	}

	// Create a new API key
	now := time.Now()
	apiKey := &APIKey{
		ID:           fmt.Sprintf("key_%s", generateRandomID(10)),
		Key:          fmt.Sprintf("sk-mockkey%s", generateRandomID(24)),
		Name:         req.Name,
		ServiceAccID: req.ServiceAccID,
		CreatedAt:    &now,
		ExpiresAt:    req.ExpiresAt,
	}

	// Store the API key
	m.apiKeys[apiKey.ID] = apiKey

	// Return the created API key
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(apiKey); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// getAPIKey handles API key retrieval requests
func (m *MockOpenAIServer) getAPIKey(w http.ResponseWriter, r *http.Request, keyID string) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if API key exists
	apiKey, exists := m.apiKeys[keyID]
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "API key not found")
		return
	}

	// Create a copy without the key value (API doesn't return this after creation)
	keyResponse := *apiKey
	keyResponse.Key = ""

	// Return the API key info
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(keyResponse); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// listAPIKeys handles API key listing requests
func (m *MockOpenAIServer) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Extract service account ID from query params if provided
	serviceAccountID := r.URL.Query().Get("service_account_id")

	// Collect all matching API keys
	keys := make([]APIKey, 0)
	for _, key := range m.apiKeys {
		// Filter by service account ID if provided
		if serviceAccountID != "" && key.ServiceAccID != serviceAccountID {
			continue
		}

		// Create a copy without the key value
		keyInfo := *key
		keyInfo.Key = ""
		keys = append(keys, keyInfo)
	}

	// Return the list of API keys
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string][]APIKey{"data": keys}); err != nil {
		m.failureMessage = fmt.Sprintf("Failed to encode response: %v", err)
		writeError(w, http.StatusInternalServerError, "encoding_error", m.failureMessage)
		return
	}
}

// deleteAPIKey handles API key deletion requests
func (m *MockOpenAIServer) deleteAPIKey(w http.ResponseWriter, r *http.Request, keyID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if we should simulate a failure
	if m.failureMode == "delete_key" {
		writeError(w, m.failureStatusCode, "server_error", m.failureMessage)
		return
	}

	// Check if API key exists
	if _, exists := m.apiKeys[keyID]; !exists {
		writeError(w, http.StatusNotFound, "not_found", "API key not found")
		return
	}

	// Delete the API key
	delete(m.apiKeys, keyID)

	// Return success with empty response
	w.WriteHeader(http.StatusNoContent)
}

// Admin API key endpoints for mocking
type adminAPIKey struct {
	ID        string     `json:"id"`
	Key       string     `json:"key,omitempty"`
	Name      string     `json:"name"`
	CreatedAt *time.Time `json:"created_at"`
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
	key := &adminAPIKey{
		ID:        fmt.Sprintf("adminkey_%s", generateRandomID(10)),
		Key:       fmt.Sprintf("sk-adminkey%s", generateRandomID(24)),
		Name:      name,
		CreatedAt: &now,
	}

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
	keys := []adminAPIKey{
		{
			ID:        "adminkey_sample",
			Name:      "sample-admin-key",
			CreatedAt: &now,
		},
	}

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

// getProject handles project retrieval by ID
func (m *MockOpenAIServer) getProject(w http.ResponseWriter, r *http.Request, projectID string) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// For testing purposes, we'll just assume any project ID is valid
	// and return a simple project response
	project := map[string]interface{}{
		"id":          projectID,
		"name":        "Test Project",
		"description": "A test project",
		"created_at":  time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(project)
}

// listProjects returns a list of projects
func (m *MockOpenAIServer) listProjects(w http.ResponseWriter, r *http.Request) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a standard paginated response with some dummy projects
	response := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"id":          "proj_test1",
				"name":        "Test Project 1",
				"description": "First test project",
				"created_at":  time.Now().Format(time.RFC3339),
			},
			{
				"id":          "proj_test2",
				"name":        "Test Project 2",
				"description": "Second test project",
				"created_at":  time.Now().Format(time.RFC3339),
			},
		},
		"has_more": false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
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
