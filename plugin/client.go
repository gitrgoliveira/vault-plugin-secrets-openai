// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/go-hclog"
)

const (
	// Default API endpoint for OpenAI
	DefaultAPIEndpoint = "https://api.openai.com/v1"

	// API endpoints - now with /organization prefix as per OpenAI docs
	organizationPrefix         = "/organization"
	adminAPIKeysEndpoint       = organizationPrefix + "/admin_api_keys"
	projectsEndpoint           = organizationPrefix + "/projects"
	serviceAccountsEndpointFmt = organizationPrefix + "/projects/%s/service_accounts"
	apiKeysEndpoint            = organizationPrefix + "/api_keys"
)

// Client represents an OpenAI API client
type Client struct {
	httpClient     *http.Client
	apiEndpoint    string
	adminAPIKey    string
	adminAPIKeyID  string
	organizationID string
	logger         hclog.Logger
}

// NewClient creates a new OpenAI client
func NewClient(adminAPIKey string, logger hclog.Logger) *Client {
	return &Client{
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		apiEndpoint:    DefaultAPIEndpoint,
		adminAPIKey:    adminAPIKey,
		organizationID: "", // Will be set through SetConfig
		logger:         logger,
	}
}

// Config contains configuration for the OpenAI client
// Add AdminAPIKeyID to track the key's ID for revocation
type Config struct {
	AdminAPIKey    string `json:"admin_api_key"`
	AdminAPIKeyID  string `json:"admin_api_key_id,omitempty"`
	APIEndpoint    string `json:"api_endpoint"`
	OrganizationID string `json:"organization_id"`
}

// ServiceAccount represents an OpenAI project service account
// Updated: OpenAI does not support a description field for service accounts
// Added Role field per API response
// Removed Description field
type ServiceAccount struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	Role      string    `json:"role,omitempty"`
	CreatedAt *UnixTime `json:"created_at,omitempty"`
}

// MarshalJSON implements custom marshaling for ServiceAccount
func (sa *ServiceAccount) MarshalJSON() ([]byte, error) {
	type Alias ServiceAccount
	return json.Marshal(&struct {
		*Alias
		CreatedAt *time.Time `json:"created_at,omitempty"`
	}{
		Alias:     (*Alias)(sa),
		CreatedAt: sa.GetCreatedAt(),
	})
}

// GetCreatedAt returns the created_at time as a time.Time pointer
func (sa *ServiceAccount) GetCreatedAt() *time.Time {
	if sa.CreatedAt == nil {
		return nil
	}
	return sa.CreatedAt.TimePtr()
}

// APIKey represents an OpenAI API key
type APIKey struct {
	ID           string    `json:"id"`
	Value        string    `json:"value,omitempty"`
	Name         string    `json:"name"`
	ServiceAccID string    `json:"service_account_id"`
	CreatedAt    *UnixTime `json:"created_at,omitempty"`
	ExpiresAt    *UnixTime `json:"expires_at,omitempty"`
}

// MarshalJSON implements custom marshaling for APIKey
func (ak *APIKey) MarshalJSON() ([]byte, error) {
	type Alias APIKey
	return json.Marshal(&struct {
		*Alias
		CreatedAt *time.Time `json:"created_at,omitempty"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}{
		Alias:     (*Alias)(ak),
		CreatedAt: ak.GetCreatedAt(),
		ExpiresAt: ak.GetExpiresAt(),
	})
}

// GetCreatedAt returns the created_at time as a time.Time pointer
func (ak *APIKey) GetCreatedAt() *time.Time {
	if ak.CreatedAt == nil {
		return nil
	}
	return ak.CreatedAt.TimePtr()
}

// GetExpiresAt returns the expires_at time as a time.Time pointer
func (ak *APIKey) GetExpiresAt() *time.Time {
	if ak.ExpiresAt == nil {
		return nil
	}
	return ak.ExpiresAt.TimePtr()
}

// CreateServiceAccountRequest represents a request to create a service account
// Only Name is supported by OpenAI
// Removed Description field
type CreateServiceAccountRequest struct {
	Name string `json:"name"`
}

// SetConfig updates the client configuration
func (c *Client) SetConfig(config *Config) error {
	if config.AdminAPIKey == "" {
		return fmt.Errorf("admin API key is required")
	}

	if config.OrganizationID == "" {
		return fmt.Errorf("organization ID is required")
	}

	c.adminAPIKey = config.AdminAPIKey
	c.adminAPIKeyID = config.AdminAPIKeyID
	c.organizationID = config.OrganizationID

	if config.APIEndpoint != "" {
		c.apiEndpoint = config.APIEndpoint
	}

	return nil
}

// doRequest performs an HTTP request with appropriate headers and error handling
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	url := c.apiEndpoint + path
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.adminAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("OpenAI-Beta", "project-service-accounts=v1")

	// Set the organization ID in the header rather than in the URL path
	if c.organizationID != "" {
		req.Header.Set("OpenAI-Organization", c.organizationID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Error("Failed to close response body", "error", err)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    string `json:"code,omitempty"`
				Param   string `json:"param,omitempty"`
			} `json:"error"`
		}

		// Try to parse error as OpenAI structured error format
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error.Message != "" {
			c.logger.Error("OpenAI API error",
				"status", resp.StatusCode,
				"error_type", errResp.Error.Type,
				"error_code", errResp.Error.Code,
				"message", errResp.Error.Message,
				"param", errResp.Error.Param,
				"method", method,
				"path", path)

			// Return error with all available context
			errMsg := fmt.Sprintf("API error (%d): %s - %s",
				resp.StatusCode, errResp.Error.Type, errResp.Error.Message)

			if errResp.Error.Code != "" {
				errMsg += fmt.Sprintf(" (code: %s)", errResp.Error.Code)
			}

			if errResp.Error.Param != "" {
				errMsg += fmt.Sprintf(" (param: %s)", errResp.Error.Param)
			}

			return nil, fmt.Errorf("%s", errMsg)
		}

		// Fallback for non-standard error format
		c.logger.Error("OpenAI API non-standard error",
			"status", resp.StatusCode,
			"body", string(respBody),
			"method", method,
			"path", path)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// ServiceAccountResponse represents the API response for creating a service account.
// It includes both the service account and the associated API key.
type ServiceAccountResponse struct {
	ServiceAccount *ServiceAccount `json:"service_account"`
	APIKey         *APIKey         `json:"api_key"`
}

// CreateServiceAccount creates a new project service account and returns both the service account and API key
// in a single operation, as per the actual OpenAI API behavior.
func (c *Client) CreateServiceAccount(ctx context.Context, projectID string, req CreateServiceAccountRequest) (*ServiceAccount, *APIKey, error) {
	// Validate inputs
	if projectID == "" {
		return nil, nil, fmt.Errorf("project ID is required")
	}

	if req.Name == "" {
		return nil, nil, fmt.Errorf("service account name is required")
	}

	// Validate service account name according to OpenAI requirements
	if err := ValidateServiceAccountName(req.Name); err != nil {
		c.logger.Error("Invalid service account name",
			"name", req.Name,
			"error", err)
		return nil, nil, fmt.Errorf("invalid service account name: %w", err)
	}

	// Log creation attempt
	c.logger.Debug("Creating service account",
		"project_id", projectID,
		"name", req.Name)

	// Construct the path for creating a service account
	path := fmt.Sprintf(serviceAccountsEndpointFmt, projectID)

	respBody, err := c.doRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		c.logger.Error("Failed to create service account",
			"project_id", projectID,
			"name", req.Name,
			"error", err)
		return nil, nil, fmt.Errorf("error creating service account: %w", err)
	}

	// Parse the exact OpenAI API response format
	var raw map[string]interface{}
	if err := json.Unmarshal(respBody, &raw); err == nil {
		// Initialize service account
		var svc *ServiceAccount

		// Try to extract from service_account field (nested structure)
		if serviceAccountData, ok := raw["service_account"].(map[string]interface{}); ok {
			// Not expected for OpenAI, but fallback for future-proofing
			svc = &ServiceAccount{
				ID:        asString(serviceAccountData["id"]),
				Name:      asString(serviceAccountData["name"]),
				ProjectID: projectID, // Ensure projectID is set
				Role:      asString(serviceAccountData["role"]),
			}

			if created, ok := serviceAccountData["created_at"].(float64); ok {
				t := time.Unix(int64(created), 0)
				svc.CreatedAt = UnixTimePtr(&t)
			}
		} else {
			// Flat structure (actual OpenAI response)
			svc = &ServiceAccount{
				ID:        asString(raw["id"]),
				Name:      asString(raw["name"]),
				ProjectID: projectID, // Ensure projectID is set
				Role:      asString(raw["role"]),
			}

			if created, ok := raw["created_at"].(float64); ok {
				t := time.Unix(int64(created), 0)
				svc.CreatedAt = UnixTimePtr(&t)
			}
		}

		// Extract the API key from the response
		if apiKeyData, ok := raw["api_key"].(map[string]interface{}); ok {
			secretKey := asString(apiKeyData["value"])

			apiKey := &APIKey{
				ID:           asString(apiKeyData["id"]),
				Value:        secretKey,
				Name:         asString(apiKeyData["name"]),
				ServiceAccID: svc.ID,
			}

			if created, ok := apiKeyData["created_at"].(float64); ok {
				t := time.Unix(int64(created), 0)
				apiKey.CreatedAt = UnixTimePtr(&t)
			}

			c.logger.Info("Created service account with API key successfully",
				"service_account_id", svc.ID,
				"project_id", projectID,
				"name", svc.Name,
				"role", svc.Role,
				"api_key_id", apiKey.ID)
			return svc, apiKey, nil
		}
	}

	return nil, nil, fmt.Errorf("service account data missing in API response")
}

// Helper for fallback parsing
func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// DeleteServiceAccount deletes a service account by ID
func (c *Client) DeleteServiceAccount(ctx context.Context, id string, projectID ...string) error {
	// Validate inputs
	if id == "" {
		return fmt.Errorf("service account ID is required")
	}

	// Project ID is required for this endpoint
	if len(projectID) == 0 || projectID[0] == "" {
		return fmt.Errorf("project ID is required to delete a service account")
	}

	// Log deletion attempt
	c.logger.Debug("Deleting service account",
		"service_account_id", id,
		"project_id", projectID[0])

	// Construct the path for deleting a service account
	path := fmt.Sprintf(serviceAccountsEndpointFmt+"/%s", projectID[0], id)

	_, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		c.logger.Error("Failed to delete service account",
			"service_account_id", id,
			"project_id", projectID[0],
			"error", err)
		return fmt.Errorf("error deleting service account: %w", err)
	}

	c.logger.Info("Deleted service account successfully",
		"service_account_id", id,
		"project_id", projectID[0])

	return nil
}

// NOTE: CreateAPIKey is no longer needed as API keys are created automatically
// when creating a service account in the OpenAI API

// DeleteAPIKey deletes an API key by ID
func (c *Client) DeleteAPIKey(ctx context.Context, id string) error {
	// Validate inputs
	if id == "" {
		return fmt.Errorf("API key ID is required")
	}

	// Log deletion attempt
	c.logger.Debug("Deleting API key", "api_key_id", id)

	path := fmt.Sprintf(apiKeysEndpoint+"/%s", id)
	_, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		c.logger.Error("Failed to delete API key",
			"api_key_id", id,
			"error", err)
		return fmt.Errorf("error deleting API key: %w", err)
	}

	c.logger.Info("Deleted API key successfully", "api_key_id", id)
	return nil
}

// GetServiceAccount gets a service account by ID
func (c *Client) GetServiceAccount(ctx context.Context, id string, projectID string) (*ServiceAccount, error) {
	// Validate inputs
	if id == "" {
		return nil, fmt.Errorf("service account ID is required")
	}

	if projectID == "" {
		return nil, fmt.Errorf("project ID is required to get a service account")
	}

	// Log retrieval attempt
	c.logger.Debug("Getting service account",
		"service_account_id", id,
		"project_id", projectID)

	// Construct the path for retrieving a service account
	path := fmt.Sprintf(serviceAccountsEndpointFmt+"/%s", projectID, id)

	respBody, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		c.logger.Error("Failed to get service account",
			"service_account_id", id,
			"project_id", projectID,
			"error", err)
		return nil, fmt.Errorf("error getting service account: %w", err)
	}

	var svcAccount ServiceAccount
	if err := json.Unmarshal(respBody, &svcAccount); err != nil {
		c.logger.Error("Failed to parse service account response",
			"error", err,
			"response", string(respBody))
		return nil, fmt.Errorf("error parsing service account response: %w", err)
	}

	c.logger.Debug("Successfully retrieved service account",
		"service_account_id", svcAccount.ID,
		"name", svcAccount.Name)

	return &svcAccount, nil
}

// ListServiceAccounts returns all service accounts for a project
func (c *Client) ListServiceAccounts(ctx context.Context, projectID string) ([]*ServiceAccount, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}
	path := fmt.Sprintf(serviceAccountsEndpointFmt, projectID)
	respBody, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []ServiceAccount `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing service accounts response: %w", err)
	}

	accounts := make([]*ServiceAccount, 0, len(result.Data))
	for i := range result.Data {
		accounts = append(accounts, &result.Data[i])
	}
	return accounts, nil
}

// CreateAdminAPIKey creates a new admin API key and returns its value and ID
func (c *Client) CreateAdminAPIKey(ctx context.Context, name string) (string, string, error) {
	if name == "" {
		return "", "", fmt.Errorf("admin API key name is required")
	}
	// Per OpenAI docs: POST /organization/admin_api_keys
	body := map[string]interface{}{"name": name}
	respBody, err := c.doRequest(ctx, http.MethodPost, adminAPIKeysEndpoint, body)
	if err != nil {
		return "", "", fmt.Errorf("error creating admin API key: %w", err)
	}
	var result struct {
		Object        string `json:"object"`
		ID            string `json:"id"`
		Name          string `json:"name"`
		Value         string `json:"value"`
		CreatedAt     int64  `json:"created_at"`
		LastUsedAt    int64  `json:"last_used_at"`
		RedactedValue string `json:"redacted_value"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("error parsing admin API key response: %w", err)
	}

	if result.Value == "" || result.ID == "" {
		return "", "", fmt.Errorf("admin API key or ID not returned in response")
	}
	return result.Value, result.ID, nil
}

// RevokeAdminAPIKey revokes the given admin API key
func (c *Client) RevokeAdminAPIKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("admin API key ID is required")
	}
	// Per OpenAI docs: DELETE /organization/admin_api_keys/{admin_api_key_id}
	path := fmt.Sprintf(adminAPIKeysEndpoint+"/%s", keyID)
	_, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("error revoking admin API key %s: %w", keyID, err)
	}
	return nil
}

// ListAdminAPIKeys lists all admin API keys
func (c *Client) ListAdminAPIKeys(ctx context.Context) ([]map[string]interface{}, error) {
	respBody, err := c.doRequest(ctx, http.MethodGet, adminAPIKeysEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error listing admin API keys: %w", err)
	}
	var result struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing admin API keys response: %w", err)
	}
	return result.Data, nil
}

// TestConnection tests the client connection by listing admin API keys
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.ListAdminAPIKeys(ctx)
	if err != nil {
		return fmt.Errorf("admin API key validation failed: %w", err)
	}
	return nil
}

// ValidateProject checks if the given project ID is valid by retrieving the project details from OpenAI.
func (c *Client) ValidateProject(ctx context.Context, projectID string) error {
	if projectID == "" {
		return fmt.Errorf("project_id is required")
	}
	// Use the OpenAI projects retrieve endpoint per docs: /organization/projects/{project_id}
	path := fmt.Sprintf(projectsEndpoint+"/%s", projectID)
	_, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("OpenAI project validation failed: %w", err)
	}
	return nil
}

// GetAdminAPIKey retrieves details for a specific admin API key by ID.
func (c *Client) GetAdminAPIKey(ctx context.Context, keyID string) (map[string]interface{}, error) {
	if keyID == "" {
		return nil, fmt.Errorf("admin API key ID is required")
	}
	path := fmt.Sprintf(adminAPIKeysEndpoint+"/%s", keyID)
	respBody, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("error retrieving admin API key details: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing admin API key details: %w", err)
	}
	return result, nil
}

// ProjectInfo represents the OpenAI project details response
// Used for project validation and caching
type ProjectInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// GetProject fetches project details from OpenAI API by project ID
func (c *Client) GetProject(ctx context.Context, projectID string) (*ProjectInfo, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}
	path := fmt.Sprintf(projectsEndpoint+"/%s", projectID)
	respBody, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var info ProjectInfo
	if err := json.Unmarshal(respBody, &info); err != nil {
		return nil, fmt.Errorf("error parsing OpenAI project response: %w", err)
	}
	return &info, nil
}
