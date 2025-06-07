// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath     = "config"
	rotationPrefix = "admin-key" // Used with rotation manager
)

// openaiConfig contains the configuration for the OpenAI secrets engine
// Only supports the current OpenAI API model and automated rotation.
type openaiConfig struct {
	AdminAPIKey     string    `json:"admin_api_key"`
	AdminAPIKeyID   string    `json:"admin_api_key_id"`
	APIEndpoint     string    `json:"api_endpoint"`
	OrganizationID  string    `json:"organization_id"`
	LastRotatedTime time.Time `json:"last_rotated_time"`

	// Automated rotation configuration
	automatedrotationutil.AutomatedRotationParams
}

// projectEntry represents a stored project configuration
// This is still required for dynamic role/project validation and cleanup.
type projectEntry struct {
	Name        string `json:"name"`
	ProjectID   string `json:"project_id"`
	Description string `json:"description,omitempty"`
}

// pathAdminConfig returns the path configuration for admin-level LDAP config endpoints
func (b *backend) pathAdminConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: configPath + "/rotate",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigRotate,
					Summary:  "Rotate the admin API key.",
				},
			},
			HelpSynopsis:    "Rotate the admin API key",
			HelpDescription: "Rotates the admin API key used for accessing the OpenAI API.",
		},
		{
			Pattern: configPath,
			Fields: func() map[string]*framework.FieldSchema {
				fields := map[string]*framework.FieldSchema{
					"admin_api_key": {
						Type:        framework.TypeString,
						Description: "Admin API key used to manage project service accounts and API keys",
						Required:    true,
						DisplayAttrs: &framework.DisplayAttributes{
							Sensitive: true,
						},
					},
					"admin_api_key_id": {
						Type:        framework.TypeString,
						Description: "ID of the admin API key used to manage project service accounts and API keys",
						Required:    true,
					},
					"organization_id": {
						Type:        framework.TypeString,
						Description: "Organization ID for the OpenAI account",
						Required:    true,
					},
					"api_endpoint": {
						Type:        framework.TypeString,
						Description: "URL to the OpenAI API. Defaults to https://api.openai.com/v1",
						Default:     DefaultAPIEndpoint,
					},
				}
				// Add the automated rotation fields
				automatedrotationutil.AddAutomatedRotationFields(fields)
				return fields
			}(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
					Summary:  "Read the OpenAI API configuration for this secrets engine.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Configure the OpenAI API connection.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Configure the OpenAI API connection.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
					Summary:  "Remove an existing OpenAI configuration.",
				},
			},
			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				entry, err := req.Storage.Get(ctx, configPath)
				if err != nil {
					return false, err
				}
				return entry != nil, nil
			},
			HelpSynopsis:    confHelpSyn,
			HelpDescription: confHelpDesc,
		},
	}
}

// pathConfigRead reads the configuration
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	respData := map[string]interface{}{
		"api_endpoint":     config.APIEndpoint,
		"organization_id":  config.OrganizationID,
		"admin_api_key_id": config.AdminAPIKeyID,
	}

	// Add automated rotation parameters to the response
	config.PopulateAutomatedRotationData(respData)

	// Only add last_rotated field if automated rotation is enabled
	if config.ShouldRegisterRotationJob() {
		respData["last_rotated"] = config.LastRotatedTime.Format(time.RFC3339)
	}

	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

// pathConfigWrite updates the configuration
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the configuration
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Initialize config if it doesn't exist
	if config == nil {
		config = &openaiConfig{}
	}

	// Update values from request data
	adminAPIKey, ok := data.GetOk("admin_api_key")
	if ok {
		config.AdminAPIKey = adminAPIKey.(string)
	}

	adminAPIKeyID, ok := data.GetOk("admin_api_key_id")
	if ok {
		config.AdminAPIKeyID = adminAPIKeyID.(string)
	}

	if config.AdminAPIKey == "" {
		return logical.ErrorResponse("admin_api_key is required"), nil
	}
	if config.AdminAPIKeyID == "" {
		return logical.ErrorResponse("admin_api_key_id is required"), nil
	}

	organizationID, ok := data.GetOk("organization_id")
	if ok {
		config.OrganizationID = organizationID.(string)
	}

	if config.OrganizationID == "" {
		return logical.ErrorResponse("organization_id is required"), nil
	}

	apiEndpoint, ok := data.GetOk("api_endpoint")
	if ok {
		config.APIEndpoint = apiEndpoint.(string)
	}

	if config.APIEndpoint == "" {
		config.APIEndpoint = DefaultAPIEndpoint
	}

	// Parse automated rotation parameters
	if err := config.ParseAutomatedRotationFields(data); err != nil {
		return logical.ErrorResponse("error parsing automated rotation fields: %s", err), nil
	}

	// If automatic rotation is enabled, ensure LastRotatedTime is set
	if !config.DisableAutomatedRotation && config.LastRotatedTime.IsZero() {
		config.LastRotatedTime = time.Now()
	}

	// Create a test client to validate the configuration
	client := NewClient(config.AdminAPIKey, b.Logger())
	clientConfig := &Config{
		AdminAPIKey:    config.AdminAPIKey,
		AdminAPIKeyID:  config.AdminAPIKeyID,
		APIEndpoint:    config.APIEndpoint,
		OrganizationID: config.OrganizationID,
	}

	if err := client.SetConfig(clientConfig); err != nil {
		return logical.ErrorResponse("error validating OpenAI configuration: %s", err), nil
	}

	// Save the configuration
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Update backend client
	b.client = client

	// Schedule admin key rotation if enabled (automated rotation only)
	if config.ShouldRegisterRotationJob() {
		b.Logger().Info("Scheduling admin key rotation after configuration update")
		if err := b.scheduleAdminKeyRotation(ctx, req.Storage); err != nil {
			b.Logger().Warn("Failed to schedule admin key rotation", "error", err)
			// Non-fatal error, continue
		}
	}

	return nil, nil
}

// pathConfigDelete deletes the configuration
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configPath)
	if err == nil {
		b.client = nil
	}
	return nil, err
}

// getConfig returns the configuration for this backend
func getConfig(ctx context.Context, s logical.Storage) (*openaiConfig, error) {
	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := &openaiConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("error reading OpenAI configuration: %w", err)
	}

	return config, nil
}

// getProject returns a project configuration by name
func (b *backend) getProject(ctx context.Context, s logical.Storage, name string) (*projectEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("project name is required")
	}

	entry, err := s.Get(ctx, projectStoragePath(name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var project projectEntry
	if err := entry.DecodeJSON(&project); err != nil {
		return nil, fmt.Errorf("error decoding project configuration: %w", err)
	}

	return &project, nil
}

// projectStoragePath returns the storage path for a project
func projectStoragePath(name string) string {
	return fmt.Sprintf("project/%s", name)
}

const confHelpSyn = `
Configure the OpenAI secrets engine with Admin API credentials.
`

const confHelpDesc = `
This endpoint configures the OpenAI secrets engine with Admin API credentials
that can be used to manage project service accounts and API keys.

The Admin API key specified must have sufficient permissions to create and
manage project service accounts and their API keys.
`
