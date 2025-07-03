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
	"github.com/hashicorp/vault/sdk/rotation"
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

// pathAdminConfig returns the path configuration for admin-level LDAP config endpoints
func (b *backend) pathAdminConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: configPath + "/rotate",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "openai",
				OperationVerb:   "rotate",
				OperationSuffix: "root-credentials",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathConfigRotateRoot,
					ForwardPerformanceStandby:   true,
					ForwardPerformanceSecondary: true,
					Summary:                     "Rotate the root admin API key.",
				},
			},
			HelpSynopsis:    "Rotate the root admin API key",
			HelpDescription: "Rotates the root admin API key used for accessing the OpenAI API. This creates a new admin API key and revokes the old one.",
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

	var performedRotationManagerOperation string
	if config.ShouldDeregisterRotationJob() {
		performedRotationManagerOperation = "deregistration"
		// Disable Automated Rotation and Deregister credentials if required
		deregisterReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    req.Path,
		}

		b.Logger().Debug("Deregistering rotation job", "mount", req.MountPoint+req.Path)
		if err := b.System().DeregisterRotationJob(ctx, deregisterReq); err != nil {
			return logical.ErrorResponse("error deregistering rotation job: %s", err), nil
		}
	} else if config.ShouldRegisterRotationJob() {
		performedRotationManagerOperation = "registration"
		// Register the rotation job if it's required.
		cfgReq := &rotation.RotationJobConfigureRequest{
			MountPoint:       req.MountPoint,
			ReqPath:          req.Path,
			RotationSchedule: config.RotationSchedule,
			RotationWindow:   config.RotationWindow,
			RotationPeriod:   config.RotationPeriod,
		}

		b.Logger().Debug("Registering rotation job", "mount", req.MountPoint+req.Path)
		if _, err = b.System().RegisterRotationJob(ctx, cfgReq); err != nil {
			return logical.ErrorResponse("error registering rotation job: %s", err), nil
		}
	}

	// Save the configuration
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		wrappedError := err
		if performedRotationManagerOperation != "" {
			b.Logger().Error("write to storage failed but the rotation manager still succeeded.",
				"operation", performedRotationManagerOperation, "mount", req.MountPoint, "path", req.Path)

			wrappedError = fmt.Errorf("write to storage failed but the rotation manager still succeeded; "+
				"operation=%s, mount=%s, path=%s, storageError=%s", performedRotationManagerOperation, req.MountPoint, req.Path, err)
		}

		return nil, wrappedError
	}

	// Update backend client
	b.client = client

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

// validateProject validates a project ID with OpenAI API without caching
// This simplifies the codebase by removing project storage and caching logic
func (b *backend) validateProject(ctx context.Context, s logical.Storage, projectID string) (*ProjectInfo, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}

	// Ensure client is configured
	if err := b.ensureClientConfigured(ctx, s); err != nil {
		return nil, err
	}

	// Validate project with OpenAI API
	projectInfo, err := b.client.GetProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("OpenAI project validation failed: %w", err)
	}
	if projectInfo.Status != "active" {
		return nil, fmt.Errorf("OpenAI project %s is not active (status: %s)", projectID, projectInfo.Status)
	}

	return projectInfo, nil
}

// pathConfigRotateRoot handles manual rotation of the admin API key
func (b *backend) pathConfigRotateRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.rotateRootCredential(ctx, req); err != nil {
		return nil, err
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("rotated credentials but failed to reload config: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"admin_api_key_id": cfg.AdminAPIKeyID,
			"rotated_time":     cfg.LastRotatedTime.Format(time.RFC3339),
		},
	}, nil
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
