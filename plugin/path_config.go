// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath     = "config"
	projectPath    = "project"
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

// pathProjectConfig returns the path configuration for project-level config
func (b *backend) pathProjectConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "project/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the OpenAI project",
					Required:    true,
				},
				"project_id": {
					Type:        framework.TypeString,
					Description: "ID of the OpenAI project",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Description of the project",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathProjectRead,
					Summary:  "Read an OpenAI project configuration.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathProjectWrite,
					Summary:  "Create or update an OpenAI project configuration.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathProjectWrite,
					Summary:  "Create or update an OpenAI project configuration.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathProjectDelete,
					Summary:  "Delete an OpenAI project configuration.",
				},
			},
			ExistenceCheck:  existenceCheckForNamedPath("name", projectStoragePath),
			HelpSynopsis:    projectHelpSyn,
			HelpDescription: projectHelpDesc,
		},
		{
			Pattern: "project/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathProjectList,
					Summary:  "List configured OpenAI projects.",
				},
			},
			HelpSynopsis:    projectListHelpSyn,
			HelpDescription: projectListHelpDesc,
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

// pathProjectRead reads a project configuration
func (b *backend) pathProjectRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("project name is required"), nil
	}

	project, err := b.getProject(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"name":        project.Name,
			"project_id":  project.ProjectID,
			"description": project.Description,
		},
	}, nil
}

// pathProjectWrite writes a project configuration
func (b *backend) pathProjectWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("project name is required"), nil
	}

	projectID := data.Get("project_id").(string)
	if projectID == "" {
		return logical.ErrorResponse("project_id is required"), nil
	}

	description := data.Get("description").(string)

	project := &projectEntry{
		Name:        name,
		ProjectID:   projectID,
		Description: description,
	}

	// Validate the project ID with the OpenAI API
	// In a test environment, we may not have a client configured
	if b.client == nil && req.Operation != logical.ReadOperation {
		return logical.ErrorResponse("OpenAI client not configured"), nil
	}

	// Validate the project ID if the client is available
	if b.client != nil {
		err := b.client.ValidateProject(ctx, projectID)
		if err != nil {
			return logical.ErrorResponse("project_id validation failed: %s", err), nil
		}
	}

	entry, err := logical.StorageEntryJSON(projectStoragePath(name), project)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathProjectDelete deletes a project configuration
func (b *backend) pathProjectDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("project name is required"), nil
	}

	// Check if the project has any roles using it
	roles, err := b.listRolesForProject(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error checking if project is in use: %w", err)
	}
	if len(roles) > 0 {
		return logical.ErrorResponse("project has roles that use it, cannot delete"), nil
	}

	if err := req.Storage.Delete(ctx, projectStoragePath(name)); err != nil {
		return nil, fmt.Errorf("error deleting project configuration: %w", err)
	}

	return nil, nil
}

// pathProjectList lists all project configurations
func (b *backend) pathProjectList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	projects, err := req.Storage.List(ctx, "project/")
	if err != nil {
		return nil, fmt.Errorf("error listing projects: %w", err)
	}

	return logical.ListResponse(projects), nil
}

// projectStoragePath returns the storage path for a project
func projectStoragePath(name string) string {
	return fmt.Sprintf("project/%s", name)
}

// projectEntry represents a stored project configuration
type projectEntry struct {
	Name        string `json:"name"`
	ProjectID   string `json:"project_id"`
	Description string `json:"description,omitempty"`
}

// getProject returns a project configuration by name
func (b *backend) getProject(ctx context.Context, s logical.Storage, name string) (*projectEntry, error) {
	if name == "" {
		return nil, errors.New("project name is required")
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

// listRolesForProject returns a list of roles that use this project
func (b *backend) listRolesForProject(ctx context.Context, s logical.Storage, projectName string) ([]string, error) {
	// First, get the project to find its project ID
	project, err := b.getProject(ctx, s, projectName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving project %q: %w", projectName, err)
	}

	if project == nil {
		// Project doesn't exist, so no roles can be using it
		return []string{}, nil
	}

	// Static roles are no longer supported, so just return an empty list
	return []string{}, nil
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

const projectHelpSyn = `
Configure an OpenAI project for use with the secrets engine.
`

const projectHelpDesc = `
This endpoint configures an OpenAI project that can be used by the secrets engine
for creating and managing project service accounts. You must provide the project ID
that corresponds to a valid project in your OpenAI account.
`

const projectListHelpSyn = `
List all configured OpenAI projects.
`

const projectListHelpDesc = `
This endpoint lists all OpenAI projects that have been configured for use with
the secrets engine.
`
