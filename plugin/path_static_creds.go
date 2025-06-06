// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// Static roles storage path
	staticRolePath = "static-roles"
)

// staticRoleEntry contains configuration for a static role
type staticRoleEntry struct {
	ServiceAccountID string        `json:"service_account_id"`
	ProjectID        string        `json:"project_id"`
	Name             string        `json:"name"`
	APIKeyName       string        `json:"api_key_name"`
	LastRotatedTime  time.Time     `json:"last_rotated_time"`
	RotationPeriod   time.Duration `json:"rotation_period"`
	TTL              time.Duration `json:"ttl"`
	APIKey           string        `json:"api_key"`
}

// pathStaticRoles returns the path for managing static roles
func (b *backend) pathStaticRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "static-roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathStaticRolesList,
					Summary:  "List all static roles.",
				},
			},
			HelpSynopsis:    "List all static roles",
			HelpDescription: "List all existing static roles.",
		},
		{
			Pattern: "static-roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the static role",
					Required:    true,
				},
				"project": {
					Type:        framework.TypeString,
					Description: "Name of the project to use for this role",
					Required:    true,
				},
				"service_account_id": {
					Type:        framework.TypeString,
					Description: "ID of the existing service account to use for this static role",
					Required:    true,
				},
				"api_key_name": {
					Type:        framework.TypeString,
					Description: "Name to use for API keys created for this role",
					Default:     "vault-static-key",
				},
				"rotation_period": {
					Type:        framework.TypeDurationSecond,
					Description: "How often to rotate the API key. If set to 0, rotation is disabled.",
					Default:     "0",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "TTL for API keys created for this role",
					Default:     "24h",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleRead,
					Summary:  "Read a static role.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleWrite,
					Summary:  "Create a static role.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleWrite,
					Summary:  "Update a static role.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathStaticRoleDelete,
					Summary:  "Delete a static role.",
				},
			},
			ExistenceCheck:  b.pathStaticRoleExistenceCheck,
			HelpSynopsis:    "Manage static roles",
			HelpDescription: "Create, update, read, and delete static roles.",
		},
		{
			Pattern: "static-creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the static role",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathStaticCredsRead,
					Summary:  "Read the API key for a static role.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathStaticCredsRotate,
					Summary:  "Rotate the API key for a static role.",
				},
			},
			ExistenceCheck:  existenceCheckForNamedPath("name", func(name string) string { return staticRolePath + "/" + name }),
			HelpSynopsis:    "Access API keys for static roles",
			HelpDescription: "Read and rotate API keys for static roles.",
		},
	}
}

// pathStaticRolesList lists all static roles
func (b *backend) pathStaticRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, staticRolePath+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathStaticRoleExistenceCheck checks if a static role exists
func (b *backend) pathStaticRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)
	if name == "" {
		return false, fmt.Errorf("role name is required")
	}

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

// pathStaticRoleRead reads a static role
func (b *backend) pathStaticRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	// Return role information (excluding sensitive information)
	return &logical.Response{
		Data: map[string]interface{}{
			"service_account_id": role.ServiceAccountID,
			"project_id":         role.ProjectID,
			"name":               role.Name,
			"api_key_name":       role.APIKeyName,
			"last_rotated_time":  role.LastRotatedTime.Format(time.RFC3339),
			"rotation_period":    int64(role.RotationPeriod.Seconds()),
			"ttl":                int64(role.TTL.Seconds()),
		},
	}, nil
}

// pathStaticRoleWrite creates or updates a static role
func (b *backend) pathStaticRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	// Check if a role with this name already exists
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// If role doesn't exist, create a new one
	if role == nil {
		role = &staticRoleEntry{
			Name: name,
		}
	}

	// Get project name
	projectName := data.Get("project").(string)
	if projectName == "" {
		return logical.ErrorResponse("project is required"), nil
	}

	// Get project configuration
	project, err := b.getProject(ctx, req.Storage, projectName)
	if err != nil {
		return nil, err
	}

	if project == nil {
		return logical.ErrorResponse("project %q not found", projectName), nil
	}

	// API key name
	if apiKeyName, ok := data.GetOk("api_key_name"); ok {
		role.APIKeyName = apiKeyName.(string)
	}
	if role.APIKeyName == "" {
		role.APIKeyName = "vault-static-key"
	}

	// Rotation period
	if rotationPeriod, ok := data.GetOk("rotation_period"); ok {
		role.RotationPeriod = time.Duration(rotationPeriod.(int)) * time.Second
	}

	// TTL
	if ttl, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttl.(int)) * time.Second
	}
	if role.TTL == 0 {
		role.TTL = 24 * time.Hour
	}

	role.ProjectID = project.ProjectID

	// Always create a new service account and API key for static roles
	if b.client == nil {
		return logical.ErrorResponse("OpenAI client not configured"), nil
	}

	svcAccount, apiKey, err := b.client.CreateServiceAccount(ctx, role.ProjectID, CreateServiceAccountRequest{
		Name:        role.APIKeyName + "-static",
		Description: "Vault static role: " + name,
	})
	if err != nil {
		return logical.ErrorResponse("failed to create service account and API key: %s", err), nil
	}
	role.ServiceAccountID = svcAccount.ID
	role.APIKey = apiKey.Key
	role.LastRotatedTime = time.Now()

	// Save the role
	entry, err := logical.StorageEntryJSON(staticRolePath+"/"+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathStaticRoleDelete deletes a static role
func (b *backend) pathStaticRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	// Get the role to check if it has an API key that needs to be deleted
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	// Revoke the API key from OpenAI if present
	if b.client != nil && role.APIKey != "" {
		// Attempt to delete the API key
		err := b.client.DeleteAPIKey(ctx, role.APIKey)
		if err != nil {
			b.Logger().Warn("failed to revoke API key during static role deletion", "role", name, "api_key", role.APIKey, "error", err)
			return logical.ErrorResponse("failed to revoke API key from OpenAI: %s", err), nil
		}
	}

	// TODO: Clean up any additional related storage if needed (e.g., API key mappings)

	// Delete the role
	if err := req.Storage.Delete(ctx, staticRolePath+"/"+name); err != nil {
		return nil, err
	}

	return nil, nil
}

// staticSecretCreds creates a Secret type for static credentials
func staticSecretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: "openai_static_api_key",
		Fields: map[string]*framework.FieldSchema{
			"api_key": {
				Type:        framework.TypeString,
				Description: "OpenAI API key",
			},
			"service_account_id": {
				Type:        framework.TypeString,
				Description: "ID of the service account",
			},
			"project_id": {
				Type:        framework.TypeString,
				Description: "ID of the project",
			},
			"last_rotated": {
				Type:        framework.TypeString,
				Description: "Last rotation time (RFC3339)",
			},
			"ttl": {
				Type:        framework.TypeInt,
				Description: "TTL in seconds",
			},
			"rotation_period": {
				Type:        framework.TypeInt,
				Description: "Rotation period in seconds",
			},
		},
	}
}

// pathStaticCredsRead reads credentials for a static role
func (b *backend) pathStaticCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	// Get the role
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("static role %q not found", name), nil
	}

	resp := staticSecretCreds(b).Response(map[string]interface{}{
		"api_key":            role.APIKey,
		"service_account_id": role.ServiceAccountID,
		"project_id":         role.ProjectID,
		"last_rotated":       role.LastRotatedTime.Format(time.RFC3339),
		"ttl":                int64(role.TTL.Seconds()),
		"rotation_period":    int64(role.RotationPeriod.Seconds()),
	}, nil)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.TTL
	resp.Secret.Renewable = false
	return resp, nil
}

// pathStaticCredsRotate rotates the API key for a static role
func (b *backend) pathStaticCredsRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	// Get the role
	role, err := b.getStaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("static role %q not found", name), nil
	}

	// Ensure client is configured
	if b.client == nil {
		return logical.ErrorResponse("OpenAI client not configured"), nil
	}

	// Create a new service account and API key for rotation
	svcAccount, apiKey, err := b.client.CreateServiceAccount(ctx, role.ProjectID, CreateServiceAccountRequest{
		Name:        role.APIKeyName + "-static",
		Description: "Vault static role rotation: " + name,
	})
	if err != nil {
		return logical.ErrorResponse("failed to create service account and API key: %s", err), nil
	}
	oldAPIKey := role.APIKey
	oldServiceAccountID := role.ServiceAccountID
	role.ServiceAccountID = svcAccount.ID
	role.APIKey = apiKey.Key
	role.LastRotatedTime = time.Now()

	// Save the updated role with the new key
	entry, err := logical.StorageEntryJSON(staticRolePath+"/"+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Now revoke the old API key and service account if present
	if oldAPIKey != "" {
		_ = b.client.DeleteAPIKey(ctx, oldAPIKey) // ignore error
	}
	if oldServiceAccountID != "" {
		_ = b.client.DeleteServiceAccount(ctx, oldServiceAccountID, role.ProjectID) // ignore error
	}

	resp := staticSecretCreds(b).Response(map[string]interface{}{
		"api_key":            role.APIKey,
		"service_account_id": role.ServiceAccountID,
		"project_id":         role.ProjectID,
		"last_rotated":       role.LastRotatedTime.Format(time.RFC3339),
		"ttl":                int64(role.TTL.Seconds()),
		"rotation_period":    int64(role.RotationPeriod.Seconds()),
	}, nil)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.TTL
	resp.Secret.Renewable = false
	return resp, nil
}

// getStaticRole retrieves a static role from storage
func (b *backend) getStaticRole(ctx context.Context, s logical.Storage, name string) (*staticRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("role name is required")
	}

	entry, err := s.Get(ctx, staticRolePath+"/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role staticRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}
