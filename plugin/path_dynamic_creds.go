// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"text/template"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathDynamicSvcAccount returns the path for managing dynamic service accounts
func (b *backend) pathDynamicSvcAccount() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"project": {
					Type:        framework.TypeString,
					Description: "Name of the project to use for this role",
					Required:    true,
				},
				"service_account_name_template": {
					Type:        framework.TypeString,
					Description: "Template for the service account name to be created",
					Default:     "vault-{{.RoleName}}-{{.RandomSuffix}}",
				},
				"service_account_description": {
					Type:        framework.TypeString,
					Description: "Description for created service accounts",
					Default:     "Service account created by Vault",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for API keys created for this role",
					Default:     "1h",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum TTL for API keys created for this role",
					Default:     "24h",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
					Summary:  "Read a role definition.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Create or update a role definition.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Create or update a role definition.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					Summary:  "Delete a role definition.",
				},
			},

			ExistenceCheck:  existenceCheckForNamedPath("name", roleStoragePath),
			HelpSynopsis:    dynamicRoleHelpSyn,
			HelpDescription: dynamicRoleHelpDesc,
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
					Summary:  "List all roles.",
				},
			},
			HelpSynopsis:    dynamicRoleListHelpSyn,
			HelpDescription: dynamicRoleListHelpDesc,
		},
	}
}

// pathDynamicCredsCreate returns the path for creating dynamic credentials
func (b *backend) pathDynamicCredsCreate() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "TTL for the API key. Overrides the role default if specified.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathCredsCreate,
					Summary:  "Generate a new API key for accessing OpenAI.",
				},
			},

			HelpSynopsis:    dynamicCredsHelpSyn,
			HelpDescription: dynamicCredsHelpDesc,
		},
	}
}

// dynamicRoleEntry represents a dynamic role
type dynamicRoleEntry struct {
	Project                    string        `json:"project"`
	ServiceAccountNameTemplate string        `json:"service_account_name_template"`
	ServiceAccountDescription  string        `json:"service_account_description"`
	TTL                        time.Duration `json:"ttl"`
	MaxTTL                     time.Duration `json:"max_ttl"`
}

// pathRoleRead reads a role definition
func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// Return role information
	return &logical.Response{
		Data: map[string]interface{}{
			"project":                       role.Project,
			"service_account_name_template": role.ServiceAccountNameTemplate,
			"service_account_description":   role.ServiceAccountDescription,
			"ttl":                           int64(role.TTL.Seconds()),
			"max_ttl":                       int64(role.MaxTTL.Seconds()),
		},
	}, nil
}

// pathRoleWrite creates or updates a role definition
func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	// Get existing role or create new one
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &dynamicRoleEntry{}
	}

	// Update role from request data
	projectName := data.Get("project").(string)
	if projectName == "" {
		return logical.ErrorResponse("project is required"), nil
	}

	// Verify the project exists
	project, err := b.getProject(ctx, req.Storage, projectName)
	if err != nil {
		return nil, fmt.Errorf("error checking project: %w", err)
	}
	if project == nil {
		return logical.ErrorResponse("project %q does not exist", projectName), nil
	}

	role.Project = projectName

	if serviceAccountNameTemplate, ok := data.GetOk("service_account_name_template"); ok {
		role.ServiceAccountNameTemplate = serviceAccountNameTemplate.(string)
	} else if role.ServiceAccountNameTemplate == "" {
		role.ServiceAccountNameTemplate = "vault-{{.RoleName}}-{{.RandomSuffix}}"
	}

	if serviceAccountDescription, ok := data.GetOk("service_account_description"); ok {
		role.ServiceAccountDescription = serviceAccountDescription.(string)
	} else if role.ServiceAccountDescription == "" {
		role.ServiceAccountDescription = "Service account created by Vault"
	}

	if ttlRaw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if role.TTL == 0 {
		role.TTL = time.Hour // Default 1 hour
	}

	if maxTTLRaw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if role.MaxTTL == 0 {
		role.MaxTTL = 24 * time.Hour // Default 24 hours
	}

	// Validate TTLs
	if role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	// Save role
	entry, err := logical.StorageEntryJSON(roleStoragePath(roleName), role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleDelete deletes a role definition
func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	err := req.Storage.Delete(ctx, roleStoragePath(roleName))
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}

	return nil, nil
}

// pathRoleList lists all role definitions
func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}

	return logical.ListResponse(roles), nil
}

// getRole retrieves a role definition from storage
func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*dynamicRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("role name is required")
	}

	entry, err := s.Get(ctx, roleStoragePath(name))
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var role dynamicRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error decoding role: %w", err)
	}

	return &role, nil
}

// roleStoragePath returns the storage path for a role
func roleStoragePath(name string) string {
	return fmt.Sprintf("roles/%s", name)
}

// pathCredsCreate creates dynamic credentials for a role
func (b *backend) pathCredsCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	// Get role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	// Get project
	project, err := b.getProject(ctx, req.Storage, role.Project)
	if err != nil {
		return nil, fmt.Errorf("error retrieving project: %w", err)
	}
	if project == nil {
		return logical.ErrorResponse("project %q does not exist", role.Project), nil
	}

	// Initialize the client if it hasn't been
	if b.client == nil {
		config, err := getConfig(ctx, req.Storage)
		if err != nil {
			return nil, fmt.Errorf("error getting OpenAI configuration: %w", err)
		}
		if config == nil {
			return logical.ErrorResponse("OpenAI is not configured"), nil
		}

		b.client = NewClient(config.AdminAPIKey, b.Logger())
	}

	// Generate a random suffix for the service account name
	randSuffix, err := generateRandomString(8)
	if err != nil {
		return nil, fmt.Errorf("error generating random suffix: %w", err)
	}

	// Format the service account name
	nameData := map[string]interface{}{
		"RoleName":     roleName,
		"RandomSuffix": randSuffix,
		"ProjectName":  project.Name,
	}
	svcAccountName, err := formatName(role.ServiceAccountNameTemplate, nameData)
	if err != nil {
		return nil, fmt.Errorf("error formatting service account name: %w", err)
	}

	// Sanitize service account name to ensure it matches OpenAI requirements
	originalName := svcAccountName
	svcAccountName = SanitizeServiceAccountName(svcAccountName)
	if originalName != svcAccountName {
		b.Logger().Info("Sanitized service account name to meet OpenAI requirements",
			"original", originalName,
			"sanitized", svcAccountName)
	}

	// Determine TTL
	ttl := role.TTL
	if ttlRaw, ok := data.GetOk("ttl"); ok {
		requestedTTL := time.Duration(ttlRaw.(int)) * time.Second
		if requestedTTL > 0 && requestedTTL < role.MaxTTL {
			ttl = requestedTTL
		}
	}

	// Calculate expiry time
	expiresAt := time.Now().Add(ttl)

	// Create service account (which automatically creates an API key in OpenAI API)
	b.Logger().Debug("Creating service account with API key", "name", svcAccountName, "project", project.ProjectID)
	svcAccount, apiKey, err := b.client.CreateServiceAccount(ctx, project.ProjectID, CreateServiceAccountRequest{
		Name:        svcAccountName,
		Description: role.ServiceAccountDescription,
	})
	if err != nil {
		b.emitAPIErrorMetric("CreateServiceAccount", "error")
		return nil, fmt.Errorf("error creating service account: %w", err)
	}

	// Note: In OpenAI API, we can't control the TTL of API keys created with service accounts
	// We'll track the TTL in Vault's system for credential revocation

	// Store service account info for cleanup
	if err := b.storeServiceAccountInfo(ctx, req.Storage, apiKey.ID, svcAccount.ID, expiresAt); err != nil {
		b.Logger().Error("failed to store service account mapping", "error", err)
		// Continue anyway, as the credentials are still valid
	}

	// Emit metric for credential issuance
	b.emitCredentialIssuedMetric(roleName)

	// Generate the response
	resp := b.Secret(dynamicSecretCredsType).Response(map[string]interface{}{
		"api_key":            apiKey.Key,
		"api_key_id":         apiKey.ID,
		"service_account_id": svcAccount.ID,
		"service_account":    svcAccount.Name,
	}, map[string]interface{}{
		"api_key_id":         apiKey.ID,
		"service_account_id": svcAccount.ID,
		"project_id":         project.ProjectID,
	})

	// Set lease
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// apiKeyMapping stores the relationship between API keys and service accounts
type apiKeyMapping struct {
	APIKeyID         string    `json:"api_key_id"`
	ServiceAccountID string    `json:"service_account_id"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// storeServiceAccountInfo stores the mapping between an API key and its service account
func (b *backend) storeServiceAccountInfo(ctx context.Context, s logical.Storage, apiKeyID, serviceAccountID string, expiresAt time.Time) error {
	mapping := apiKeyMapping{
		APIKeyID:         apiKeyID,
		ServiceAccountID: serviceAccountID,
		ExpiresAt:        expiresAt,
	}

	entry, err := logical.StorageEntryJSON(apiKeyMappingPath(apiKeyID), mapping)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

// apiKeyMappingPath returns the storage path for an API key mapping
func apiKeyMappingPath(apiKeyID string) string {
	return fmt.Sprintf("api_keys/%s", apiKeyID)
}

// Secret structure that represents a dynamically generated API key
func dynamicSecretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: dynamicSecretCredsType,
		Fields: map[string]*framework.FieldSchema{
			"api_key": {
				Type:        framework.TypeString,
				Description: "OpenAI API key",
			},
			"api_key_id": {
				Type:        framework.TypeString,
				Description: "ID of the OpenAI API key",
			},
			"service_account_id": {
				Type:        framework.TypeString,
				Description: "ID of the service account",
			},
			"service_account": {
				Type:        framework.TypeString,
				Description: "Name of the service account",
			},
		},

		Revoke: b.dynamicCredsRevoke,
	}
}

// dynamicCredsRevoke revokes the API key and deletes the service account
func (b *backend) dynamicCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	apiKeyID := req.Secret.InternalData["api_key_id"].(string)
	serviceAccountID := req.Secret.InternalData["service_account_id"].(string)
	projectID := req.Secret.InternalData["project_id"].(string)

	b.Logger().Debug("revoking API key", "api_key_id", apiKeyID, "service_account_id", serviceAccountID)

	// Initialize the client if it hasn't been
	if b.client == nil {
		config, err := getConfig(ctx, req.Storage)
		if err != nil {
			return nil, fmt.Errorf("error getting OpenAI configuration: %w", err)
		}
		if config == nil {
			return logical.ErrorResponse("OpenAI is not configured"), nil
		}

		b.client = NewClient(config.AdminAPIKey, b.Logger())
	}

	// Delete the API key
	if err := b.client.DeleteAPIKey(ctx, apiKeyID); err != nil {
		b.emitAPIErrorMetric("DeleteAPIKey", "error")
		b.Logger().Error("error deleting API key", "api_key_id", apiKeyID, "error", err)
		// Continue to try to delete the service account even if API key deletion fails
	}

	// Delete the service account - include projectID as required by the OpenAI API
	if err := b.client.DeleteServiceAccount(ctx, serviceAccountID, projectID); err != nil {
		b.emitAPIErrorMetric("DeleteServiceAccount", "error")
		return nil, fmt.Errorf("error deleting service account: %w", err)
	}

	// Delete the API key mapping
	if err := req.Storage.Delete(ctx, apiKeyMappingPath(apiKeyID)); err != nil {
		b.Logger().Error("error deleting API key mapping", "api_key_id", apiKeyID, "error", err)
		// This is not a fatal error, so continue
	}

	// Emit metric for credential revocation
	b.emitCredentialRevokedMetric("dynamic")

	return nil, nil
}

// Helper functions

// formatName formats a name template with the provided data
func formatName(templateStr string, data map[string]interface{}) (string, error) {
	tmpl, err := template.New("name").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("invalid template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("error executing template: %w", err)
	}

	return buf.String(), nil
}

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)

	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %w", err)
	}

	for i, b := range randomBytes {
		result[i] = charset[int(b)%len(charset)]
	}

	return string(result), nil
}

const dynamicRoleHelpSyn = `
Manage roles for generating OpenAI API keys.
`

const dynamicRoleHelpDesc = `
This endpoint allows you to create, read, update, and delete roles that can be
used to generate dynamic OpenAI API keys. Each role is associated with an OpenAI
project and defines the TTL and naming for generated service accounts and API keys.
`

const dynamicRoleListHelpSyn = `
List all roles.
`

const dynamicRoleListHelpDesc = `
This endpoint lists all roles that can be used to generate dynamic OpenAI API keys.
`

const dynamicCredsHelpSyn = `
Generate a new OpenAI API key.
`

const dynamicCredsHelpDesc = `
This endpoint generates a new dynamic OpenAI API key by creating a project service
account and then generating an API key for that service account. The API key will
have a TTL as defined by the role or as specified in the request.
`

const dynamicSecretCredsType = "openai_api_key"
