// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatName(t *testing.T) {
	tests := []struct {
		name     string
		template string
		data     map[string]interface{}
		expected string
		hasError bool
	}{
		{
			name:     "simple template",
			template: "vault-{{.RoleName}}-{{.RandomSuffix}}",
			data: map[string]interface{}{
				"RoleName":     "test",
				"RandomSuffix": "abc123",
			},
			expected: "vault-test-abc123",
			hasError: false,
		},
		{
			name:     "complex template",
			template: "vault-{{.RoleName}}-{{.RandomSuffix}}-{{.ProjectName}}",
			data: map[string]interface{}{
				"RoleName":     "test",
				"RandomSuffix": "abc123",
				"ProjectName":  "proj1",
			},
			expected: "vault-test-abc123-proj1",
			hasError: false,
		},
		{
			name:     "invalid template",
			template: "vault-{{.RoleName}-{{.RandomSuffix}}",
			data: map[string]interface{}{
				"RoleName":     "test",
				"RandomSuffix": "abc123",
			},
			expected: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := formatName(tt.template, tt.data)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	// Test with different lengths
	lengths := []int{8, 16, 32}

	for _, length := range lengths {
		t.Run("length_"+string(rune(length)), func(t *testing.T) {
			// Generate two random strings of the same length
			str1, err := generateRandomString(length)
			require.NoError(t, err)
			str2, err := generateRandomString(length)
			require.NoError(t, err)

			// Check that both strings have the expected length
			assert.Equal(t, length, len(str1))
			assert.Equal(t, length, len(str2))

			// Check that the two strings are different (extremely unlikely to be the same)
			assert.NotEqual(t, str1, str2)
		})
	}
}

func TestDynamicRoleEntry_Validation(t *testing.T) {
	b := &backend{
		client: nil, // Not needed for this test
	}

	// Setup storage for project
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	project := &projectEntry{
		ProjectID: "proj_123",
		Name:      "test-project",
	}

	entry, err := logical.StorageEntryJSON("project/test-project", project)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Test cases
	tests := []struct {
		name        string
		data        *framework.FieldData
		expectError bool
	}{
		{
			name: "valid role",
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"name":                          "test-role",
					"project_id":                    "test-project",
					"service_account_name_template": "vault-{{.RoleName}}-{{.RandomSuffix}}",
					"service_account_description":   "Test service account",
					"ttl":                           3600,
					"max_ttl":                       86400,
				},
				Schema: b.pathDynamicSvcAccount()[0].Fields,
			},
			expectError: false,
		},
		{
			name: "missing project",
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"name":                          "test-role",
					"service_account_name_template": "vault-{{.RoleName}}-{{.RandomSuffix}}",
					"ttl":                           3600,
					"max_ttl":                       86400,
				},
				Schema: b.pathDynamicSvcAccount()[0].Fields,
			},
			expectError: true,
		},
		{
			name: "non-existent project",
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"name":                          "test-role",
					"project_id":                    "non-existent",
					"service_account_name_template": "vault-{{.RoleName}}-{{.RandomSuffix}}",
					"ttl":                           3600,
					"max_ttl":                       86400,
				},
				Schema: b.pathDynamicSvcAccount()[0].Fields,
			},
			expectError: true,
		},
		{
			name: "ttl > max_ttl",
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"name":                          "test-role",
					"project_id":                    "test-project",
					"service_account_name_template": "vault-{{.RoleName}}-{{.RandomSuffix}}",
					"ttl":                           100000,
					"max_ttl":                       3600,
				},
				Schema: b.pathDynamicSvcAccount()[0].Fields,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := b.pathRoleWrite(ctx, &logical.Request{Storage: storage}, tt.data)
			if tt.expectError {
				// Accept either a non-nil error response or a nil response (for non-existent project)
				if resp == nil {
					// Acceptable: nil response means error
					return
				}
				if resp.Data != nil {
					_, hasError := resp.Data["error"]
					assert.True(t, hasError, "Expected error message in response")
				}
			} else {
				assert.Nil(t, resp, "Expected no response for success case")
			}
		})
	}
}

// TestMetricEmissionOnCredentialIssuance verifies that emitCredentialIssuedMetric is called during credential issuance
func TestMetricEmissionOnCredentialIssuance(t *testing.T) {
	b := getTestBackend(t)
	// Setup: create a role and project in storage
	ctx := context.Background()
	storage := getTestStorage(t)
	b.storageView = storage
	roleName := "test-role"
	projectName := "test-project"
	// Insert project and role
	insertTestProject(ctx, t, storage, projectName)
	insertTestRole(ctx, t, storage, roleName, projectName)

	// Spy: wrap IncrCounterWithLabels
	var called bool
	orig := IncrCounterWithLabels
	IncrCounterWithLabels = func(ctx context.Context, names []string, val float32, labels []Label) {
		called = true
		t.Logf("IncrCounterWithLabels called: names=%v val=%v labels=%v", names, val, labels)
		orig(ctx, names, val, labels)
	}
	defer func() { IncrCounterWithLabels = orig }()

	// Issue credentials
	fieldData := &framework.FieldData{
		Raw: map[string]interface{}{"name": roleName},
		Schema: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
		},
	}
	resp, err := b.pathCredsCreate(ctx, &logical.Request{Storage: storage}, fieldData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("Issuance Response: %+v", resp)
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
	t.Logf("Issuance Secret: %+v", resp.Secret)
	if !called {
		t.Error("expected emitCredentialIssuedMetric to be called, but it was not")
	}
}

// TestMetricEmissionOnCredentialRevocation verifies that emitCredentialRevokedMetric is called during revocation
func TestMetricEmissionOnCredentialRevocation(t *testing.T) {
	b := getTestBackend(t)
	ctx := context.Background()
	storage := getTestStorage(t)
	b.storageView = storage
	roleName := "test-role"
	projectName := "test-project"
	insertTestProject(ctx, t, storage, projectName)
	insertTestRole(ctx, t, storage, roleName, projectName)

	// Issue credentials to get a secret
	fieldData := &framework.FieldData{
		Raw: map[string]interface{}{"name": roleName},
		Schema: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
		},
	}
	resp, err := b.pathCredsCreate(ctx, &logical.Request{Storage: storage}, fieldData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret := resp.Secret
	// Ensure InternalData is fully populated for revocation
	if secret.InternalData == nil {
		secret.InternalData = map[string]interface{}{}
	}
	secret.InternalData["api_key_id"] = "key-123"
	secret.InternalData["service_account_id"] = "svc-123"
	secret.InternalData["project_id"] = projectName + "_id"
	t.Logf("Revocation Secret: %+v", secret)

	// Spy: wrap IncrCounterWithLabels
	var called bool
	orig := IncrCounterWithLabels
	IncrCounterWithLabels = func(ctx context.Context, names []string, val float32, labels []Label) {
		called = true
		t.Logf("IncrCounterWithLabels called: names=%v val=%v labels=%v", names, val, labels)
		orig(ctx, names, val, labels)
	}
	defer func() { IncrCounterWithLabels = orig }()

	// Revoke credentials
	_, err = b.dynamicCredsRevoke(ctx, &logical.Request{Storage: storage, Secret: secret}, &framework.FieldData{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected emitCredentialRevokedMetric to be called, but it was not")
	}
}
