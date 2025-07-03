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

func TestConfig_Paths(t *testing.T) {
	b := getTestBackend(t)

	paths := b.pathAdminConfig()
	assert.Len(t, paths, 2, "expected 2 admin config paths")
	assert.Equal(t, configPath, paths[1].Pattern, "unexpected admin config path pattern")
}

func TestConfig_AdminConfig_CRUD(t *testing.T) {
	b := getTestBackend(t)
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Create config (all required fields present)
	createData := &framework.FieldData{
		Raw: map[string]interface{}{
			"admin_api_key":    "test-key",
			"admin_api_key_id": "test-admin-key-id",
			"organization_id":  "org-123",
			"api_endpoint":     "https://api.test.com/v1",
			"rotation_period":  0, // Required field
		},
		Schema: b.pathAdminConfig()[1].Fields,
	}

	resp, err := b.pathConfigWrite(ctx, &logical.Request{
		Storage:    storage,
		MountPoint: "openai/",
		Path:       "config",
	}, createData)
	require.NoError(t, err)
	require.Nil(t, resp) // On success, response should be nil

	// Test missing admin_api_key
	missingKeyData := &framework.FieldData{
		Raw: map[string]interface{}{
			"organization_id": "org-123",
			"api_endpoint":    "https://api.test.com/v1",
			"rotation_period": 0, // Required field
		},
		Schema: b.pathAdminConfig()[1].Fields,
	}
	missingKeyStorage := &logical.InmemStorage{} // Use fresh storage to ensure no config exists
	resp, err = b.pathConfigWrite(ctx, &logical.Request{
		Storage:    missingKeyStorage,
		MountPoint: "openai/",
		Path:       "config",
	}, missingKeyData)
	require.NoError(t, err)
	t.Logf("resp after missing admin_api_key: %#v", resp)
	if assert.NotNil(t, resp) {
		assert.Equal(t, "admin_api_key is required", resp.Data["error"])
	}

	// Read config
	resp, err = b.pathConfigRead(ctx, &logical.Request{
		Storage:    storage,
		MountPoint: "openai/",
		Path:       "config",
	}, &framework.FieldData{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "https://api.test.com/v1", resp.Data["api_endpoint"])
	assert.Equal(t, "org-123", resp.Data["organization_id"])
	assert.NotContains(t, resp.Data, "admin_api_key", "admin_api_key should not be returned")
	// AdminAPIKeyID should be present in read response and persist in config
	assert.Equal(t, "test-admin-key-id", resp.Data["admin_api_key_id"])
	config, err := getConfig(ctx, storage)
	require.NoError(t, err)
	assert.Equal(t, "test-admin-key-id", config.AdminAPIKeyID)

	// Update config with AdminAPIKeyID
	updateData := &framework.FieldData{
		Raw: map[string]interface{}{
			"admin_api_key":    "updated-key",
			"admin_api_key_id": "updated-key-id",
			"organization_id":  "org-456",
			"api_endpoint":     "https://api.test.com/v1",
			"rotation_period":  0, // Required field
		},
		Schema: b.pathAdminConfig()[1].Fields,
	}
	resp, err = b.pathConfigWrite(ctx, &logical.Request{
		Storage:    storage,
		MountPoint: "openai/",
		Path:       "config",
	}, updateData)
	require.NoError(t, err)
	require.Nil(t, resp) // On success, response should be nil

	// Read updated config
	resp, err = b.pathConfigRead(ctx, &logical.Request{
		Storage:    storage,
		MountPoint: "openai/",
		Path:       "config",
	}, &framework.FieldData{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "https://api.test.com/v1", resp.Data["api_endpoint"])
	assert.Equal(t, "org-456", resp.Data["organization_id"])
	assert.Equal(t, "updated-key-id", resp.Data["admin_api_key_id"])
	config, err = getConfig(ctx, storage)
	require.NoError(t, err)
	assert.Equal(t, "updated-key-id", config.AdminAPIKeyID)

	// Delete config
	_, err = b.pathConfigDelete(ctx, &logical.Request{
		Storage:    storage,
		MountPoint: "openai/",
		Path:       "config",
	}, &framework.FieldData{})
	require.NoError(t, err)

	// Read after delete
	resp, err = b.pathConfigRead(ctx, &logical.Request{
		Storage:    storage,
		MountPoint: "openai/",
		Path:       "config",
	}, &framework.FieldData{})
	require.NoError(t, err)
	require.Nil(t, resp)
}
