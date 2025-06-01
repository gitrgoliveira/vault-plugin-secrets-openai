// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	context "context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminKeyRotation_Manual(t *testing.T) {
	// Start mock server for API calls
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	b := Backend()
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Initial config with mock server URL
	configData := map[string]interface{}{
		"admin_api_key":   "test-key",
		"organization_id": "org-123",
		"api_endpoint":    mockServer.URL() + "/v1",
		"rotation_period": 0, // Required field
	}
	fd := &framework.FieldData{Raw: configData, Schema: b.pathAdminConfig()[1].Fields}
	_, err := b.pathConfigWrite(ctx, &logical.Request{Storage: storage}, fd)
	require.NoError(t, err)

	cfg, cfgErr := getConfig(ctx, storage)
	if cfgErr != nil {
		t.Fatalf("getConfig error after write: %v", cfgErr)
	}
	if cfg == nil {
		t.Fatalf("config is nil after write")
	}
	t.Logf("Config after write: admin_api_key=%q last_rotated_time=%v", cfg.AdminAPIKey, cfg.LastRotatedTime)

	// Spy on rotateAdminAPIKey
	rotated, err := b.rotateAdminAPIKey(ctx, storage)
	if !rotated || err != nil {
		t.Logf("rotateAdminAPIKey returned rotated=%v, err=%v", rotated, err)
		cfg, cfgErr := getConfig(ctx, storage)
		if cfgErr != nil {
			t.Logf("getConfig error: %v", cfgErr)
		} else {
			t.Logf("Config after rotation: admin_api_key=%q last_rotated_time=%v", cfg.AdminAPIKey, cfg.LastRotatedTime)
		}
	}
	assert.NoError(t, err)
	assert.True(t, rotated)
}

func TestAdminKeyRotation_Schedule(t *testing.T) {
	// Start mock server for API calls
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	b := Backend()
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Initial config with mock server URL and rotation period
	configData := map[string]interface{}{
		"admin_api_key":   "test-key",
		"organization_id": "org-123",
		"api_endpoint":    mockServer.URL() + "/v1",
		"rotation_period": 1, // 1 second for test
	}

	// Need to use the correct schema for the test
	fd := &framework.FieldData{
		Raw:    configData,
		Schema: b.pathAdminConfig()[1].Fields,
	}

	_, err := b.pathConfigWrite(ctx, &logical.Request{Storage: storage}, fd)
	require.NoError(t, err)

	// Create rotation queue
	b.credRotationQueue = queue.New()

	// Schedule rotation
	err = b.scheduleAdminKeyRotation(ctx, storage)
	assert.NoError(t, err)

	// Verify item was added to queue
	assert.Equal(t, 1, b.credRotationQueue.Len())

	// To check the item, we need to pop it
	item, err := b.credRotationQueue.Pop()
	assert.NoError(t, err)
	assert.Equal(t, "admin_api_key", item.Key)
}

func TestAdminKeyRotation_Automatic(t *testing.T) {
	// Start mock server for API calls
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	b := Backend()
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Set up storage view for backend
	b.storageView = storage

	// Initial config with mock server URL and 1 second rotation period
	configData := map[string]interface{}{
		"admin_api_key":   "test-key",
		"organization_id": "org-123",
		"api_endpoint":    mockServer.URL() + "/v1",
		"rotation_period": 1, // 1 second for test
	}

	// Set up the config
	fd := &framework.FieldData{
		Raw:    configData,
		Schema: b.pathAdminConfig()[1].Fields,
	}
	_, err := b.pathConfigWrite(ctx, &logical.Request{Storage: storage}, fd)
	require.NoError(t, err)

	// Initialize rotation queue
	b.credRotationQueue = queue.New()

	// Schedule admin key rotation
	err = b.scheduleAdminKeyRotation(ctx, storage)
	assert.NoError(t, err)

	// Verify the queue has an item
	assert.Equal(t, 1, b.credRotationQueue.Len())

	// Instead of using processRotations which would start a goroutine,
	// directly call rotateAdminAPIKey for testing
	rotated, err := b.rotateAdminAPIKey(ctx, storage)
	assert.NoError(t, err)
	assert.True(t, rotated, "Admin key should be rotated")

	// Check if the config was updated with a new API key
	cfg, err := getConfig(ctx, storage)
	assert.NoError(t, err)
	assert.NotEqual(t, "test-key", cfg.AdminAPIKey, "API key should have been rotated")
	assert.Contains(t, cfg.AdminAPIKey, "sk-adminkey", "API key should match the mock implementation")

	// Verify the rotation queue was updated with a new scheduled rotation
	assert.Equal(t, 1, b.credRotationQueue.Len(), "Queue should have one item after rotation")
}
