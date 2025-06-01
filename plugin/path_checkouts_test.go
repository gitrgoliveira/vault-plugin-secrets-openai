package openaisecrets

// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckoutOperations(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)
	ctx := context.Background()

	// Set up config
	config := &openaiConfig{
		AdminAPIKey: "test-admin-key",
	}
	configEntry, err := logical.StorageEntryJSON(configPath, config)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, configEntry))

	// Create a library set
	set := &librarySet{
		ServiceAccountIDs: []string{"svc1", "svc2"},
		ProjectID:         "project1",
		TTL:               1 * time.Hour,
		MaxTTL:            24 * time.Hour,
	}
	err = saveSet(ctx, storage, "testset", set)
	require.NoError(t, err)

	// Mark service accounts as available
	for _, id := range set.ServiceAccountIDs {
		checkOut := &CheckOut{
			IsAvailable: true,
		}
		entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+id, checkOut)
		require.NoError(t, err)
		require.NoError(t, storage.Put(ctx, entry))
	}

	// Register service accounts as managed
	b.managedUserLock.Lock()
	for _, id := range set.ServiceAccountIDs {
		b.managedUsers[id] = struct{}{}
	}
	b.managedUserLock.Unlock()

	// Set up mock client behavior
	mc := &mockClient{}
	b.client = mc
	mc.createAPIKeyFn = func(ctx context.Context, req CreateAPIKeyRequest) (*APIKey, error) {
		return &APIKey{
			ID:  fmt.Sprintf("apikey-%s", req.ServiceAccID),
			Key: "test-api-key",
		}, nil
	}
	mc.getServiceAccountFn = func(ctx context.Context, id string, projectID string) (*ServiceAccount, error) {
		return &ServiceAccount{
			ID:   id,
			Name: fmt.Sprintf("Service Account %s", id),
		}, nil
	}

	// Test checkout operation
	checkoutData := map[string]interface{}{
		"name": "testset",
		"ttl":  1800, // 30 minutes
	}
	checkoutReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "library/testset/check-out",
		Data:        checkoutData,
		Storage:     storage,
		EntityID:    "test-entity",
		ClientToken: "test-token",
	}

	// Create field data
	checkoutFields := map[string]*framework.FieldSchema{
		"name": {
			Type:     framework.TypeString,
			Required: true,
		},
		"ttl": {
			Type: framework.TypeInt,
		},
	}

	checkoutFieldData := &framework.FieldData{
		Raw:    checkoutReq.Data,
		Schema: checkoutFields,
	}

	// Perform checkout
	resp, err := b.operationSetCheckOut(ctx, checkoutReq, checkoutFieldData)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify response
	assert.Equal(t, "svc1", resp.Data["service_account_id"])
	assert.Equal(t, "test-api-key", resp.Data["api_key"])
	assert.Equal(t, "Service Account svc1", resp.Data["service_account_name"])

	// Verify checkout status
	status := map[string]*framework.FieldSchema{
		"name": {
			Type:     framework.TypeString,
			Required: true,
		},
	}

	statusReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "library/testset/status",
		Data: map[string]interface{}{
			"name": "testset",
		},
		Storage: storage,
	}

	statusData := &framework.FieldData{
		Raw:    statusReq.Data,
		Schema: status,
	}

	// Check status
	statusResp, err := b.operationSetStatus(ctx, statusReq, statusData)
	assert.NoError(t, err)
	assert.NotNil(t, statusResp)

	// Verify svc1 is checked out and svc2 is available
	svc1Status := statusResp.Data["svc1"].(map[string]interface{})
	assert.Equal(t, false, svc1Status["available"])
	assert.Equal(t, "test-entity", svc1Status["borrower_entity_id"])
	assert.Equal(t, "test-token", svc1Status["borrower_client_token"])
	assert.NotEmpty(t, svc1Status["check_out_time"])

	svc2Status := statusResp.Data["svc2"].(map[string]interface{})
	assert.Equal(t, true, svc2Status["available"])

	// Test checkin operation
	checkinData := map[string]interface{}{
		"name":                "testset",
		"service_account_ids": []string{"svc1"},
	}
	checkinReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "library/testset/check-in",
		Data:        checkinData,
		Storage:     storage,
		EntityID:    "test-entity",
		ClientToken: "test-token",
	}

	checkinFields := map[string]*framework.FieldSchema{
		"name": {
			Type:     framework.TypeString,
			Required: true,
		},
		"service_account_ids": {
			Type: framework.TypeCommaStringSlice,
		},
	}

	checkinFieldData := &framework.FieldData{
		Raw:    checkinReq.Data,
		Schema: checkinFields,
	}

	// Setup mock for API key deletion
	mc.deleteAPIKeyFn = func(ctx context.Context, id string) error {
		return nil
	}

	// Perform checkin
	checkinResp, err := b.operationCheckIn(false)(ctx, checkinReq, checkinFieldData)
	assert.NoError(t, err)
	assert.NotNil(t, checkinResp)

	// Verify checkin response
	assert.Equal(t, []string{"svc1"}, checkinResp.Data["check_ins"])

	// Verify service account is now available
	statusResp, err = b.operationSetStatus(ctx, statusReq, statusData)
	assert.NoError(t, err)

	svc1Status = statusResp.Data["svc1"].(map[string]interface{})
	assert.Equal(t, true, svc1Status["available"])

	// Test checkout when no service accounts are available
	// First, check out both service accounts
	for _, id := range set.ServiceAccountIDs {
		checkOut := &CheckOut{
			IsAvailable:         false,
			BorrowerEntityID:    "test-entity",
			BorrowerClientToken: "test-token",
		}
		entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+id, checkOut)
		require.NoError(t, err)
		require.NoError(t, storage.Put(ctx, entry))
	}

	// Try to checkout
	unavailableResp, err := b.operationSetCheckOut(ctx, checkoutReq, checkoutFieldData)
	assert.NoError(t, err)
	assert.NotNil(t, unavailableResp)
	assert.Equal(t, "no service accounts available for check-out", unavailableResp.Data["error"])

	// Test forced checkin
	forcedCheckinData := map[string]interface{}{
		"name":                "testset",
		"service_account_ids": []string{"svc1", "svc2"},
	}
	forcedCheckinReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "library/manage/testset/check-in",
		Data:        forcedCheckinData,
		Storage:     storage,
		EntityID:    "admin-entity", // Different entity
		ClientToken: "admin-token",  // Different token
	}

	forcedCheckinFieldData := &framework.FieldData{
		Raw:    forcedCheckinReq.Data,
		Schema: checkinFields,
	}

	// Perform forced checkin
	forcedCheckinResp, err := b.operationCheckIn(true)(ctx, forcedCheckinReq, forcedCheckinFieldData)
	assert.NoError(t, err)
	assert.NotNil(t, forcedCheckinResp)

	// Verify checkin response
	assert.Equal(t, []string{"svc1", "svc2"}, forcedCheckinResp.Data["check_ins"])

	// Verify service accounts are now available
	statusResp, err = b.operationSetStatus(ctx, statusReq, statusData)
	assert.NoError(t, err)

	svc1Status = statusResp.Data["svc1"].(map[string]interface{})
	assert.Equal(t, true, svc1Status["available"])

	svc2Status = statusResp.Data["svc2"].(map[string]interface{})
	assert.Equal(t, true, svc2Status["available"])
}

func TestRenewCheckOut(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)
	ctx := context.Background()

	// Create a library set
	set := &librarySet{
		ServiceAccountIDs: []string{"svc1"},
		ProjectID:         "project1",
		TTL:               1 * time.Hour,
		MaxTTL:            24 * time.Hour,
	}
	err := saveSet(ctx, storage, "testset", set)
	require.NoError(t, err)

	// Create a checkout
	checkOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    "test-entity",
		BorrowerClientToken: "test-token",
		CheckOutTime:        time.Now(),
	}
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+"svc1", checkOut)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Create a renewal request
	renewReq := &logical.Request{
		Operation: logical.RenewOperation,
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"service_account_id": "svc1",
				"set_name":           "testset",
				"project_id":         "project1",
			},
		},
	}

	// Test renewal
	resp, err := b.renewCheckOut(ctx, renewReq, nil)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify renewal TTL
	assert.Equal(t, set.TTL, resp.Secret.TTL)
	assert.Equal(t, set.MaxTTL, resp.Secret.MaxTTL)

	// Test renewal when service account is already checked in
	checkOut.IsAvailable = true
	entry, err = logical.StorageEntryJSON(checkoutStoragePrefix+"svc1", checkOut)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	resp, _ = b.renewCheckOut(ctx, renewReq, nil) // err is ignored as we're checking resp.Error() directly
	assert.NotNil(t, resp)
	assert.Error(t, resp.Error())
}

func TestEndCheckOut(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)
	ctx := context.Background()

	// Set up config
	config := &openaiConfig{
		AdminAPIKey: "test-admin-key",
	}
	configEntry, err := logical.StorageEntryJSON(configPath, config)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, configEntry))

	// Create a checkout
	checkOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    "test-entity",
		BorrowerClientToken: "test-token",
		CheckOutTime:        time.Now(),
	}
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+"svc1", checkOut)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Store an API key
	apiKeyID := "test-api-key"
	keyEntry, err := logical.StorageEntryJSON(apiKeyStoragePrefix+"svc1", apiKeyID)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, keyEntry))

	// Set up mock for API key deletion
	mc := &mockClient{}
	b.client = mc
	mc.deleteAPIKeyFn = func(ctx context.Context, id string) error {
		return nil
	}

	// Create revocation request
	revokeReq := &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"service_account_id": "svc1",
				"project_id":         "project1", // Ensure this is set
				"set_name":           "testset",  // Add set_name for compliance
				"api_key_id":         apiKeyID,
			},
		},
	}

	// Before calling endCheckOut, add:
	require.NotNil(t, revokeReq.Secret.InternalData["project_id"], "project_id must be set in InternalData")
	require.IsType(t, "", revokeReq.Secret.InternalData["project_id"], "project_id must be a string")

	// Test revocation
	_, err = b.endCheckOut(ctx, revokeReq, nil)
	assert.NoError(t, err)

	// Verify service account is now available
	result, err := b.LoadCheckOut(ctx, storage, "svc1")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.IsAvailable)
}
