package openaisecrets

// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckOut(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)

	ctx := context.Background()

	// Create a test service account checkout entry
	serviceAccountID := "test-service-account"
	checkOut := &CheckOut{
		IsAvailable: true,
	}
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+serviceAccountID, checkOut)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Test checkout of the service account
	newCheckOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    "test-entity",
		BorrowerClientToken: "test-token",
	}

	err = b.CheckOut(ctx, storage, serviceAccountID, newCheckOut)
	assert.NoError(t, err)

	// Verify the service account is now checked out
	result, err := b.LoadCheckOut(ctx, storage, serviceAccountID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsAvailable)
	assert.Equal(t, "test-entity", result.BorrowerEntityID)
	assert.Equal(t, "test-token", result.BorrowerClientToken)
	assert.False(t, result.CheckOutTime.IsZero())

	// Test trying to check out an already checked out service account
	err = b.CheckOut(ctx, storage, serviceAccountID, &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    "another-entity",
		BorrowerClientToken: "another-token",
	})
	assert.Equal(t, errCheckedOut, err)

	// Test checkout with nil parameters
	err = b.CheckOut(context.TODO(), storage, serviceAccountID, newCheckOut)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ctx must be provided")

	err = b.CheckOut(ctx, nil, serviceAccountID, newCheckOut)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage must be provided")

	err = b.CheckOut(ctx, storage, "", newCheckOut)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account ID must be provided")

	err = b.CheckOut(ctx, storage, serviceAccountID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "check-out must be provided")
}

func TestCheckIn(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)

	ctx := context.Background()
	serviceAccountID := "test-service-account"
	projectID := "test-project"

	// Create a checked out service account
	checkOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    "test-entity",
		BorrowerClientToken: "test-token",
		CheckOutTime:        time.Now(),
	}
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+serviceAccountID, checkOut)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Store a fake API key ID for the service account
	apiKeyID := "test-api-key-id"
	keyEntry, err := logical.StorageEntryJSON(apiKeyStoragePrefix+serviceAccountID, apiKeyID)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, keyEntry))

	// Setup a mock client
	mc := &mockClient{}
	b.client = mc

	// Test check in
	err = b.CheckIn(ctx, storage, serviceAccountID, projectID)
	assert.NoError(t, err)

	// Verify the service account is now available
	result, err := b.LoadCheckOut(ctx, storage, serviceAccountID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.IsAvailable)

	// Verify the API key was deleted
	assert.Equal(t, apiKeyID, mc.lastDeletedAPIKeyID)

	// Test checkin with nil parameters
	err = b.CheckIn(context.TODO(), storage, serviceAccountID, projectID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ctx must be provided")

	err = b.CheckIn(ctx, nil, serviceAccountID, projectID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage must be provided")

	err = b.CheckIn(ctx, storage, "", projectID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account ID must be provided")

	err = b.CheckIn(ctx, storage, serviceAccountID, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "project ID must be provided")
}

func TestLoadCheckOut(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)

	ctx := context.Background()
	serviceAccountID := "test-service-account"

	// Test loading a non-existent checkout
	result, err := b.LoadCheckOut(ctx, storage, serviceAccountID)
	assert.Equal(t, errNotFound, err)
	assert.Nil(t, result)

	// Create a checkout entry
	checkOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    "test-entity",
		BorrowerClientToken: "test-token",
		CheckOutTime:        time.Now(),
	}
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+serviceAccountID, checkOut)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Test loading the checkout
	result, err = b.LoadCheckOut(ctx, storage, serviceAccountID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, checkOut.IsAvailable, result.IsAvailable)
	assert.Equal(t, checkOut.BorrowerEntityID, result.BorrowerEntityID)
	assert.Equal(t, checkOut.BorrowerClientToken, result.BorrowerClientToken)
	assert.Equal(t, checkOut.CheckOutTime.Unix(), result.CheckOutTime.Unix())

	// Test with nil parameters
	result, err = b.LoadCheckOut(context.TODO(), storage, serviceAccountID)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ctx must be provided")

	result, err = b.LoadCheckOut(ctx, nil, serviceAccountID)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "storage must be provided")

	result, err = b.LoadCheckOut(ctx, storage, "")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "service account ID must be provided")
}

func TestDeleteCheckout(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)

	ctx := context.Background()
	serviceAccountID := "test-service-account"

	// Create a checkout entry
	checkOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    "test-entity",
		BorrowerClientToken: "test-token",
	}
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+serviceAccountID, checkOut)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Create an API key entry
	apiKeyID := "test-api-key-id"
	keyEntry, err := logical.StorageEntryJSON(apiKeyStoragePrefix+serviceAccountID, apiKeyID)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, keyEntry))

	// Test deleting the checkout
	err = b.DeleteCheckout(ctx, storage, serviceAccountID)
	assert.NoError(t, err)

	// Verify the checkout was deleted
	result, err := b.LoadCheckOut(ctx, storage, serviceAccountID)
	assert.Equal(t, errNotFound, err)
	assert.Nil(t, result)

	// Verify the API key entry was deleted
	apiKeyEntry, err := storage.Get(ctx, apiKeyStoragePrefix+serviceAccountID)
	assert.NoError(t, err)
	assert.Nil(t, apiKeyEntry)

	// Test with nil parameters
	err = b.DeleteCheckout(nil, storage, serviceAccountID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ctx must be provided")

	err = b.DeleteCheckout(ctx, nil, serviceAccountID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage must be provided")

	err = b.DeleteCheckout(ctx, storage, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account ID must be provided")
}

func TestCheckinAuthorized(t *testing.T) {
	// Test cases for entity ID
	req := &logical.Request{
		EntityID: "test-entity",
	}
	checkOut := &CheckOut{
		BorrowerEntityID: "test-entity",
	}
	assert.True(t, checkinAuthorized(req, checkOut))

	// Different entity ID
	checkOut.BorrowerEntityID = "different-entity"
	assert.False(t, checkinAuthorized(req, checkOut))

	// Test cases for client token
	req = &logical.Request{
		ClientToken: "test-token",
	}
	checkOut = &CheckOut{
		BorrowerClientToken: "test-token",
	}
	assert.True(t, checkinAuthorized(req, checkOut))

	// Different client token
	checkOut.BorrowerClientToken = "different-token"
	assert.False(t, checkinAuthorized(req, checkOut))

	// Empty checkout
	checkOut = &CheckOut{}
	assert.False(t, checkinAuthorized(req, checkOut))
}

func TestStoreAndGetAPIKey(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)

	ctx := context.Background()
	serviceAccountID := "test-service-account"
	apiKeyID := "test-api-key-id"

	// Store API key
	err := b.StoreAPIKey(ctx, storage, serviceAccountID, apiKeyID)
	assert.NoError(t, err)

	// Get API key
	retrievedKeyID, err := b.GetAPIKey(ctx, storage, serviceAccountID)
	assert.NoError(t, err)
	assert.Equal(t, apiKeyID, retrievedKeyID)

	// Test get with non-existent key
	retrievedKeyID, err = b.GetAPIKey(ctx, storage, "non-existent")
	assert.Equal(t, errNotFound, err)
	assert.Empty(t, retrievedKeyID)

	// Test with nil parameters for StoreAPIKey
	err = b.StoreAPIKey(nil, storage, serviceAccountID, apiKeyID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ctx must be provided")

	err = b.StoreAPIKey(ctx, nil, serviceAccountID, apiKeyID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage must be provided")

	err = b.StoreAPIKey(ctx, storage, "", apiKeyID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account ID must be provided")

	err = b.StoreAPIKey(ctx, storage, serviceAccountID, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key ID must be provided")

	// Test with nil parameters for GetAPIKey
	retrievedKeyID, err = b.GetAPIKey(nil, storage, serviceAccountID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ctx must be provided")
	assert.Empty(t, retrievedKeyID)

	retrievedKeyID, err = b.GetAPIKey(ctx, nil, serviceAccountID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage must be provided")
	assert.Empty(t, retrievedKeyID)

	retrievedKeyID, err = b.GetAPIKey(ctx, storage, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account ID must be provided")
	assert.Empty(t, retrievedKeyID)
}
