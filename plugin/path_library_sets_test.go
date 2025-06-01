package openaisecrets

// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLibrarySet_Validate(t *testing.T) {
	// Test valid set
	set := &librarySet{
		ServiceAccountIDs: []string{"svc1"},
		ProjectID:         "project1",
		TTL:               1 * time.Hour,
		MaxTTL:            24 * time.Hour,
	}
	assert.NoError(t, set.Validate())

	// Test empty service accounts
	set = &librarySet{
		ServiceAccountIDs: []string{},
		ProjectID:         "project1",
		TTL:               1 * time.Hour,
		MaxTTL:            24 * time.Hour,
	}
	assert.Error(t, set.Validate())
	assert.Contains(t, set.Validate().Error(), "at least one service account ID must be provided")

	// Test empty project ID
	set = &librarySet{
		ServiceAccountIDs: []string{"svc1"},
		ProjectID:         "",
		TTL:               1 * time.Hour,
		MaxTTL:            24 * time.Hour,
	}
	assert.Error(t, set.Validate())
	assert.Contains(t, set.Validate().Error(), "project_id is required")

	// Test TTL > MaxTTL
	set = &librarySet{
		ServiceAccountIDs: []string{"svc1"},
		ProjectID:         "project1",
		TTL:               48 * time.Hour,
		MaxTTL:            24 * time.Hour,
	}
	assert.Error(t, set.Validate())
	assert.Contains(t, set.Validate().Error(), "ttl cannot be greater than max_ttl")
}

func TestSetStorageFunctions(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	// Test saving and reading a set
	set := &librarySet{
		ServiceAccountIDs:         []string{"svc1", "svc2"},
		ProjectID:                 "project1",
		TTL:                       1 * time.Hour,
		MaxTTL:                    24 * time.Hour,
		DisableCheckInEnforcement: true,
	}

	err := saveSet(ctx, storage, "testset", set)
	require.NoError(t, err)

	retrieved, err := readSet(ctx, storage, "testset")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, set.ServiceAccountIDs, retrieved.ServiceAccountIDs)
	assert.Equal(t, set.ProjectID, retrieved.ProjectID)
	assert.Equal(t, set.TTL, retrieved.TTL)
	assert.Equal(t, set.MaxTTL, retrieved.MaxTTL)
	assert.Equal(t, set.DisableCheckInEnforcement, retrieved.DisableCheckInEnforcement)

	// Test listing sets
	sets, err := listSets(ctx, storage)
	require.NoError(t, err)
	require.Len(t, sets, 1)
	assert.Equal(t, "testset", sets[0])

	// Test reading a non-existent set
	nonExistent, err := readSet(ctx, storage, "nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, nonExistent)

	// Test deleting a set
	err = deleteSet(ctx, storage, "testset")
	require.NoError(t, err)

	deleted, err := readSet(ctx, storage, "testset")
	assert.NoError(t, err)
	assert.Nil(t, deleted)

	// Test empty set name
	err = saveSet(ctx, storage, "", set)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "set name is required")

	_, err = readSet(ctx, storage, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "set name is required")

	err = deleteSet(ctx, storage, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "set name is required")
}

func TestLibrarySetOperations(t *testing.T) {
	b, storage := getTestBackendAndStorage(t)
	ctx := context.Background()

	// Set up config
	config := &openaiConfig{
		AdminAPIKey: "test-admin-key",
	}
	configEntry, err := logical.StorageEntryJSON(configPath, config)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, configEntry))

	// Test create operation
	createData := map[string]interface{}{
		"name":                         "testset",
		"service_account_ids":          []string{"svc1", "svc2"},
		"project_id":                   "project1",
		"ttl":                          3600,  // 1 hour
		"max_ttl":                      86400, // 24 hours
		"disable_check_in_enforcement": true,
	}
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "library/testset",
		Data:      createData,
		Storage:   storage,
	}

	// The mock client should return service accounts
	mc := &mockClient{}
	b.client = mc
	mc.getServiceAccountFn = func(ctx context.Context, id string, projectID string) (*ServiceAccount, error) {
		return &ServiceAccount{
			ID:   id,
			Name: "Test Service Account",
		}, nil
	}

	// Create the set
	resp, err := b.operationSetCreate(ctx, createReq, getFieldData(t, b.pathSets()[0].Fields, createReq))
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Test read operation
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "library/testset",
		Storage:   storage,
	}
	resp, err = b.operationSetRead(ctx, readReq, getFieldData(t, b.pathSets()[0].Fields, readReq))
	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.Equal(t, []string{"svc1", "svc2"}, resp.Data["service_account_ids"])
		assert.Equal(t, "project1", resp.Data["project_id"])
		assert.Equal(t, int64(3600), resp.Data["ttl"])
		assert.Equal(t, int64(86400), resp.Data["max_ttl"])
		assert.Equal(t, true, resp.Data["disable_check_in_enforcement"])
	}

	// Test update operation
	updateData := map[string]interface{}{
		"name":                         "testset",
		"service_account_ids":          []string{"svc1", "svc3"}, // Changed svc2 to svc3
		"project_id":                   "project2",               // Changed project
		"ttl":                          7200,                     // 2 hours
		"max_ttl":                      172800,                   // 48 hours
		"disable_check_in_enforcement": false,
	}
	updateReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "library/testset",
		Data:      updateData,
		Storage:   storage,
	}
	resp, err = b.operationSetUpdate(ctx, updateReq, getFieldData(t, b.pathSets()[0].Fields, updateReq))
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Verify the update
	readResp, err := b.operationSetRead(ctx, readReq, getFieldData(t, b.pathSets()[0].Fields, readReq))
	assert.NoError(t, err)
	if assert.NotNil(t, readResp) {
		assert.Equal(t, []string{"svc1", "svc3"}, readResp.Data["service_account_ids"])
		assert.Equal(t, "project2", readResp.Data["project_id"])
		assert.Equal(t, int64(7200), readResp.Data["ttl"])
		assert.Equal(t, int64(172800), readResp.Data["max_ttl"])
		assert.Equal(t, false, readResp.Data["disable_check_in_enforcement"])
	}

	// Test list operation
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "library",
		Storage:   storage,
	}
	resp, err = b.operationListSets(ctx, listReq, nil)
	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.Equal(t, []string{"testset"}, resp.Data["keys"])
	}

	// Test delete operation
	deleteReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "library/testset",
		Storage:   storage,
	}
	resp, err = b.operationSetDelete(ctx, deleteReq, getFieldData(t, b.pathSets()[0].Fields, deleteReq))
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Verify the set was deleted
	readResp, err = b.operationSetRead(ctx, readReq, getFieldData(t, b.pathSets()[0].Fields, readReq))
	assert.NoError(t, err)
	assert.Nil(t, readResp)

	// Test error on missing set name
	badReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "library/",
		Data:      map[string]interface{}{},
		Storage:   storage,
	}
	badResp, badErr := b.operationSetCreate(ctx, badReq, getFieldData(t, b.pathSets()[0].Fields, badReq))
	assert.NoError(t, badErr)
	if assert.NotNil(t, badResp) {
		assert.Contains(t, badResp.Data["error"], "set name is required")
	}
}

func getFieldData(t *testing.T, fields map[string]*framework.FieldSchema, req *logical.Request) *framework.FieldData {
	t.Helper()

	// Extract set name from path if present
	data := map[string]interface{}{}
	for k, v := range req.Data {
		data[k] = v
	}
	if fields["name"] != nil && data["name"] == nil {
		// Path is like "library/testset"; extract after last slash
		parts := strings.Split(req.Path, "/")
		if len(parts) > 1 && parts[1] != "" {
			data["name"] = parts[1]
		}
	}

	return &framework.FieldData{
		Raw:    data,
		Schema: fields,
	}
}
