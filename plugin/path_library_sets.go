// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	libraryPrefix       = "library/"
	libraryManagePrefix = "library/manage/"
	setStoragePath      = "sets/"
)

// librarySet defines a set of service accounts that can be checked out
type librarySet struct {
	ServiceAccountIDs         []string      `json:"service_account_ids"` // IDs of service accounts in this set
	ProjectID                 string        `json:"project_id"`          // OpenAI Project ID associated with this set
	TTL                       time.Duration `json:"ttl"`                 // Default TTL for check-outs
	MaxTTL                    time.Duration `json:"max_ttl"`             // Maximum TTL for check-outs
	DisableCheckInEnforcement bool          `json:"disable_check_in_enforcement"`
}

// Validate ensures that a set meets our code assumptions that TTLs are set in
// a way that makes sense, and that there's at least one service account.
func (l *librarySet) Validate() error {
	if l.ProjectID == "" {
		return fmt.Errorf("project_id is required")
	}

	if len(l.ServiceAccountIDs) == 0 {
		return fmt.Errorf("at least one service account ID must be provided")
	}

	if l.TTL > l.MaxTTL {
		return fmt.Errorf("ttl cannot be greater than max_ttl")
	}

	return nil
}

// readSet reads a library set from storage
func readSet(ctx context.Context, s logical.Storage, name string) (*librarySet, error) {
	if name == "" {
		return nil, fmt.Errorf("set name is required")
	}

	entry, err := s.Get(ctx, setStoragePath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result librarySet
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// saveSet saves a library set to storage
func saveSet(ctx context.Context, s logical.Storage, name string, set *librarySet) error {
	if name == "" {
		return fmt.Errorf("set name is required")
	}

	entry, err := logical.StorageEntryJSON(setStoragePath+name, set)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

// deleteSet deletes a library set from storage
func deleteSet(ctx context.Context, s logical.Storage, name string) error {
	if name == "" {
		return fmt.Errorf("set name is required")
	}

	return s.Delete(ctx, setStoragePath+name)
}

// listSets lists all library sets from storage
func listSets(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, setStoragePath)
}

// pathListSets returns a framework path for listing sets
func (b *backend) pathListSets() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(libraryPrefix, "/") + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.operationListSets,
					Summary:  "List all the library sets.",
				},
			},
			HelpSynopsis:    "List all the library sets.",
			HelpDescription: "Returns the names of all library sets.",
		},
	}
}

// pathSets returns a framework path for managing library sets
func (b *backend) pathSets() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(libraryPrefix, "/") + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the set.",
					Required:    true,
				},
				"service_account_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "The service account IDs with which this set will be associated.",
				},
				"project_id": {
					Type:        framework.TypeString,
					Description: "OpenAI Project ID that these service accounts belong to.",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "In seconds, the amount of time a check-out should last. Defaults to 24 hours.",
					Default:     24 * 60 * 60, // 24 hours
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "In seconds, the max amount of time a check-out's renewals should last. Defaults to 24 hours.",
					Default:     24 * 60 * 60, // 24 hours
				},
				"disable_check_in_enforcement": {
					Type:        framework.TypeBool,
					Description: "Disable the default behavior of requiring that check-ins are performed by the entity that checked them out.",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.operationSetCreate,
					Summary:  "Create a library set.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.operationSetUpdate,
					Summary:  "Update a library set.",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.operationSetRead,
					Summary:  "Read a library set.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.operationSetDelete,
					Summary:  "Delete a library set.",
				},
			},
			ExistenceCheck:  existenceCheckForNamedPath("name", func(name string) string { return setStoragePath + name }),
			HelpSynopsis:    "Manage library sets.",
			HelpDescription: "Create, read, update, and delete library sets.",
		},
	}
}

// operationListSets lists all library sets
func (b *backend) operationListSets(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	sets, err := listSets(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(sets), nil
}

// operationSetCreate creates a new library set
func (b *backend) operationSetCreate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName, ok := fieldData.Get("name").(string)
	if !ok || setName == "" {
		return logical.ErrorResponse("set name is required"), nil
	}

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	// Check if set already exists
	existingSet, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if existingSet != nil {
		return logical.ErrorResponse("set %q already exists", setName), nil
	}

	// Get config to verify service accounts
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("OpenAI config must be set up before creating library sets"), nil
	}

	serviceAccountIDs := fieldData.Get("service_account_ids").([]string)
	projectID := fieldData.Get("project_id").(string)
	ttl := time.Duration(fieldData.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(fieldData.Get("max_ttl").(int)) * time.Second
	disableCheckInEnforcement := fieldData.Get("disable_check_in_enforcement").(bool)

	if len(serviceAccountIDs) == 0 {
		return logical.ErrorResponse("at least one service account ID must be provided"), nil
	}

	// Initialize the client if needed
	if b.client == nil {
		b.client = NewClient(config.AdminAPIKey, b.Logger())
		if err := b.client.SetConfig(&Config{
			AdminAPIKey:    config.AdminAPIKey,
			APIEndpoint:    config.APIEndpoint,
			OrganizationID: config.OrganizationID,
		}); err != nil {
			return nil, err
		}
	}

	// Verify that all service accounts exist in the specified project
	for _, id := range serviceAccountIDs {
		_, err := b.client.GetServiceAccount(ctx, id, projectID)
		if err != nil {
			return logical.ErrorResponse("service account %q not found in project %q: %s", id, projectID, err), nil
		}
	}

	// Create the set
	set := &librarySet{
		ServiceAccountIDs:         serviceAccountIDs,
		ProjectID:                 projectID,
		TTL:                       ttl,
		MaxTTL:                    maxTTL,
		DisableCheckInEnforcement: disableCheckInEnforcement,
	}

	if err := set.Validate(); err != nil {
		return logical.ErrorResponse("invalid set configuration: %s", err), nil
	}

	// Register service accounts as managed
	b.managedUserLock.Lock()
	defer b.managedUserLock.Unlock()

	for _, id := range serviceAccountIDs {
		b.managedUsers[id] = struct{}{}

		// Make sure all service accounts start in the "available" state
		checkOut := &CheckOut{
			IsAvailable: true,
		}
		entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+id, checkOut)
		if err != nil {
			return nil, err
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
	}

	// Save the set
	if err := saveSet(ctx, req.Storage, setName, set); err != nil {
		return nil, err
	}

	return nil, nil
}

// operationSetUpdate updates an existing library set
func (b *backend) operationSetUpdate(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	// Get the existing set
	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse("set %q does not exist", setName), nil
	}

	// Get config to verify service accounts
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("OpenAI config not found"), nil
	}

	// Initialize the client if needed
	if b.client == nil {
		b.client = NewClient(config.AdminAPIKey, b.Logger())
		if err := b.client.SetConfig(&Config{
			AdminAPIKey:    config.AdminAPIKey,
			APIEndpoint:    config.APIEndpoint,
			OrganizationID: config.OrganizationID,
		}); err != nil {
			return nil, err
		}
	}

	// Check for updated values
	serviceAccountIDsRaw, serviceAccountIDsSet := fieldData.GetOk("service_account_ids")
	projectIDRaw, projectIDSet := fieldData.GetOk("project_id")
	ttlRaw, ttlSet := fieldData.GetOk("ttl")
	maxTTLRaw, maxTTLSet := fieldData.GetOk("max_ttl")
	disableCheckInEnforcementRaw, disableCheckInEnforcementSet := fieldData.GetOk("disable_check_in_enforcement")

	// Track current service accounts to determine which ones are removed
	currentServiceAccountIDs := make(map[string]struct{})
	for _, id := range set.ServiceAccountIDs {
		currentServiceAccountIDs[id] = struct{}{}
	}

	// Update values if provided
	if projectIDSet {
		set.ProjectID = projectIDRaw.(string)
	}

	if ttlSet {
		set.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLSet {
		set.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if disableCheckInEnforcementSet {
		set.DisableCheckInEnforcement = disableCheckInEnforcementRaw.(bool)
	}

	if serviceAccountIDsSet {
		newServiceAccountIDs := serviceAccountIDsRaw.([]string)

		// Verify that all new service accounts exist
		for _, id := range newServiceAccountIDs {
			_, err := b.client.GetServiceAccount(ctx, id, set.ProjectID)
			if err != nil {
				return logical.ErrorResponse("service account %q not found in project %q: %s", id, set.ProjectID, err), nil
			}
		}

		// Track new service accounts
		newServiceAccountIDsMap := make(map[string]struct{})
		for _, id := range newServiceAccountIDs {
			newServiceAccountIDsMap[id] = struct{}{}
		}

		// Handle removed service accounts
		b.managedUserLock.Lock()
		for id := range currentServiceAccountIDs {
			if _, exists := newServiceAccountIDsMap[id]; !exists {
				// Service account was removed from set
				delete(b.managedUsers, id)

				// Delete checkout entry
				if err := b.DeleteCheckout(ctx, req.Storage, id); err != nil {
					b.Logger().Warn("failed to delete checkout entry for removed service account",
						"service_account_id", id, "error", err)
				}
			}
		}

		// Handle added service accounts
		for id := range newServiceAccountIDsMap {
			if _, exists := currentServiceAccountIDs[id]; !exists {
				// Service account was added to set
				b.managedUsers[id] = struct{}{}

				// Create checkout entry
				checkOut := &CheckOut{
					IsAvailable: true,
				}
				entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+id, checkOut)
				if err != nil {
					b.managedUserLock.Unlock()
					return nil, err
				}
				if err := req.Storage.Put(ctx, entry); err != nil {
					b.managedUserLock.Unlock()
					return nil, err
				}
			}
		}
		b.managedUserLock.Unlock()

		// Update the service account IDs
		set.ServiceAccountIDs = newServiceAccountIDs
	}

	// Validate the updated set
	if err := set.Validate(); err != nil {
		return logical.ErrorResponse("invalid set configuration: %s", err), nil
	}

	// Save the updated set
	if err := saveSet(ctx, req.Storage, setName, set); err != nil {
		return nil, err
	}

	return nil, nil
}

// operationSetRead reads a library set
func (b *backend) operationSetRead(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName, ok := fieldData.Get("name").(string)
	if !ok || setName == "" {
		return logical.ErrorResponse("set name is required"), nil
	}

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.RLock()
	defer lock.RUnlock()

	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_account_ids":          set.ServiceAccountIDs,
			"project_id":                   set.ProjectID,
			"ttl":                          int64(set.TTL.Seconds()),
			"max_ttl":                      int64(set.MaxTTL.Seconds()),
			"disable_check_in_enforcement": set.DisableCheckInEnforcement,
		},
	}, nil
}

// operationSetDelete deletes a library set
func (b *backend) operationSetDelete(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName, ok := fieldData.Get("name").(string)
	if !ok || setName == "" {
		return logical.ErrorResponse("set name is required"), nil
	}

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	// Get the set to remove service accounts from managed list
	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return nil, nil
	}

	// Register service accounts as managed
	b.managedUserLock.Lock()
	defer b.managedUserLock.Unlock()

	for _, id := range set.ServiceAccountIDs {
		delete(b.managedUsers, id)

		// Delete checkout entry
		if err := b.DeleteCheckout(ctx, req.Storage, id); err != nil {
			b.Logger().Warn("failed to delete checkout entry for removed service account",
				"service_account_id", id, "error", err)
		}
	}

	// Delete the set
	if err := deleteSet(ctx, req.Storage, setName); err != nil {
		return nil, err
	}

	return nil, nil
}
