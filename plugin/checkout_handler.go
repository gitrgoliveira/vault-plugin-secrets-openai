// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	checkoutStoragePrefix = "checkout/"
	apiKeyStoragePrefix   = "apikey/"
)

var (
	// errCheckedOut is returned when a check-out request is received
	// for a service account that's already checked out.
	errCheckedOut = errors.New("checked out")

	// errNotFound is used when a requested item doesn't exist.
	errNotFound = errors.New("not found")
)

// CheckOut provides information for a service account that is currently
// checked out.
type CheckOut struct {
	IsAvailable         bool      `json:"is_available"`
	BorrowerEntityID    string    `json:"borrower_entity_id"`
	BorrowerClientToken string    `json:"borrower_client_token"`
	CheckOutTime        time.Time `json:"check_out_time"`
}

// CheckOut attempts to check out a service account. If the account is unavailable, it returns
// errCheckedOut. If the service account isn't managed by this plugin, it returns
// errNotFound.
func (b *backend) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountID string, checkOut *CheckOut) error {
	if ctx == nil {
		return errors.New("context must be provided")
	}
	if storage == nil {
		return errors.New("storage must be provided")
	}
	if serviceAccountID == "" {
		return errors.New("service account ID must be provided")
	}
	if checkOut == nil {
		return errors.New("check-out must be provided")
	}

	// Check if the service account is currently checked out.
	currentEntry, err := storage.Get(ctx, checkoutStoragePrefix+serviceAccountID)
	if err != nil {
		return err
	}
	if currentEntry == nil {
		return errNotFound
	}
	currentCheckOut := &CheckOut{}
	if err := currentEntry.DecodeJSON(currentCheckOut); err != nil {
		return err
	}
	if !currentCheckOut.IsAvailable {
		return errCheckedOut
	}

	// Update the checkout time when checking out
	checkOut.CheckOutTime = time.Now()

	// Store the new check-out.
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+serviceAccountID, checkOut)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// CheckIn attempts to check in a service account. If an error occurs, the account remains checked out
// and can either be retried by the caller, or eventually may be checked in if it has a ttl
// that ends.
func (b *backend) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountID string, projectID string) error {
	if ctx == nil {
		return errors.New("ctx must be provided")
	}
	if storage == nil {
		return errors.New("storage must be provided")
	}
	if serviceAccountID == "" {
		return errors.New("service account ID must be provided")
	}
	if projectID == "" {
		return errors.New("project ID must be provided")
	}

	// On check-ins, we should delete the current API key and generate a new one
	// to ensure that the previous user can no longer access the service account
	// First, get the API key ID associated with this service account
	apiKeyEntry, err := storage.Get(ctx, apiKeyStoragePrefix+serviceAccountID)
	if err != nil {
		return err
	}

	// If there's an existing API key, delete it
	if apiKeyEntry != nil {
		var apiKeyID string
		if err := apiKeyEntry.DecodeJSON(&apiKeyID); err != nil {
			return err
		}

		// Initialize the client if it hasn't been
		if b.client == nil {
			config, err := getConfig(ctx, storage)
			if err != nil {
				return err
			}
			if config == nil {
				return errors.New("OpenAI is not configured")
			}
			b.client = NewClient(config.AdminAPIKey, b.Logger())
		}

		// Delete the existing API key
		if err := b.client.DeleteAPIKey(ctx, apiKeyID); err != nil {
			// Log but don't fail - the API key will expire eventually
			b.Logger().Warn("Failed to delete API key during check-in",
				"api_key_id", apiKeyID,
				"error", err)
			b.emitAPIErrorMetric("DeleteAPIKey", "check_in_error")
		}

		// Remove the API key entry from storage
		if err := storage.Delete(ctx, apiKeyStoragePrefix+serviceAccountID); err != nil {
			b.Logger().Warn("Failed to delete API key mapping during check-in",
				"service_account_id", serviceAccountID,
				"error", err)
		}
	}

	// Store a check-out status indicating it's available.
	checkOut := &CheckOut{
		IsAvailable: true,
	}
	entry, err := logical.StorageEntryJSON(checkoutStoragePrefix+serviceAccountID, checkOut)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// LoadCheckOut returns either:
//   - A *CheckOut and nil error if the serviceAccountID is currently managed by this engine.
//   - A nil *Checkout and errNotFound if the serviceAccountID is not currently managed by this engine.
func (b *backend) LoadCheckOut(ctx context.Context, storage logical.Storage, serviceAccountID string) (*CheckOut, error) {
	if ctx == nil {
		return nil, errors.New("ctx must be provided")
	}
	if storage == nil {
		return nil, errors.New("storage must be provided")
	}
	if serviceAccountID == "" {
		return nil, errors.New("service account ID must be provided")
	}

	entry, err := storage.Get(ctx, checkoutStoragePrefix+serviceAccountID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errNotFound
	}
	checkOut := &CheckOut{}
	if err := entry.DecodeJSON(checkOut); err != nil {
		return nil, err
	}
	return checkOut, nil
}

// DeleteCheckout cleans up anything we were tracking from the service account that
// we will no longer need.
func (b *backend) DeleteCheckout(ctx context.Context, storage logical.Storage, serviceAccountID string) error {
	if ctx == nil {
		return errors.New("ctx must be provided")
	}
	if storage == nil {
		return errors.New("storage must be provided")
	}
	if serviceAccountID == "" {
		return errors.New("service account ID must be provided")
	}

	// Delete any API key mappings
	if err := storage.Delete(ctx, apiKeyStoragePrefix+serviceAccountID); err != nil {
		return err
	}

	// Delete the checkout entry
	if err := storage.Delete(ctx, checkoutStoragePrefix+serviceAccountID); err != nil {
		return err
	}

	return nil
}

// StoreAPIKey stores the mapping between a service account and its current API key
func (b *backend) StoreAPIKey(ctx context.Context, storage logical.Storage, serviceAccountID, apiKeyID string) error {
	if ctx == nil {
		return errors.New("ctx must be provided")
	}
	if storage == nil {
		return errors.New("storage must be provided")
	}
	if serviceAccountID == "" {
		return errors.New("service account ID must be provided")
	}
	if apiKeyID == "" {
		return errors.New("API key ID must be provided")
	}

	entry, err := logical.StorageEntryJSON(apiKeyStoragePrefix+serviceAccountID, apiKeyID)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// GetAPIKey retrieves the current API key ID for a service account
func (b *backend) GetAPIKey(ctx context.Context, storage logical.Storage, serviceAccountID string) (string, error) {
	if ctx == nil {
		return "", errors.New("ctx must be provided")
	}
	if storage == nil {
		return "", errors.New("storage must be provided")
	}
	if serviceAccountID == "" {
		return "", errors.New("service account ID must be provided")
	}

	entry, err := storage.Get(ctx, apiKeyStoragePrefix+serviceAccountID)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", errNotFound
	}

	var apiKeyID string
	if err := entry.DecodeJSON(&apiKeyID); err != nil {
		return "", err
	}
	return apiKeyID, nil
}

// checkinAuthorized determines whether the requester is authorized to check in a service account
func checkinAuthorized(req *logical.Request, checkOut *CheckOut) bool {
	if checkOut.BorrowerEntityID != "" && req.EntityID != "" {
		if checkOut.BorrowerEntityID == req.EntityID {
			return true
		}
	}
	if checkOut.BorrowerClientToken != "" && req.ClientToken != "" {
		if checkOut.BorrowerClientToken == req.ClientToken {
			return true
		}
	}
	return false
}
