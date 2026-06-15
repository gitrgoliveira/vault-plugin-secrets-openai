// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

//------------------------------------------------------------------------------
// Core Rotation Implementation
//------------------------------------------------------------------------------

// rotateAdminAPIKey rotates the admin API key
func (b *backend) rotateAdminAPIKey(ctx context.Context, storage logical.Storage) (bool, error) {
	// Get the existing configuration
	config, err := getConfig(ctx, storage)
	if err != nil {
		return false, err
	}

	if config == nil || config.AdminAPIKey == "" {
		return false, nil
	}

	b.Logger().Info("Starting admin API key rotation")

	// Save the old admin key ID before rotation
	oldAdminKeyID := config.AdminAPIKeyID

	// Create a new client with the existing admin API key
	oldClient := NewClient(config.AdminAPIKey, b.Logger())
	oldClientConfig := &Config{
		AdminAPIKey:          config.AdminAPIKey,
		APIEndpoint:          config.APIEndpoint,
		OrganizationID:       config.OrganizationID,
		AllowPrivateEndpoint: config.AllowPrivateEndpoint,
	}

	if err := oldClient.SetConfig(oldClientConfig); err != nil {
		return false, fmt.Errorf("error configuring client with old key: %w", err)
	}

	// Create a new admin API key with retry logic
	var newAdminKey, newAdminKeyID string
	var createErr error

	// Try up to 3 times with exponential backoff
	for attempt := 1; attempt <= 3; attempt++ {
		// Use a random suffix for the key name so rotation timing is not
		// disclosed to anyone who can list admin API keys in the OpenAI console.
		keyNameSuffix, randErr := generateRandomString(8)
		if randErr != nil {
			keyNameSuffix = fmt.Sprintf("r%d", attempt) // safe fallback
		}
		b.Logger().Debug("Creating new admin API key", "attempt", attempt)
		newAdminKey, newAdminKeyID, createErr = oldClient.CreateAdminAPIKey(ctx, fmt.Sprintf("vault-admin-key-%s", keyNameSuffix))

		if createErr == nil && newAdminKey != "" && newAdminKeyID != "" {
			break
		}

		if attempt < 3 {
			backoffDuration := time.Duration(attempt*attempt) * time.Second
			b.Logger().Warn("Failed to create admin key, retrying",
				"attempt", attempt,
				"error", createErr,
				"retry_in", backoffDuration)
			time.Sleep(backoffDuration)
		}
	}

	// If all retries failed
	if createErr != nil {
		return false, fmt.Errorf("error creating new admin key after retries: %w", createErr)
	}

	if newAdminKey == "" {
		return false, fmt.Errorf("received empty admin key during rotation")
	}

	// Test the new key
	newClient := NewClient(newAdminKey, b.Logger())
	newClientConfig := &Config{
		AdminAPIKey:          newAdminKey,
		APIEndpoint:          config.APIEndpoint,
		OrganizationID:       config.OrganizationID,
		AllowPrivateEndpoint: config.AllowPrivateEndpoint,
	}

	if err := newClient.SetConfig(newClientConfig); err != nil {
		return false, fmt.Errorf("error configuring client with new key: %w", err)
	}

	// Test with the new key
	b.Logger().Debug("Testing new admin API key")
	if err := newClient.TestConnection(ctx); err != nil {
		return false, fmt.Errorf("new admin key failed validation: %w", err)
	}

	// Update the configuration with the new key and new key ID
	b.Logger().Info("New admin API key validated, updating configuration")
	config.AdminAPIKey = newAdminKey
	config.AdminAPIKeyID = newAdminKeyID
	config.LastRotatedTime = time.Now()

	// Save the updated configuration
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return false, err
	}

	if err := storage.Put(ctx, entry); err != nil {
		return false, err
	}

	// Update the current client under the write lock so concurrent requests
	// always see a consistent client reference.
	b.Lock()
	b.client = newClient
	b.Unlock()

	// Revoke the previous key now that the new one is confirmed and persisted.
	// If revocation fails, the new key is already in storage, so record the
	// stale key ID under a dedicated storage key. This lets an operator find
	// and manually revoke it, and prevents the next rotation from treating the
	// new key ID as the one to revoke.
	if oldAdminKeyID != "" {
		b.Logger().Debug("Cleaning up previous admin API key")
		if err := newClient.RevokeAdminAPIKey(ctx, oldAdminKeyID); err != nil {
			b.Logger().Error("Failed to revoke previous admin key - the key may still be active in OpenAI",
				"old_key_id", oldAdminKeyID, "error", err)
			if putErr := storage.Put(ctx, &logical.StorageEntry{
				Key:   "rotation/pending_revocation",
				Value: []byte(oldAdminKeyID),
			}); putErr != nil {
				b.Logger().Error("Failed to record stale admin key for manual cleanup",
					"old_key_id", oldAdminKeyID, "error", putErr)
			}
			return false, err
		}
	} else {
		b.Logger().Warn("No previous admin key ID found, skipping revocation")
	}

	b.Logger().Info("Admin API key rotation completed successfully")

	return true, nil
}
