// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

const (
	// adminKeyRotationPath is where we store the admin key rotation queue
	// This is currently unused but kept for future implementation
	// nolint:unused
	adminKeyRotationPath = "admin-key-rotation"
)

// pathConfigRotate handles rotation of the admin API key
func (b *backend) pathConfigRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Manual rotation of admin API key triggered")

	rotated, err := b.rotateAdminAPIKey(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to rotate admin API key: %s", err), nil
	}

	if !rotated {
		return logical.ErrorResponse("failed to rotate admin API key: no API key configured"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"success":      true,
			"rotated_time": time.Now().Format(time.RFC3339),
		},
	}, nil
}

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

	// Create a new client with the existing admin API key
	oldClient := NewClient(config.AdminAPIKey, b.Logger())
	oldClientConfig := &Config{
		AdminAPIKey:    config.AdminAPIKey,
		APIEndpoint:    config.APIEndpoint,
		OrganizationID: config.OrganizationID,
	}

	if err := oldClient.SetConfig(oldClientConfig); err != nil {
		return false, fmt.Errorf("error configuring client with old key: %w", err)
	}

	// Create a new admin API key with retry logic
	var newAdminKey string
	var createErr error

	// Try up to 3 times with exponential backoff
	for attempt := 1; attempt <= 3; attempt++ {
		b.Logger().Debug("Creating new admin API key", "attempt", attempt)
		newAdminKey, createErr = oldClient.CreateAdminAPIKey(ctx, fmt.Sprintf("vault-rotated-admin-key-%d", time.Now().Unix()))

		if createErr == nil && newAdminKey != "" {
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
		AdminAPIKey:    newAdminKey,
		APIEndpoint:    config.APIEndpoint,
		OrganizationID: config.OrganizationID,
	}

	if err := newClient.SetConfig(newClientConfig); err != nil {
		return false, fmt.Errorf("error configuring client with new key: %w", err)
	}

	// Test with the new key
	b.Logger().Debug("Testing new admin API key")
	if err := newClient.TestConnection(ctx); err != nil {
		return false, fmt.Errorf("new admin key failed validation: %w", err)
	}

	// Update the configuration with the new key
	b.Logger().Info("New admin API key validated, updating configuration")
	config.AdminAPIKey = newAdminKey
	config.LastRotatedTime = time.Now()

	// Save the updated configuration
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return false, err
	}

	if err := storage.Put(ctx, entry); err != nil {
		return false, err
	}

	// Update the current client
	b.client = newClient

	// Clean up the old key using the new client
	b.Logger().Debug("Cleaning up old admin API key")
	if err := newClient.RevokeAdminAPIKey(ctx, oldClientConfig.AdminAPIKey); err != nil {
		b.Logger().Warn("Failed to revoke old admin key", "error", err)
		// We don't return an error here as the rotation was successful
	}

	b.Logger().Info("Admin API key rotation completed successfully")

	return true, nil
}

// scheduleAdminKeyRotation adds the admin key to the rotation queue
func (b *backend) scheduleAdminKeyRotation(ctx context.Context, storage logical.Storage) error {
	// Get the configuration
	config, err := getConfig(ctx, storage)
	if err != nil {
		return err
	}

	if config == nil {
		return fmt.Errorf("no configuration found")
	}

	// Check if rotation should be scheduled using the automated rotation params
	if config.DisableAutomatedRotation {
		b.Logger().Debug("Admin key rotation is explicitly disabled, not scheduling")
		return nil
	}

	// Determine rotation period - use AutomatedRotationParams if configured, or fall back to legacy
	var rotationPeriod time.Duration

	// Get rotation period from automated rotation params
	if config.AutomatedRotationParams.RotationPeriod > 0 {
		// Use automated rotation period if set
		rotationPeriod = config.AutomatedRotationParams.RotationPeriod
		b.Logger().Info("Using automated rotation period",
			"period", rotationPeriod)
	} else if config.RotationDuration > 0 {
		// Fall back to legacy rotation duration
		rotationPeriod = config.RotationDuration
		b.Logger().Info("Using legacy rotation period",
			"period", config.RotationPeriod)
	} else {
		// No rotation period defined
		b.Logger().Debug("Admin key rotation is disabled (no period), not scheduling")
		return nil
	}

	// If no admin API key is configured, don't schedule
	if config.AdminAPIKey == "" {
		b.Logger().Debug("No admin API key configured, not scheduling rotation")
		return nil
	}

	// Calculate next rotation time
	nextRotation := config.LastRotatedTime.Add(rotationPeriod)

	// If the next rotation is in the past, schedule it for now plus a small delay
	if nextRotation.Before(time.Now()) {
		b.Logger().Info("Next rotation time is in the past, scheduling immediate rotation")
		nextRotation = time.Now().Add(10 * time.Second) // Small delay to allow system to initialize
	}

	b.Logger().Info("Scheduling admin key rotation",
		"last_rotated", config.LastRotatedTime.Format(time.RFC3339),
		"rotation_period", rotationPeriod,
		"next_rotation", nextRotation.Format(time.RFC3339))

	// Create an item for the queue
	item := &queue.Item{
		Key:      "admin_api_key",
		Value:    nextRotation.Format(time.RFC3339),
		Priority: nextRotation.Unix(),
	}

	// Add to rotation queue
	return b.addToKeyRotationQueue(item)
}

// addToKeyRotationQueue adds an item to the rotation queue
func (b *backend) addToKeyRotationQueue(item *queue.Item) error {
	// Just push; Push will update if the item exists
	if err := b.credRotationQueue.Push(item); err != nil {
		return fmt.Errorf("failed to add to rotation queue: %w", err)
	}
	return nil
}

// adminKeyRotationHandler is the rotation handler for the admin API key (for automatedrotationutil)
// This is reserved for future use with the automated rotation framework
// nolint:unused
func (b *backend) adminKeyRotationHandler(ctx context.Context, req *logical.Request) error {
	b.Logger().Info("Automated admin API key rotation triggered by rotation framework")
	rotated, err := b.rotateAdminAPIKey(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("failed to rotate admin API key: %w", err)
	}
	if !rotated {
		return fmt.Errorf("admin API key rotation did not complete (no key configured)")
	}
	return nil
}

// checkAdminKeyRotation verifies if the admin key needs immediate rotation
func (b *backend) checkAdminKeyRotation(ctx context.Context, storage logical.Storage) error {
	// Get the configuration
	config, err := getConfig(ctx, storage)
	if err != nil {
		return err
	}

	if config == nil || config.AdminAPIKey == "" {
		// No config or no admin key
		return nil
	}

	// Check if rotation is disabled
	if config.DisableAutomatedRotation {
		return nil
	}

	// Determine the rotation period to use
	var rotationPeriod time.Duration

	// First try to use the automated rotation parameters
	if config.AutomatedRotationParams.RotationPeriod > 0 {
		rotationPeriod = config.AutomatedRotationParams.RotationPeriod
	} else if config.RotationDuration > 0 {
		// Fall back to legacy rotation duration
		rotationPeriod = config.RotationDuration
	} else {
		// No rotation period defined
		return nil
	}

	// Calculate when the next rotation should happen
	nextRotationTime := config.LastRotatedTime.Add(rotationPeriod)

	// If the next rotation time is in the past, rotate immediately
	if time.Now().After(nextRotationTime) {
		b.Logger().Warn("Admin API key is past its rotation time, rotating immediately",
			"last_rotated", config.LastRotatedTime.Format(time.RFC3339),
			"next_scheduled", nextRotationTime.Format(time.RFC3339))

		rotated, err := b.rotateAdminAPIKey(ctx, storage)
		if err != nil {
			return fmt.Errorf("failed to rotate overdue admin key: %w", err)
		}

		if !rotated {
			return fmt.Errorf("admin API key rotation failed")
		}

		b.Logger().Info("Successfully rotated overdue admin API key")
	}

	return nil
}
