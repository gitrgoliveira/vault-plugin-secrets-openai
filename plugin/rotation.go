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
	"github.com/hashicorp/vault/sdk/rotation"
)

const (
	// Constant for rotation job name in Vault's rotation framework
	rotationKeyName = "admin-key-rotation" // Used for job registration in Vault's rotation system
)

//------------------------------------------------------------------------------
// Rotation Initialization and Queue Management
//------------------------------------------------------------------------------

// initRotationQueue registers the admin key rotation job with Vault's rotation manager
func (b *backend) initRotationQueue(ctx context.Context, storage logical.Storage) {
	b.Lock()
	defer b.Unlock()

	if b.cancelQueue != nil {
		b.cancelQueue()
	}

	b.Logger().Info("Registering admin key rotation job with Vault's rotation manager")
	if err := b.setupAdminKeyRotation(ctx, storage); err != nil {
		b.Logger().Error("Failed to setup automated admin key rotation", "error", err)
	}
}

// setupAdminKeyRotation registers the admin key rotation job with the rotation manager
func (b *backend) setupAdminKeyRotation(ctx context.Context, storage logical.Storage) error {
	config, err := getConfig(ctx, storage)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	if config == nil || config.AdminAPIKey == "" {
		b.Logger().Debug("No admin API key configured, skipping rotation setup")
		return nil
	}

	if config.DisableAutomatedRotation {
		b.Logger().Info("Admin key automatic rotation is disabled")
		return nil
	}

	var configErr error

	// If rotation is enabled via automated rotation params (prefer scheduled rotation if set)
	if config.RotationSchedule != "" {
		b.Logger().Info("Setting up scheduled rotation for admin API key",
			"schedule", config.RotationSchedule)

		// Configure the rotation job with schedule
		rotationJobReq := &rotation.RotationJobConfigureRequest{
			Name:             rotationKeyName,
			MountPoint:       rotationPrefix,
			ReqPath:          "config/rotate", // Point to our consolidated rotation path
			RotationSchedule: config.RotationSchedule,
			RotationWindow:   config.RotationWindow,
		}

		// Use the SDK's default scheduler to validate the schedule
		_, err := rotation.DefaultScheduler.Parse(config.RotationSchedule)
		if err != nil {
			return fmt.Errorf("invalid rotation schedule: %w", err)
		}

		_, configErr = rotation.ConfigureRotationJob(rotationJobReq)
	} else if config.AutomatedRotationParams.RotationPeriod > 0 {
		b.Logger().Info("Setting up periodic rotation for admin API key",
			"period", config.AutomatedRotationParams.RotationPeriod)

		rotationJobReqPeriodic := &rotation.RotationJobConfigureRequest{
			Name:           rotationKeyName,
			MountPoint:     rotationPrefix,
			ReqPath:        "config/rotate", // Point to our consolidated rotation path
			RotationPeriod: config.AutomatedRotationParams.RotationPeriod,
		}

		_, configErr = rotation.ConfigureRotationJob(rotationJobReqPeriodic)
	} else {
		// No rotation configuration
		return nil
	}

	if configErr != nil {
		return fmt.Errorf("failed to configure rotation job: %w", configErr)
	}

	b.Logger().Info("Admin API key rotation configuration complete")
	return nil
}

// addToKeyRotationQueue adds an item to the rotation queue
func (b *backend) addToKeyRotationQueue(item *queue.Item) error {
	// Just push; Push will update if the item exists
	if err := b.credRotationQueue.Push(item); err != nil {
		return fmt.Errorf("failed to add to rotation queue: %w", err)
	}
	return nil
}

//------------------------------------------------------------------------------
// Manual Key Rotation
//------------------------------------------------------------------------------

// pathConfigRotate handles both manual and automated rotation of the admin API key
func (b *backend) pathConfigRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Rotation of admin API key triggered")

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

//------------------------------------------------------------------------------
// Automated Key Rotation
//------------------------------------------------------------------------------

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

	// Only use automated rotation params;
	rotationPeriod := config.AutomatedRotationParams.RotationPeriod
	if rotationPeriod <= 0 {
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

	rotationPeriod := config.AutomatedRotationParams.RotationPeriod
	if rotationPeriod <= 0 {
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
		AdminAPIKey:    config.AdminAPIKey,
		APIEndpoint:    config.APIEndpoint,
		OrganizationID: config.OrganizationID,
	}

	if err := oldClient.SetConfig(oldClientConfig); err != nil {
		return false, fmt.Errorf("error configuring client with old key: %w", err)
	}

	// Create a new admin API key with retry logic
	var newAdminKey, newAdminKeyID string
	var createErr error

	// Try up to 3 times with exponential backoff
	for attempt := 1; attempt <= 3; attempt++ {
		b.Logger().Debug("Creating new admin API key", "attempt", attempt)
		newAdminKey, newAdminKeyID, createErr = oldClient.CreateAdminAPIKey(ctx, fmt.Sprintf("vault-rotated-admin-key-%d", time.Now().Unix()))

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

	// Update the current client
	b.client = newClient

	// Clean up the old key using the new client and the old key ID
	if oldAdminKeyID != "" {
		b.Logger().Debug("Cleaning up old admin API key", "oldAdminKeyID", oldAdminKeyID)
		if err := newClient.RevokeAdminAPIKey(ctx, oldAdminKeyID); err != nil {
			b.Logger().Error("Failed to revoke old admin key", "error", err)
			return false, err
		}
	} else {
		b.Logger().Warn("No old admin key ID found, skipping revocation")
	}

	b.Logger().Info("Admin API key rotation completed successfully")

	return true, nil
}

//------------------------------------------------------------------------------
// API Path Registration
//------------------------------------------------------------------------------

// rotationPaths returns the list of paths for rotation
func (b *backend) rotationPaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/rotate/?$", // Single path for both manual and automated rotation
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigRotate, // Use the same handler for both types of rotation
					Summary:  "Rotate the admin API key",
				},
			},
			HelpSynopsis:    "Rotate the admin API key",
			HelpDescription: "Triggers rotation of the admin API key. Can be called manually or automatically by Vault's rotation system.",
		},
	}
}
