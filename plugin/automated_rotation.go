// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
)

const (
	// adminKeyRotationName is the name used to register the admin key rotation job
	adminKeyRotationName = "admin-key-rotation"
)

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
			Name:             adminKeyRotationName,
			MountPoint:       rotationPrefix,
			ReqPath:          configPath,
			RotationSchedule: config.RotationSchedule,
			RotationWindow:   config.RotationWindow,
		}

		// Use the SDK's default scheduler to validate the schedule
		_, err := rotation.DefaultScheduler.Parse(config.RotationSchedule)
		if err != nil {
			return fmt.Errorf("invalid rotation schedule: %w", err)
		}

		_, configErr = rotation.ConfigureRotationJob(rotationJobReq)
	} else if config.RotationPeriod != "" && config.RotationPeriod != "0" {
		b.Logger().Info("Setting up periodic rotation for admin API key",
			"period", config.RotationPeriod)

		rotationPeriod, err := time.ParseDuration(config.RotationPeriod)
		if err != nil {
			return fmt.Errorf("invalid rotation period: %w", err)
		}

		// Configure the rotation job with period
		rotationJobReq := &rotation.RotationJobConfigureRequest{
			Name:           adminKeyRotationName,
			MountPoint:     rotationPrefix,
			ReqPath:        configPath,
			RotationPeriod: rotationPeriod,
		}

		_, configErr = rotation.ConfigureRotationJob(rotationJobReq)
	} else {
		// For legacy rotation, use the queue-based approach
		if config.RotationDuration > 0 {
			b.Logger().Info("Using legacy queue-based rotation for admin API key",
				"period", config.RotationPeriod)
			return b.scheduleAdminKeyRotation(ctx, storage)
		}

		return nil // No rotation configuration
	}

	if configErr != nil {
		return fmt.Errorf("failed to configure rotation job: %w", configErr)
	}

	// Register the rotation job with the rotation manager (not available in this SDK version)
	b.Logger().Warn("Automated rotation registration is not available in this Vault SDK version; falling back to legacy rotation if enabled.")
	if config.RotationDuration > 0 {
		return b.scheduleAdminKeyRotation(ctx, storage)
	}
	return nil
}

// handleRotation is the rotation handler called by the rotation manager
// This is reserved for future use with the automated rotation framework
func (b *backend) handleRotation(ctx context.Context, req *logical.Request) error {
	b.Logger().Info("Automated admin API key rotation triggered by rotation manager")

	rotated, err := b.rotateAdminAPIKey(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("failed to rotate admin API key: %w", err)
	}

	if !rotated {
		return fmt.Errorf("admin API key rotation did not complete (no key configured)")
	}

	// Update the next rotation time in the configuration
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("failed to get config after rotation: %w", err)
	}

	// Update LastRotatedTime to now
	config.LastRotatedTime = time.Now()

	// Save the updated configuration
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return fmt.Errorf("failed to encode config after rotation: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to save config after rotation: %w", err)
	}

	b.Logger().Info("Admin API key rotation completed successfully")
	return nil
}
