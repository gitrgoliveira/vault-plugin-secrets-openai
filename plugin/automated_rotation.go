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
		rotationJobReqPeriodic := &rotation.RotationJobConfigureRequest{
			Name:           adminKeyRotationName,
			MountPoint:     rotationPrefix,
			ReqPath:        configPath,
			RotationPeriod: rotationPeriod,
		}

		_, configErr = rotation.ConfigureRotationJob(rotationJobReqPeriodic)
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

	b.Logger().Info("Admin API key rotation configuration complete")
	return nil
}
