// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

const (
	// rotationCheckInterval is the interval at which we check for credentials needing rotation
	rotationCheckInterval = 10 * time.Minute

	// clockSkew is the time to subtract from the next rotation time to ensure
	// we have enough time to process the rotation before the actual deadline
	clockSkew = 30 * time.Second
)

// initRotationQueue initializes the credential rotation queue for static roles
func (b *backend) initRotationQueue(ctx context.Context, storage logical.Storage) {
	b.Lock()
	defer b.Unlock()

	// Cancel any existing queue rotation goroutines
	if b.cancelQueue != nil {
		b.cancelQueue()
	}

	// Initialize a new priority queue
	b.credRotationQueue = queue.New()

	// Create a new context for rotation operations
	rotationCtx, rotationCancel := context.WithCancel(context.Background())
	b.cancelQueue = rotationCancel

	b.Logger().Info("Starting static credential rotation scheduler")

	// Start a goroutine that will check for credentials to rotate
	go b.rotateCredentials(rotationCtx)

	// Load all static roles and add them to the rotation queue
	if err := b.loadRotationQueue(ctx, storage); err != nil {
		b.Logger().Error("Failed to load rotation queue", "error", err)
	}
}

// loadRotationQueue loads all static roles and adds them to the rotation queue
func (b *backend) loadRotationQueue(ctx context.Context, storage logical.Storage) error {
	entries, err := storage.List(ctx, staticRolePath+"/")
	if err != nil {
		b.Logger().Error("Failed to list static roles", "error", err)
		return err
	}

	for _, name := range entries {
		b.Logger().Debug("Loading static role into rotation queue", "role", name)
		role, err := b.getStaticRole(ctx, storage, name)
		if err != nil {
			b.Logger().Error("Failed to load static role", "role", name, "error", err)
			continue
		}

		// Skip roles that don't have rotation enabled
		if role.RotationPeriod <= 0 {
			b.Logger().Debug("Skipping role with no rotation", "role", name)
			continue
		}

		// Add to the rotation queue with appropriate priority
		if err := b.queueRotation(name, role.LastRotatedTime, role.RotationPeriod); err != nil {
			b.Logger().Error("Failed to queue rotation for role", "role", name, "error", err)
			continue
		}
	}

	return nil
}

// queueRotation adds a role to the rotation queue with appropriate priority
func (b *backend) queueRotation(roleName string, lastRotated time.Time, rotationPeriod time.Duration) error {
	// Calculate the next rotation time
	nextRotation := lastRotated.Add(rotationPeriod)

	// Subtract clock skew to ensure we rotate before the deadline
	nextRotation = nextRotation.Add(-clockSkew)

	// Immediate rotation if already past the rotation time
	if nextRotation.Before(time.Now()) {
		nextRotation = time.Now()
	}

	// Calculate priority (use timestamp for queue priority)
	item := &queue.Item{
		Key:      roleName,
		Value:    nextRotation.Format(time.RFC3339),
		Priority: nextRotation.Unix(),
	}

	// Just push; Push will update if the item exists
	if err := b.credRotationQueue.Push(item); err != nil {
		return fmt.Errorf("failed to add to rotation queue: %w", err)
	}

	return nil
}

// rotateCredentials is a long-running goroutine that checks for credentials that need rotation
func (b *backend) rotateCredentials(ctx context.Context) {
	ticker := time.NewTicker(rotationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Logger().Info("Stopping credential rotation scheduler")
			return
		case <-ticker.C:
			// Check for credentials to rotate
			b.processRotations(ctx)
		}
	}
}

// processRotations checks the queue and rotates any credentials that need rotation
func (b *backend) processRotations(ctx context.Context) {
	// Get a snapshot of current time to ensure consistent comparisons
	now := time.Now()

	for b.credRotationQueue.Len() > 0 {
		// Pop the item from the queue
		item, err := b.credRotationQueue.Pop()
		if err != nil {
			b.Logger().Error("Failed to pop from rotation queue", "error", err)
			return
		}

		if item.Priority > now.Unix() {
			// Not ready yet, requeue and break
			_ = b.credRotationQueue.Push(item)
			return
		}

		// Special case for admin API key rotation
		if item.Key == "admin_api_key" {
			b.Logger().Info("Rotating admin API key due to scheduled rotation")

			// Process admin key rotation in a separate goroutine
			go func() {
				rotated, err := b.rotateAdminAPIKey(ctx, b.storageView)
				if err != nil {
					b.Logger().Error("Failed to rotate admin API key", "error", err)

					// Re-queue for retry with short delay
					retryTime := time.Now().Add(30 * time.Second)
					newItem := &queue.Item{
						Key:      "admin_api_key",
						Value:    retryTime.Format(time.RFC3339),
						Priority: retryTime.Unix(),
					}
					_ = b.addToKeyRotationQueue(newItem)
					return
				}

				if rotated {
					b.Logger().Info("Admin API key rotated successfully")
					// Reschedule next rotation
					_ = b.scheduleAdminKeyRotation(ctx, b.storageView)
				} else {
					b.Logger().Warn("Admin API key rotation was not performed (no API key configured)")
				}
			}()
		} else {
			// Normal case for static role rotation
			roleName := item.Key
			b.Logger().Info("Rotating credentials for static role", "role", roleName)

			// Process the rotation in a separate goroutine to avoid blocking
			go b.rotateRole(ctx, roleName)
		}
	}
}

// rotateRole rotates credentials for a specific role
func (b *backend) rotateRole(ctx context.Context, roleName string) {
	// Acquire a lock on the role to prevent concurrent modifications
	lock := locksutil.LockForKey(b.roleLocks, roleName)
	lock.Lock()
	defer lock.Unlock()

	// Load the current role
	role, err := b.getStaticRole(ctx, b.storageView, roleName)
	if err != nil {
		b.Logger().Error("Failed to load static role", "role", roleName, "error", err)
		return
	}

	// Role might have been deleted or rotation disabled
	if role == nil || role.RotationPeriod <= 0 {
		b.Logger().Info("Role deleted or rotation disabled", "role", roleName)
		return
	}

	// Check if client is available
	if b.client == nil {
		b.Logger().Error("OpenAI client not configured, skipping rotation", "role", roleName)
		return
	}

	// Create a new service account and API key for rotation
	svcAccount, apiKey, err := b.client.CreateServiceAccount(ctx, role.ProjectID, CreateServiceAccountRequest{
		Name:        role.APIKeyName + "-static-rotation",
		Description: "Vault static role rotation: " + roleName,
	})
	if err != nil {
		b.Logger().Error("Failed to create service account and API key", "role", roleName, "error", err)

		// Re-queue for retry
		retryTime := time.Now().Add(30 * time.Second) // Retry in 30 seconds
		if err := b.queueRotation(roleName, retryTime.Add(-role.RotationPeriod), role.RotationPeriod); err != nil {
			b.Logger().Error("Failed to re-queue rotation", "role", roleName, "error", err)
		}
		return
	}

	oldAPIKey := role.APIKey
	oldServiceAccountID := role.ServiceAccountID
	role.ServiceAccountID = svcAccount.ID
	role.APIKey = apiKey.Key
	role.LastRotatedTime = time.Now()

	// Save the updated role
	entry, err := logical.StorageEntryJSON(staticRolePath+"/"+roleName, role)
	if err != nil {
		b.Logger().Error("Failed to encode role", "role", roleName, "error", err)
		return
	}

	if err := b.storageView.Put(ctx, entry); err != nil {
		b.Logger().Error("Failed to save role", "role", roleName, "error", err)
		return
	}

	// Clean up the old API key and service account if present
	if oldAPIKey != "" {
		_ = b.client.DeleteAPIKey(ctx, oldAPIKey) // ignore error
	}
	if oldServiceAccountID != "" {
		_ = b.client.DeleteServiceAccount(ctx, oldServiceAccountID, role.ProjectID) // ignore error
	}

	b.Logger().Info("Successfully rotated credentials", "role", roleName)

	// Queue the next rotation
	if err := b.queueRotation(roleName, role.LastRotatedTime, role.RotationPeriod); err != nil {
		b.Logger().Error("Failed to queue next rotation", "role", roleName, "error", err)
	}
}
