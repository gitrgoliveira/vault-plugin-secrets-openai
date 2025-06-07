// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

const (
	// rotationCheckInterval is the interval at which we check for credentials needing rotation
	rotationCheckInterval = 10 * time.Minute
)

// initRotationQueue initializes the credential rotation queue for admin key rotation
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

	b.Logger().Info("Starting admin key rotation scheduler")

	// Start a goroutine that will check for credentials to rotate
	go b.rotateCredentials(rotationCtx)

	// Schedule admin key rotation if needed
	if err := b.scheduleAdminKeyRotation(ctx, storage); err != nil {
		b.Logger().Error("Failed to schedule admin key rotation", "error", err)
	}
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

// processRotations checks the queue and rotates the admin API key if needed
func (b *backend) processRotations(ctx context.Context) {
	now := time.Now()

	for b.credRotationQueue.Len() > 0 {
		item, err := b.credRotationQueue.Pop()
		if err != nil {
			b.Logger().Error("Failed to pop from rotation queue", "error", err)
			return
		}

		if item.Priority > now.Unix() {
			_ = b.credRotationQueue.Push(item)
			return
		}

		if item.Key == "admin_api_key" {
			b.Logger().Info("Rotating admin API key due to scheduled rotation")
			go func() {
				rotated, err := b.rotateAdminAPIKey(ctx, b.storageView)
				if err != nil {
					b.Logger().Error("Failed to rotate admin API key", "error", err)
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
					_ = b.scheduleAdminKeyRotation(ctx, b.storageView)
				} else {
					b.Logger().Warn("Admin API key rotation was not performed (no API key configured)")
				}
			}()
		}
	}
}
