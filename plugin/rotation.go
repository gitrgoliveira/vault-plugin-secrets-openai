// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

const ()

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
