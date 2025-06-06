// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// existenceCheckForNamedPath returns a function that checks if an object with a given name exists in storage
// This function is used by multiple path handlers to check if an object exists before creating it
func existenceCheckForNamedPath(fieldName string, pathGenerator func(string) string) framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		name := data.Get(fieldName).(string)
		if name == "" {
			return false, nil
		}

		path := pathGenerator(name)
		entry, err := req.Storage.Get(ctx, path)
		if err != nil {
			return false, err
		}

		return entry != nil, nil
	}
}
