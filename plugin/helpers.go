// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// existenceCheckForNamedPath returns a function that checks if an object with a given name exists in storage
// This function is used by multiple path handlers to check if an object exists before creating it
func existenceCheckForNamedPath(fieldName string, pathGenerator func(string) string) framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		name, ok := data.Get(fieldName).(string)
		if !ok {
			return false, fmt.Errorf("field %q is not of type string", fieldName)
		}
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

// configureClientFromStorage creates and configures a client from storage configuration
// This centralizes the repeated pattern of getting config and setting up a client
func (b *backend) configureClientFromStorage(ctx context.Context, storage logical.Storage) (*Client, error) {
	config, err := getConfig(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("error getting OpenAI configuration: %w", err)
	}
	if config == nil {
		return nil, fmt.Errorf("OpenAI is not configured")
	}

	client := NewClient(config.AdminAPIKey, b.Logger())
	clientConfig := &Config{
		AdminAPIKey:    config.AdminAPIKey,
		AdminAPIKeyID:  config.AdminAPIKeyID,
		APIEndpoint:    config.APIEndpoint,
		OrganizationID: config.OrganizationID,
	}

	if err := client.SetConfig(clientConfig); err != nil {
		return nil, fmt.Errorf("error configuring OpenAI client: %w", err)
	}

	return client, nil
}

// ensureClientConfigured ensures the backend has a configured client
// This is used in multiple places to lazy-load the client when needed
func (b *backend) ensureClientConfigured(ctx context.Context, storage logical.Storage) error {
	if b.client == nil {
		client, err := b.configureClientFromStorage(ctx, storage)
		if err != nil {
			return err
		}
		b.client = client
	}
	return nil
}

// maskSensitiveString masks sensitive strings like API keys for safe logging
// Shows first 4 and last 4 characters with masked middle for identification
func maskSensitiveString(s string) string {
	if s == "" {
		return ""
	}
	
	// For very short strings, mask completely
	if len(s) <= 8 {
		return "[REDACTED]"
	}
	
	// For longer strings, show first 4 and last 4 chars with dots in between
	return s[:4] + "..." + s[len(s)-4:]
}

// maskAPIKeyID masks API key IDs for safe logging
func maskAPIKeyID(keyID string) string {
	return maskSensitiveString(keyID)
}

// maskResponseBody masks potentially sensitive response body content for logging
func maskResponseBody(body string) string {
	if body == "" {
		return ""
	}
	
	// If the body contains potential API key patterns or is very long, mask it
	if strings.Contains(strings.ToLower(body), "api") || 
		strings.Contains(strings.ToLower(body), "key") || 
		strings.Contains(strings.ToLower(body), "secret") ||
		len(body) > 200 {
		return "[RESPONSE_BODY_REDACTED]"
	}
	
	return body
}
