// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateReportedVersion ensures the plugin only self-reports a version in
// the format Vault accepts for RunningVersion: empty, or a semver with a leading
// 'v'. A non-empty, invalid value would fail Vault plugin registration.
func TestValidateReportedVersion(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{name: "Empty is allowed (unversioned)", input: "", expectError: false},
		{name: "Valid release", input: "v0.8.0", expectError: false},
		{name: "Valid with pre-release", input: "v1.2.3-rc.1", expectError: false},
		{name: "Valid with build metadata", input: "v1.2.3+builtin", expectError: false},
		{name: "Missing leading v", input: "0.8.0", expectError: true},
		{name: "Dev placeholder", input: "dev", expectError: true},
		{name: "Dev with sha", input: "dev-abc1234", expectError: true},
		{name: "Trailing junk", input: "v1.2.3foo", expectError: true},
		{name: "Incomplete semver", input: "v1.2", expectError: true},
		{name: "Leading junk", input: "release-v1.2.3", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReportedVersion(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFactoryRejectsInvalidReportedVersion ensures a malformed build-time
// injected version fails fast at plugin construction instead of surfacing as an
// opaque Vault registration error.
func TestFactoryRejectsInvalidReportedVersion(t *testing.T) {
	original := ReportedVersion
	t.Cleanup(func() { ReportedVersion = original })

	ReportedVersion = "not-a-version"
	_, err := Factory(context.Background(), &logical.BackendConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid plugin version")
}
