// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// These tests validate the service account name validation logic based on
// common API resource naming conventions and observed behavior

// Helper to generate repeated strings
func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

func TestValidateServiceAccountName(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid name with letters and numbers",
			input:       "test123",
			expectError: false,
		},
		{
			name:        "Valid name with underscore",
			input:       "test_account",
			expectError: false,
		},
		{
			name:        "Valid name with hyphen",
			input:       "test-account",
			expectError: false,
		},
		{
			name:        "Valid name with mixed characters",
			input:       "test-account_123",
			expectError: false,
		},
		{
			name:        "Empty name",
			input:       "",
			expectError: true,
			errorMsg:    "service account name cannot be empty",
		},
		{
			name:        "Too short",
			input:       "ab",
			expectError: true,
			errorMsg:    "service account name must be at least 3 characters long",
		},
		{
			name:        "Too long",
			input:       repeat("a", 65),
			expectError: true,
			errorMsg:    "service account name cannot exceed 64 characters",
		},
		{
			name:        "Contains invalid characters",
			input:       "test@account",
			expectError: true,
			errorMsg:    "service account name can only contain letters, numbers, hyphens, and underscores",
		},
		{
			name:        "Consecutive special characters",
			input:       "test__account",
			expectError: true,
			errorMsg:    "service account name cannot contain consecutive hyphens or underscores",
		},
		{
			name:        "Starts with special character",
			input:       "_test",
			expectError: true,
			errorMsg:    "service account name cannot start or end with a hyphen or underscore",
		},
		{
			name:        "Ends with special character",
			input:       "test-",
			expectError: true,
			errorMsg:    "service account name cannot start or end with a hyphen or underscore",
		},
		{
			name:        "Reserved word",
			input:       "admin",
			expectError: true,
			errorMsg:    "service account name cannot be a reserved word: admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceAccountName(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSanitizeServiceAccountName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Already valid",
			input:    "valid-name",
			expected: "valid-name",
		},
		{
			name:     "Invalid characters",
			input:    "name@with.invalid#chars",
			expected: "name_with_invalid_chars",
		},
		{
			name:     "Consecutive special characters",
			input:    "name--with__consecutive",
			expected: "name_with_consecutive",
		},
		{
			name:     "Starting with special character",
			input:    "_name",
			expected: "name",
		},
		{
			name:     "Ending with special character",
			input:    "name-",
			expected: "name",
		},
		{
			name:     "Too short",
			input:    "x",
			expected: "x__",
		},
		{
			name:     "Too long",
			input:    repeat("a", 100),
			expected: repeat("a", 64),
		},
		{
			name:     "Too long with special char at truncation point",
			input:    repeat("a", 63) + "-" + repeat("b", 10),
			expected: repeat("a", 63),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeServiceAccountName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// No longer needed - using the helper function at the top of the file
