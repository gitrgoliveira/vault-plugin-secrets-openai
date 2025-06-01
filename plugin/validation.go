// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"fmt"
	"regexp"
	"strings"
)

// Service account name validation rules are based on observed behavior and best practices
// for API resource naming. Official OpenAI documentation for project service accounts:
// https://platform.openai.com/docs/api-reference/projects

const (
	// Service account name requirements
	minServiceAccountNameLength = 3
	maxServiceAccountNameLength = 64
)

// Regular expressions for service account name validation
var (
	// Valid characters for service account names
	validServiceAccountNameChars = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	// Check for consecutive special characters
	consecutiveSpecialChars = regexp.MustCompile(`[-_]{2,}`)

	// Check for special characters at the beginning or end
	startsOrEndsWithSpecialChar = regexp.MustCompile(`^[-_]|[-_]$`)
)

// ValidateServiceAccountName validates a service account name based on common API naming conventions
// and observed behavior with the OpenAI API. These constraints help ensure compatibility
// with OpenAI's platform requirements.
func ValidateServiceAccountName(name string) error {
	// Check for empty name
	if name == "" {
		return fmt.Errorf("service account name cannot be empty")
	}

	// Check length requirements
	if len(name) < minServiceAccountNameLength {
		return fmt.Errorf("service account name must be at least %d characters long", minServiceAccountNameLength)
	}

	if len(name) > maxServiceAccountNameLength {
		return fmt.Errorf("service account name cannot exceed %d characters", maxServiceAccountNameLength)
	}

	// Check if name contains only valid characters
	if !validServiceAccountNameChars.MatchString(name) {
		return fmt.Errorf("service account name can only contain letters, numbers, hyphens, and underscores")
	}

	// Check for consecutive special characters
	if consecutiveSpecialChars.MatchString(name) {
		return fmt.Errorf("service account name cannot contain consecutive hyphens or underscores")
	}

	// Check for special characters at the beginning or end
	if startsOrEndsWithSpecialChar.MatchString(name) {
		return fmt.Errorf("service account name cannot start or end with a hyphen or underscore")
	}

	// Consider reserved names or keywords that should be avoided
	reservedNames := []string{"admin", "administrator", "root", "system", "openai"}
	for _, reserved := range reservedNames {
		if strings.EqualFold(name, reserved) {
			return fmt.Errorf("service account name cannot be a reserved word: %s", reserved)
		}
	}

	return nil
}

// SanitizeServiceAccountName modifies a name to conform to service account naming best practices
// This ensures names will be compatible with the OpenAI API and follow standard conventions
// for cloud resource naming
func SanitizeServiceAccountName(name string) string {
	// Replace invalid characters with underscores
	reg := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	sanitized := reg.ReplaceAllString(name, "_")

	// Replace consecutive special characters with a single underscore
	sanitized = consecutiveSpecialChars.ReplaceAllString(sanitized, "_")

	// Remove special characters from the beginning and end
	sanitized = strings.Trim(sanitized, "-_")

	// Ensure the name meets the minimum length
	if len(sanitized) < minServiceAccountNameLength {
		// Pad with underscores if too short
		for len(sanitized) < minServiceAccountNameLength {
			sanitized += "_"
		}
	}

	// Truncate if too long
	if len(sanitized) > maxServiceAccountNameLength {
		sanitized = sanitized[:maxServiceAccountNameLength]
		// Ensure we don't end with a special character after truncation
		sanitized = strings.TrimRight(sanitized, "-_")
	}

	return sanitized
}
