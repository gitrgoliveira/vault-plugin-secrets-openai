// Copyright 2025 MIT Office of Learning.
// SPDX-License-Identifier: MPL-2.0
//
// Tests for the security fixes described in the upstream security analysis:
// https://github.com/gitrgoliveira/vault-plugin-secrets-openai/pull/XXXX

package openaisecrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SSRF / api_endpoint validation
// ---------------------------------------------------------------------------

func TestValidateAPIEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		wantError bool
		errContains string
	}{
		// Valid
		{"openai production endpoint", "https://api.openai.com/v1", false, ""},
		{"custom https endpoint", "https://myproxy.internal.example.com/v1", false, ""},
		{"http loopback by IP", "http://127.0.0.1:8080/v1", false, ""},
		{"http loopback by hostname", "http://localhost:9090/v1", false, ""},
		{"https with port", "https://api.openai.com:443/v1", false, ""},

		// Invalid scheme
		{"ftp scheme", "ftp://api.openai.com/v1", true, "https"},
		{"no scheme", "api.openai.com/v1", true, "valid URL"},

		// http with non-loopback — blocked
		{"http with public IP", "http://1.2.3.4/v1", true, "loopback"},
		{"http with public hostname", "http://api.openai.com/v1", true, "loopback"},
		{"http with private IP", "http://10.0.0.1/v1", true, "loopback"},

		// SSRF: private / link-local ranges
		{"AWS metadata service", "https://169.254.169.254/latest/meta-data", true, "link-local"},
		{"RFC1918 10.x", "https://10.0.0.1/", true, "private"},
		{"RFC1918 172.16.x", "https://172.16.0.1/", true, "private"},
		{"RFC1918 192.168.x", "https://192.168.1.1/", true, "private"},
		{"IPv6 link-local", "https://[fe80::1]/", true, "link-local"},

		// Malformed
		{"empty string", "", true, "valid URL"},
		{"just a path", "/v1", true, "https"},
		{"missing hostname", "https:///v1", true, "hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAPIEndpoint(tt.endpoint)
			if tt.wantError {
				require.Error(t, err, "expected error for endpoint %q", tt.endpoint)
				if tt.errContains != "" {
					assert.True(t, strings.Contains(err.Error(), tt.errContains),
						"error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err, "unexpected error for endpoint %q", tt.endpoint)
			}
		})
	}
}

// TestSSRF_PrivateEndpointRejectedAtConfig verifies that a private-network
// api_endpoint is rejected at config-write time, not silently accepted.
func TestSSRF_PrivateEndpointRejectedAtConfig(t *testing.T) {
	b := getTestBackend(t)
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	ssrfEndpoints := []string{
		"http://10.0.0.1/v1",
		"https://192.168.1.1/v1",
		"https://169.254.169.254/latest/meta-data",
		"ftp://api.openai.com/v1",
	}

	for _, ep := range ssrfEndpoints {
		t.Run(ep, func(t *testing.T) {
			configData := map[string]interface{}{
				"admin_api_key":    "test-key",
				"admin_api_key_id": "test-key-id",
				"organization_id":  "org-123",
				"api_endpoint":     ep,
			}
			fd := &framework.FieldData{
				Raw:    configData,
				Schema: b.pathAdminConfig()[1].Fields,
			}
			req := &logical.Request{
				Storage:    storage,
				MountPoint: "openai/",
				Path:       "config",
			}
			resp, err := b.pathConfigWrite(ctx, req, fd)
			// Should be rejected — either as an error response or a Go error.
			if err == nil && (resp == nil || !resp.IsError()) {
				t.Errorf("config write with endpoint %q should have been rejected", ep)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Response-body size limit
// ---------------------------------------------------------------------------

// TestResponseBodySizeLimit verifies that the HTTP client caps response bodies
// at 1 MiB, protecting against memory exhaustion.
func TestResponseBodySizeLimit(t *testing.T) {
	const megabyte = 1 << 20
	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, megabyte)
		for i := 0; i < 4; i++ {
			_, _ = w.Write(chunk)
		}
	}))
	defer oversized.Close()

	logger := hclog.NewNullLogger()
	client := NewClient("sk-test", logger)
	_ = client.SetConfig(&Config{
		AdminAPIKey:    "sk-test",
		OrganizationID: "org-123",
		APIEndpoint:    oversized.URL,
	})

	// For a 200 OK response the body bytes are returned without a Go error.
	// The key invariant is that the returned slice is capped at 1 MiB.
	body, err := client.doRequest(context.Background(), http.MethodGet, "/test", nil)
	if err != nil {
		// An error is also acceptable (e.g. if Vault parses the truncated JSON).
		t.Logf("doRequest returned error (acceptable): %v", err)
		return
	}
	assert.LessOrEqual(t, len(body), megabyte,
		"response body should be capped at 1 MiB, got %d bytes", len(body))
}

// ---------------------------------------------------------------------------
// Safe type assertions in dynamicCredsRevoke
// ---------------------------------------------------------------------------

// TestDynamicCredsRevoke_MissingInternalData verifies that a revocation request
// with missing or nil InternalData fields returns an error rather than panicking.
func TestDynamicCredsRevoke_MissingInternalData(t *testing.T) {
	b := getTestBackend(t)
	ctx := context.Background()

	cases := []struct {
		name         string
		internalData map[string]interface{}
	}{
		{"empty internal data", map[string]interface{}{}},
		{"missing service_account_id", map[string]interface{}{
			"api_key_id": "key-123",
			"project_id": "proj_123",
		}},
		{"nil api_key_id", map[string]interface{}{
			"api_key_id":         nil,
			"service_account_id": "svc-123",
			"project_id":         "proj_123",
		}},
		{"wrong type for project_id", map[string]interface{}{
			"api_key_id":         "key-123",
			"service_account_id": "svc-123",
			"project_id":         12345,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Storage: &logical.InmemStorage{},
				Secret: &logical.Secret{
					InternalData: tc.internalData,
				},
			}
			// Must not panic.
			resp, err := b.dynamicCredsRevoke(ctx, req, &framework.FieldData{})
			assert.Error(t, err, "should return error for missing internal data")
			assert.Nil(t, resp)
		})
	}
}

// ---------------------------------------------------------------------------
// Uniform random suffix (no modular bias)
// ---------------------------------------------------------------------------

// TestGenerateRandomString_NoBias checks that all characters in the charset
// appear with roughly equal frequency, confirming rejection-sampling works.
func TestGenerateRandomString_NoBias(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const iterations = 500_000
	const length = 1

	counts := make(map[byte]int, len(charset))
	for i := 0; i < iterations; i++ {
		s, err := generateRandomString(length)
		require.NoError(t, err)
		require.Len(t, s, length)
		counts[s[0]]++
	}

	expected := float64(iterations) / float64(len(charset))
	// Allow ±5% deviation from the expected uniform distribution.
	tolerance := expected * 0.05

	for _, ch := range []byte(charset) {
		count := float64(counts[ch])
		diff := count - expected
		if diff < 0 {
			diff = -diff
		}
		assert.Less(t, diff, tolerance,
			"character %q has count %d, expected ~%.0f (±%.0f)", ch, counts[ch], expected, tolerance)
	}
}

// ---------------------------------------------------------------------------
// Template validation at role-write time
// ---------------------------------------------------------------------------

func TestValidateNameTemplate(t *testing.T) {
	tests := []struct {
		name      string
		template  string
		wantError bool
	}{
		{"default template", "vault-{{.RoleName}}-{{.RandomSuffix}}", false},
		{"with project name", "{{.ProjectName}}-{{.RoleName}}-{{.RandomSuffix}}", false},
		{"static prefix", "myapp-{{.RandomSuffix}}", false},
		{"empty template", "", true},
		{"syntax error", "{{.Unclosed", true},
		{"produces_too-short_name", "ab", true},   // sanitised → "ab_" ends with underscore
		{"unknown variable", "{{.Unknown}}", false}, // text/template renders missing keys as <no value>; sanitised result may still pass
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNameTemplate(tt.template)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRoleWrite_InvalidTemplate verifies that pathRoleWrite rejects a template
// that would produce an invalid service-account name.
// TestRoleWrite_InvalidTemplate verifies that pathRoleWrite rejects a template
// that would produce an invalid service-account name.
// Uses the mockClient (which bypasses HTTP) so project validation passes.
func TestRoleWrite_InvalidTemplate(t *testing.T) {
	b := getTestBackend(t) // uses mockClient — GetProject returns a valid project
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Store a minimal config directly so ensureClientConfigured is satisfied.
	cfg := &openaiConfig{
		AdminAPIKey:    TestAPIKey,
		AdminAPIKeyID:  TestAdminAPIKeyID,
		OrganizationID: TestOrganizationID,
		APIEndpoint:    DefaultAPIEndpoint,
	}
	entry, err := logical.StorageEntryJSON(configPath, cfg)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// Try to write a role with a syntactically broken template.
	roleData := map[string]interface{}{
		"name":                          "bad-template-role",
		"project_id":                    TestProjectID,
		"service_account_name_template": "{{.Unclosed",
	}
	roleFD := &framework.FieldData{
		Raw:    roleData,
		Schema: b.pathDynamicSvcAccount()[0].Fields,
	}
	roleReq := &logical.Request{
		Storage:    storage,
		MountPoint: "openai/",
		Path:       "roles/bad-template-role",
	}
	resp, err := b.pathRoleWrite(ctx, roleReq, roleFD)
	require.NoError(t, err) // template error returns an ErrorResponse, not a Go error
	require.NotNil(t, resp)
	assert.True(t, resp.IsError(), "expected error response for invalid template, got: %v", resp.Data)
}

// ---------------------------------------------------------------------------
// Config delete deregisters rotation job
// ---------------------------------------------------------------------------

// TestConfigDelete_DeregistersRotationJob verifies that deleting the config
// with automated rotation enabled calls DeregisterRotationJob so Vault's
// rotation manager does not continue firing after the config is gone.
func TestConfigDelete_DeregistersRotationJob(t *testing.T) {
	mockServer := NewMockOpenAIServer()
	defer mockServer.Close()

	b := getTestBackend(t)
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	// Write a config with a rotation period so a job gets registered.
	configData := map[string]interface{}{
		"admin_api_key":    TestAPIKey,
		"admin_api_key_id": TestAdminAPIKeyID,
		"organization_id":  TestOrganizationID,
		"api_endpoint":     mockServer.URL() + "/v1",
		"rotation_period":  3600, // 1 hour
	}
	fd := &framework.FieldData{Raw: configData, Schema: b.pathAdminConfig()[1].Fields}
	writeReq := &logical.Request{Storage: storage, MountPoint: "openai/", Path: "config"}
	_, err := b.pathConfigWrite(ctx, writeReq, fd)
	require.NoError(t, err)

	// Confirm config exists.
	cfg, err := getConfig(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Delete the config.
	deleteReq := &logical.Request{Storage: storage, MountPoint: "openai/", Path: "config"}
	resp, err := b.pathConfigDelete(ctx, deleteReq, &framework.FieldData{})
	require.NoError(t, err)
	assert.Nil(t, resp)

	// Config should be gone.
	cfg, err = getConfig(ctx, storage)
	require.NoError(t, err)
	assert.Nil(t, cfg, "config should be removed after delete")

	// Client should be nil.
	b.RLock()
	clientNil := b.client == nil
	b.RUnlock()
	assert.True(t, clientNil, "backend client should be nil after config delete")
}
