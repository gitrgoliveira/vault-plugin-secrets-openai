// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0
//
// Regression tests for the security hardening described in the follow-up to
// https://github.com/gitrgoliveira/vault-plugin-secrets-openai/pull/7

package openaisecrets

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Item 1: SSRF / api_endpoint validation
// ---------------------------------------------------------------------------

func TestValidateAPIEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		allowPrivate bool
		wantError    bool
		errContains  string
	}{
		// Valid
		{"openai production endpoint", "https://api.openai.com/v1", false, false, ""},
		{"custom https hostname", "https://proxy.example.com/v1", false, false, ""},
		{"https with port", "https://api.openai.com:443/v1", false, false, ""},
		{"http loopback by IP", "http://127.0.0.1:8080/v1", false, false, ""},
		{"http loopback by hostname", "http://localhost:9090/v1", false, false, ""},

		// Invalid scheme
		{"ftp scheme", "ftp://api.openai.com/v1", false, true, "https"},
		{"no scheme", "api.openai.com/v1", false, true, "valid URL"},

		// http with non-loopback is rejected
		{"http public IP", "http://1.2.3.4/v1", false, true, "loopback"},
		{"http public hostname", "http://api.openai.com/v1", false, true, "loopback"},
		{"http private IP", "http://10.0.0.1/v1", false, true, "loopback"},

		// SSRF: private / link-local literals
		{"AWS metadata service", "https://169.254.169.254/latest/meta-data", false, true, "link-local"},
		{"RFC1918 10.x", "https://10.0.0.1/", false, true, "private"},
		{"RFC1918 172.16.x", "https://172.16.0.1/", false, true, "private"},
		{"RFC1918 192.168.x", "https://192.168.1.1/", false, true, "private"},
		{"IPv6 link-local", "https://[fe80::1]/", false, true, "link-local"},

		// Opt-in override
		{"private allowed when opted in", "https://10.0.0.1/v1", true, false, ""},
		{"metadata allowed when opted in", "https://169.254.169.254/", true, false, ""},

		// Malformed
		{"empty string", "", false, true, "valid URL"},
		{"just a path", "/v1", false, true, "https"},
		{"missing hostname", "https:///v1", false, true, "hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAPIEndpoint(tt.endpoint, tt.allowPrivate)
			if tt.wantError {
				require.Error(t, err, "expected error for endpoint %q", tt.endpoint)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err, "unexpected error for endpoint %q", tt.endpoint)
		})
	}
}

// TestCheckDialAddress verifies the dial-time guard that closes the gap a
// hostname-only validation leaves open: a name that resolves to an internal IP.
func TestCheckDialAddress(t *testing.T) {
	c := NewClient("k", hclog.NewNullLogger())

	// Private and link-local resolved addresses are rejected by default.
	for _, addr := range []string{"10.0.0.1:443", "192.168.1.1:443", "169.254.169.254:80", "[fe80::1]:443"} {
		require.Error(t, c.checkDialAddress(addr), "expected %q to be blocked", addr)
	}

	// Loopback and public addresses are allowed.
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "1.2.3.4:443"} {
		require.NoError(t, c.checkDialAddress(addr), "expected %q to be allowed", addr)
	}

	// Opt-in relaxes the guard for private addresses.
	c.allowPrivateEndpoint = true
	require.NoError(t, c.checkDialAddress("10.0.0.1:443"))
}

// TestDialGuard_BlocksPrivateAtTransport drives a real request through the
// guarded transport to prove the resolved-IP check fires at dial time, even
// when the endpoint bypassed config-write validation.
func TestDialGuard_BlocksPrivateAtTransport(t *testing.T) {
	c := NewClient("k", hclog.NewNullLogger())
	// Simulate a hostname that resolved to a private IP by assigning the
	// endpoint directly, bypassing SetConfig validation.
	c.apiEndpoint = "https://10.0.0.1"

	_, err := c.doRequest(context.Background(), http.MethodGet, "/v1/models", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private or link-local")

	// With the opt-in flag the guard no longer blocks; the request fails for a
	// different reason (no server listening / timeout), not the SSRF guard. Use
	// a short context so the unreachable dial does not wait for the full client
	// timeout.
	c.allowPrivateEndpoint = true
	shortCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = c.doRequest(shortCtx, http.MethodGet, "/v1/models", nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "private or link-local")
}

// TestSSRF_PrivateEndpointRejectedAtConfig verifies end-to-end rejection at
// config-write time.
func TestSSRF_PrivateEndpointRejectedAtConfig(t *testing.T) {
	b := getTestBackend(t)
	ctx := context.Background()
	schema := b.pathAdminConfig()[1].Fields

	for _, ep := range []string{
		"http://10.0.0.1/v1",
		"https://192.168.1.1/v1",
		"https://169.254.169.254/latest/meta-data",
		"ftp://api.openai.com/v1",
	} {
		t.Run(ep, func(t *testing.T) {
			req := &logical.Request{
				Operation:  logical.UpdateOperation,
				Path:       "config",
				Storage:    &logical.InmemStorage{},
				MountPoint: TestMountPoint,
			}
			fd := &framework.FieldData{
				Raw: map[string]interface{}{
					"admin_api_key":    "test-key",
					"admin_api_key_id": "test-key-id",
					"organization_id":  "org-123",
					"api_endpoint":     ep,
				},
				Schema: schema,
			}
			resp, err := b.pathConfigWrite(ctx, req, fd)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.IsError(), "expected error response for endpoint %q", ep)
		})
	}
}

// TestConfig_AllowPrivateEndpoint confirms the opt-in flag permits a private
// endpoint at config-write time.
func TestConfig_AllowPrivateEndpoint(t *testing.T) {
	b := getTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation:  logical.UpdateOperation,
		Path:       "config",
		Storage:    &logical.InmemStorage{},
		MountPoint: TestMountPoint,
	}
	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"admin_api_key":          "test-key",
			"admin_api_key_id":       "test-key-id",
			"organization_id":        "org-123",
			"api_endpoint":           "https://10.0.0.1/v1",
			"allow_private_endpoint": true,
		},
		Schema: b.pathAdminConfig()[1].Fields,
	}
	resp, err := b.pathConfigWrite(ctx, req, fd)
	require.NoError(t, err)
	if resp != nil {
		assert.False(t, resp.IsError(), "private endpoint should be accepted when opted in")
	}
}

// ---------------------------------------------------------------------------
// Item 6: response body size limit
// ---------------------------------------------------------------------------

func TestResponseBodySizeLimit(t *testing.T) {
	const maxResponseBytes = 1 << 20
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("a", 2*maxResponseBytes)))
	}))
	defer server.Close()

	c := NewClient("k", hclog.NewNullLogger())
	require.NoError(t, c.SetConfig(&Config{
		AdminAPIKey:    "k",
		OrganizationID: "org-123",
		APIEndpoint:    server.URL,
	}))

	body, err := c.doRequest(context.Background(), http.MethodGet, "/v1/models", nil)
	require.NoError(t, err)
	assert.Len(t, body, maxResponseBytes, "response body should be capped at 1 MiB")
}

// ---------------------------------------------------------------------------
// Item 3: safe type assertions in dynamicCredsRevoke
// ---------------------------------------------------------------------------

func TestDynamicCredsRevoke_MissingInternalData(t *testing.T) {
	b := getTestBackend(t)
	ctx := context.Background()

	cases := []struct {
		name     string
		internal map[string]interface{}
	}{
		{"nil internal data", nil},
		{"missing api_key_id", map[string]interface{}{"service_account_id": "svc", "project_id": "proj"}},
		{"wrong type service_account_id", map[string]interface{}{"api_key_id": "k", "service_account_id": 42, "project_id": "proj"}},
		{"empty project_id", map[string]interface{}{"api_key_id": "k", "service_account_id": "svc", "project_id": ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Storage: &logical.InmemStorage{},
				Secret:  &logical.Secret{InternalData: tc.internal},
			}
			// Must return an error, not panic.
			_, err := b.dynamicCredsRevoke(ctx, req, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "internal error")
		})
	}
}

// ---------------------------------------------------------------------------
// Item 7: uniform random distribution
// ---------------------------------------------------------------------------

func TestGenerateRandomString_NoBias(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const samples = 60000
	const strLen = 10

	counts := make(map[rune]int, len(charset))
	total := 0
	for i := 0; i < samples; i++ {
		s, err := generateRandomString(strLen)
		require.NoError(t, err)
		require.Len(t, s, strLen)
		for _, r := range s {
			assert.True(t, strings.ContainsRune(charset, r), "unexpected character %q", r)
			counts[r]++
			total++
		}
	}

	expected := float64(total) / float64(len(charset))
	for _, r := range charset {
		dev := math.Abs(float64(counts[r])-expected) / expected
		assert.Less(t, dev, 0.1, "character %q deviates %.3f from uniform", r, dev)
	}
}

// ---------------------------------------------------------------------------
// Item 8: name template validation
// ---------------------------------------------------------------------------

func TestValidateNameTemplate(t *testing.T) {
	cases := []struct {
		name      string
		template  string
		wantError bool
	}{
		{"default template", "vault-{{.RoleName}}-{{.RandomSuffix}}", false},
		{"project name template", "{{.ProjectName}}-{{.RandomSuffix}}", false},
		{"empty template", "", true},
		{"broken syntax", "vault-{{.RoleName", true},
		{"reserved word", "openai", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNameTemplate(tc.template)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRoleWrite_InvalidTemplate(t *testing.T) {
	b := getTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Storage:   &logical.InmemStorage{},
	}
	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":                          "bad",
			"project_id":                    TestProjectID,
			"service_account_name_template": "vault-{{.RoleName",
		},
		Schema: b.pathDynamicSvcAccount()[0].Fields,
	}
	resp, err := b.pathRoleWrite(ctx, req, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError(), "broken template should be rejected at role-write time")
}

// ---------------------------------------------------------------------------
// Item 5: config delete deregisters the rotation job
// ---------------------------------------------------------------------------

type recordingSystemView struct {
	logical.StaticSystemView
	deregisterCalled bool
}

func (r *recordingSystemView) RegisterRotationJob(_ context.Context, _ *rotation.RotationJobConfigureRequest) (string, error) {
	return "test-job-id", nil
}

func (r *recordingSystemView) DeregisterRotationJob(_ context.Context, _ *rotation.RotationJobDeregisterRequest) error {
	r.deregisterCalled = true
	return nil
}

func TestConfigDelete_DeregistersRotationJob(t *testing.T) {
	sv := &recordingSystemView{
		StaticSystemView: logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultTTL,
			MaxLeaseTTLVal:     maxTTL,
		},
	}
	b := Backend(&mockClient{})
	cfg := logical.TestBackendConfig()
	cfg.Logger = hclog.NewNullLogger()
	cfg.System = sv
	require.NoError(t, b.Setup(context.Background(), cfg))

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	// Persist a config with automated rotation enabled so a job exists.
	config := &openaiConfig{
		AdminAPIKey:    "k",
		AdminAPIKeyID:  "id",
		OrganizationID: "org-123",
		APIEndpoint:    DefaultAPIEndpoint,
	}
	config.RotationPeriod = 24 * 3600
	require.True(t, config.ShouldRegisterRotationJob())
	entry, err := logical.StorageEntryJSON(configPath, config)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	req := &logical.Request{
		Operation:  logical.DeleteOperation,
		Path:       "config",
		Storage:    storage,
		MountPoint: TestMountPoint,
	}
	_, err = b.pathConfigDelete(ctx, req, nil)
	require.NoError(t, err)
	assert.True(t, sv.deregisterCalled, "expected rotation job to be deregistered on config delete")
}

// ---------------------------------------------------------------------------
// Item 4: failed revocation records each stale key under a per-ID path
// ---------------------------------------------------------------------------

// TestRotation_PendingRevocationPerKey verifies that when admin key revocation
// fails, the stale key ID is recorded under a per-ID storage path, and that two
// consecutive failures retain two distinct records rather than overwriting.
func TestRotation_PendingRevocationPerKey(t *testing.T) {
	var keyCounter int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/admin_api_keys"):
			keyCounter++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"object":"admin_api_key","id":"new-key-%d","name":"n","value":"sk-new-%d","created_at":1}`,
				keyCounter, keyCounter)))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/admin_api_keys"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodDelete:
			// Simulate revocation failure.
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	b := getTestBackend(t)
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	config := &openaiConfig{
		AdminAPIKey:    "old-secret",
		AdminAPIKeyID:  "old-key-1",
		OrganizationID: "org-123",
		APIEndpoint:    server.URL + "/v1",
	}
	entry, err := logical.StorageEntryJSON(configPath, config)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))

	// First rotation: revocation of "old-key-1" fails.
	_, err = b.rotateAdminAPIKey(ctx, storage)
	require.Error(t, err)
	first, err := storage.Get(ctx, pendingRevocationPath("old-key-1"))
	require.NoError(t, err)
	require.NotNil(t, first, "first stale key should be recorded")
	assert.Equal(t, "old-key-1", string(first.Value))

	// Config now holds "new-key-1". Second rotation: revocation of it also fails.
	_, err = b.rotateAdminAPIKey(ctx, storage)
	require.Error(t, err)
	second, err := storage.Get(ctx, pendingRevocationPath("new-key-1"))
	require.NoError(t, err)
	require.NotNil(t, second, "second stale key should be recorded under its own path")

	// The first record must survive the second failure.
	stillThere, err := storage.Get(ctx, pendingRevocationPath("old-key-1"))
	require.NoError(t, err)
	require.NotNil(t, stillThere, "first stale key must not be overwritten by the second failure")
}
