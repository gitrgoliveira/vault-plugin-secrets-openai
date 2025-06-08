// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// Cleanup configuration defaults
	defaultCleanupInterval = 1 * time.Hour
	defaultCleanupTimeout  = 5 * time.Minute
)

// CleanupManager handles periodic cleanup of orphaned service accounts and expired API keys
type CleanupManager struct {
	backend        *backend
	stopCh         chan struct{}
	doneCh         chan struct{}
	cleanupRunning bool
	mutex          sync.Mutex
	interval       time.Duration
}

// NewCleanupManager creates a new cleanup manager
func NewCleanupManager(b *backend) *CleanupManager {
	return &CleanupManager{
		backend:  b,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		interval: defaultCleanupInterval,
	}
}

// Start begins the periodic cleanup process
func (c *CleanupManager) Start() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.cleanupRunning {
		return
	}

	c.cleanupRunning = true
	go c.runCleanupLoop()
}

// Stop gracefully shuts down the cleanup manager
func (c *CleanupManager) Stop() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.cleanupRunning {
		return
	}

	close(c.stopCh)
	<-c.doneCh
	c.cleanupRunning = false
}

// SetInterval changes the cleanup interval
func (c *CleanupManager) SetInterval(interval time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.interval = interval
}

// runCleanupLoop runs the cleanup process at regular intervals
func (c *CleanupManager) runCleanupLoop() {
	defer close(c.doneCh)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Create a context with a timeout for the cleanup operation
			ctx, cancel := context.WithTimeout(context.Background(), defaultCleanupTimeout)
			if err := c.RunCleanup(ctx); err != nil {
				c.backend.Logger().Error("Error during cleanup process", "error", err)
			}
			cancel()
		case <-c.stopCh:
			return
		}
	}
}

// RunCleanup performs a single cleanup operation
func (c *CleanupManager) RunCleanup(ctx context.Context) error {
	c.backend.Logger().Debug("Starting cleanup process")

	// Get all projects configured in the backend
	projects, err := c.getConfiguredProjects(ctx)
	if err != nil {
		return fmt.Errorf("error getting configured projects: %w", err)
	}

	for projectID, projectConfig := range projects {
		c.backend.Logger().Debug("Cleaning up project", "project_id", projectID)
		if err := c.cleanupProject(ctx, projectID, projectConfig); err != nil {
			c.backend.Logger().Error("Error cleaning up project",
				"project_id", projectID,
				"error", err)
			// Continue with next project
		}
	}

	c.backend.Logger().Debug("Cleanup process completed")
	return nil
}

// getConfiguredProjects retrieves all project configurations from storage
func (c *CleanupManager) getConfiguredProjects(ctx context.Context) (map[string]*projectEntry, error) {
	// Get the backend's storage
	storage := c.backend.storageView

	// List all project entries
	projectList, err := storage.List(ctx, "config/projects/")
	if err != nil {
		return nil, fmt.Errorf("error listing projects: %w", err)
	}

	projects := make(map[string]*projectEntry)
	for _, projectKey := range projectList {
		// Remove trailing slash if present
		projectID := projectKey
		if len(projectID) > 0 && projectID[len(projectID)-1] == '/' {
			projectID = projectID[:len(projectID)-1]
		}

		// Read project config
		entry, err := storage.Get(ctx, "config/projects/"+projectID)
		if err != nil {
			c.backend.Logger().Error("Error reading project config",
				"project_id", projectID,
				"error", err)
			continue
		}

		if entry == nil {
			c.backend.Logger().Warn("Project config not found", "project_id", projectID)
			continue
		}

		var projectConfig projectEntry
		if err := entry.DecodeJSON(&projectConfig); err != nil {
			c.backend.Logger().Error("Error decoding project config",
				"project_id", projectID,
				"error", err)
			continue
		}

		projects[projectID] = &projectConfig
	}

	return projects, nil
}

// cleanupProject cleans up orphaned service accounts for a specific project
func (c *CleanupManager) cleanupProject(ctx context.Context, projectID string, projectConfig *projectEntry) error {
	// Make sure we have a properly configured client
	if c.backend.client == nil {
		return fmt.Errorf("OpenAI client not configured")
	}

	// Get all service accounts for this project
	serviceAccounts, err := c.backend.client.ListServiceAccounts(ctx, projectID)
	if err != nil {
		return fmt.Errorf("error listing service accounts: %w", err)
	}

	// Get all leases associated with this project
	leases, err := c.getActiveLeases(ctx, projectID)
	if err != nil {
		return fmt.Errorf("error getting active leases: %w", err)
	}

	// Identify orphaned service accounts (those without an active lease)
	for _, sa := range serviceAccounts {
		// Skip if the service account name doesn't start with the vault- prefix
		// This assumes that service accounts created by this plugin have names starting with "vault-"
		if len(sa.Name) < 6 || sa.Name[:6] != "vault-" {
			continue
		}

		// Check if this service account has an active lease
		hasLease := false
		for _, lease := range leases {
			if lease.ServiceAccountID == sa.ID {
				hasLease = true
				break
			}
		}

		// If no active lease, delete the service account
		if !hasLease {
			c.backend.Logger().Info("Deleting orphaned service account",
				"service_account_id", sa.ID,
				"name", sa.Name,
				"project_id", projectID)

			if err := c.backend.client.DeleteServiceAccount(ctx, sa.ID, projectID); err != nil {
				c.backend.Logger().Error("Error deleting orphaned service account",
					"service_account_id", sa.ID,
					"project_id", projectID,
					"error", err)
				// Continue with next service account
			}
		}
	}

	return nil
}

// ActiveLease represents an active service account lease
type ActiveLease struct {
	RoleName         string `json:"role_name"`
	ServiceAccountID string `json:"service_account_id"`
	ProjectID        string `json:"project_id"`
}

// getActiveLeases retrieves all active leases for a project from storage
func (c *CleanupManager) getActiveLeases(ctx context.Context, projectID string) ([]ActiveLease, error) {
	// Get the backend's storage
	storage := c.backend.storageView

	// Get all role entries
	rolesList, err := storage.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}

	var leases []ActiveLease

	// For each role, check the project ID and get the service account IDs
	for _, roleName := range rolesList {
		// List all leases for this role
		leaseIDs, err := c.getLeaseIDsForRole(ctx, roleName, storage)
		if err != nil {
			c.backend.Logger().Error("Error retrieving leases for role", "role", roleName, "error", err)
			continue
		}

		// Get service account IDs for each lease
		for _, leaseID := range leaseIDs {
			serviceAccID, err := c.getServiceAccountIDForLease(ctx, leaseID, storage)
			if err != nil {
				c.backend.Logger().Error("Error retrieving service account for lease",
					"lease_id", leaseID,
					"error", err)
				continue
			}

			if serviceAccID != "" {
				leases = append(leases, ActiveLease{
					RoleName:         roleName,
					ServiceAccountID: serviceAccID,
					ProjectID:        projectID,
				})
			}
		}
	}

	return leases, nil
}

// getLeaseIDsForRole gets all lease IDs for a specific role using Vault's lease storage pattern
func (c *CleanupManager) getLeaseIDsForRole(ctx context.Context, roleName string, storage logical.Storage) ([]string, error) {
	// Reference: Vault LDAP plugin uses 'lease/' prefix for lease tracking
	// Leases are stored at: "lease/openai/creds/<role_name>/<lease_id>"
	leasePath := "lease/openai/creds/" + roleName + "/"
	leaseIDs, err := storage.List(ctx, leasePath)
	if err != nil {
		return nil, fmt.Errorf("error listing leases for role %s: %w", roleName, err)
	}
	return leaseIDs, nil
}

// getServiceAccountIDForLease gets the service account ID for a specific lease
func (c *CleanupManager) getServiceAccountIDForLease(ctx context.Context, leaseID string, storage logical.Storage) (string, error) {
	// Read lease entry - this would be stored when credentials are generated
	entry, err := storage.Get(ctx, "leases/"+leaseID)
	if err != nil {
		return "", fmt.Errorf("error reading lease: %w", err)
	}

	if entry == nil {
		return "", nil
	}

	var leaseData struct {
		ServiceAccountID string `json:"service_account_id"`
	}

	if err := entry.DecodeJSON(&leaseData); err != nil {
		return "", fmt.Errorf("error decoding lease data: %w", err)
	}

	return leaseData.ServiceAccountID, nil
}
