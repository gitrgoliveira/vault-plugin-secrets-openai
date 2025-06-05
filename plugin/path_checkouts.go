// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const checkoutKeyType = "checkout-creds"

// checkoutSecretCreds creates a Secret type for checkout credentials
func checkoutSecretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: checkoutKeyType,
		Fields: map[string]*framework.FieldSchema{
			"service_account_id": {
				Type:        framework.TypeString,
				Description: "Service account ID",
			},
			"api_key": {
				Type:        framework.TypeString,
				Description: "API key",
			},
		},
		Renew:  b.renewCheckOut,
		Revoke: b.endCheckOut,
	}
}

// pathSetCheckOut creates a framework path for checking out service accounts
func (b *backend) pathSetCheckOut() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(libraryPrefix, "/") + framework.GenericNameRegex("name") + "/check-out$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the set",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "The length of time before the check-out will expire, in seconds.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.operationSetCheckOut,
					Summary:  "Check a service account out from the library.",
				},
			},
			HelpSynopsis:    "Check a service account out from the library.",
			HelpDescription: "Check out an available service account from the library set.",
		},
	}
}

// operationSetCheckOut handles checkout requests for library sets
func (b *backend) operationSetCheckOut(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	// Check if requested TTL was provided
	ttlPeriodRaw, ttlPeriodSent := fieldData.GetOk("ttl")
	if !ttlPeriodSent {
		ttlPeriodRaw = 0
	}
	requestedTTL := time.Duration(ttlPeriodRaw.(int)) * time.Second

	// Get the set configuration
	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse("set %q doesn't exist", setName), nil
	}

	// Determine TTL to use
	ttl := set.TTL
	if ttlPeriodSent {
		switch {
		case set.TTL <= 0 && requestedTTL > 0:
			// The set's TTL is infinite and the caller requested a finite TTL
			ttl = requestedTTL
		case set.TTL > 0 && requestedTTL < set.TTL:
			// The set's TTL isn't infinite and the caller requested a shorter TTL
			ttl = requestedTTL
		}
	}

	// Create check-out object
	newCheckOut := &CheckOut{
		IsAvailable:         false,
		BorrowerEntityID:    req.EntityID,
		BorrowerClientToken: req.ClientToken,
	}

	// Get configuration for client
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("OpenAI config not found"), nil
	}

	// Initialize the client if needed
	if b.client == nil {
		b.client = NewClient(config.AdminAPIKey, b.Logger())
		if err := b.client.SetConfig(&Config{
			AdminAPIKey:    config.AdminAPIKey,
			APIEndpoint:    config.APIEndpoint,
			OrganizationID: config.OrganizationID,
		}); err != nil {
			return nil, err
		}
	}

	// Check out the first available service account
	for _, serviceAccountID := range set.ServiceAccountIDs {
		if err := b.CheckOut(ctx, req.Storage, serviceAccountID, newCheckOut); err != nil {
			if err == errCheckedOut {
				continue
			}
			return nil, err
		}

		// Found an available account - generate API key for it
		expiresAt := time.Now().Add(ttl)
		apiKey, err := b.client.CreateAPIKey(ctx, CreateAPIKeyRequest{
			Name:         fmt.Sprintf("checkout-key-%d", time.Now().Unix()),
			ServiceAccID: serviceAccountID,
			ExpiresAt:    &expiresAt,
		})
		if err != nil {
			// Failed to create API key - set the service account back to available
			checkInErr := b.CheckIn(ctx, req.Storage, serviceAccountID, set.ProjectID)
			if checkInErr != nil {
				b.Logger().Error("failed to check in service account after API key creation failure",
					"service_account_id", serviceAccountID, "error", checkInErr)
			}
			b.emitAPIErrorMetric("CreateAPIKey", "check_out_error")
			return nil, fmt.Errorf("error creating API key: %w", err)
		}

		// Store the API key ID for later cleanup
		if err := b.StoreAPIKey(ctx, req.Storage, serviceAccountID, apiKey.ID); err != nil {
			b.Logger().Warn("failed to store API key ID",
				"service_account_id", serviceAccountID,
				"api_key_id", apiKey.ID,
				"error", err)
			// Continue anyway as this is not fatal
		}

		// Get service account details for the response
		svcAccount, err := b.client.GetServiceAccount(ctx, serviceAccountID, set.ProjectID)
		if err != nil {
			b.Logger().Warn("failed to retrieve service account details",
				"service_account_id", serviceAccountID,
				"error", err)
			// Continue anyway, as we have the key
		}

		// Create response data
		respData := map[string]interface{}{
			"service_account_id": serviceAccountID,
			"api_key":            apiKey.Key,
		}

		// Add service account details if available
		if svcAccount != nil {
			respData["service_account_name"] = svcAccount.Name
		}

		// Track checkout metrics
		b.emitCheckoutMetric(setName)

		// Create response with secret for renewal
		internalData := map[string]interface{}{
			"service_account_id": serviceAccountID,
			"api_key_id":         apiKey.ID,
			"set_name":           setName,
			"project_id":         set.ProjectID,
		}

		// Create response with secret
		resp := b.Secret(checkoutKeyType).Response(respData, internalData)
		resp.Secret.Renewable = true
		resp.Secret.TTL = ttl
		resp.Secret.MaxTTL = set.MaxTTL
		return resp, nil
	}

	// If we got here, there are no available service accounts
	b.Logger().Debug(fmt.Sprintf("set %q had no service accounts available", setName))
	b.emitUnavailableMetric(setName)
	return logical.ErrorResponse("no service accounts available for check-out"), nil
}

// pathSetCheckIn creates a framework path for checking in service accounts
func (b *backend) pathSetCheckIn() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(libraryPrefix, "/") + framework.GenericNameRegex("name") + "/check-in$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the set.",
					Required:    true,
				},
				"service_account_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "The service account IDs to check in.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.operationCheckIn(false),
					Summary:  "Check service accounts in to the library.",
				},
			},
			HelpSynopsis:    "Check service accounts in to the library.",
			HelpDescription: "Check service accounts in to the library.",
		},
	}
}

// pathSetManageCheckIn creates a framework path for admin/forced check-in
func (b *backend) pathSetManageCheckIn() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(libraryManagePrefix, "/") + framework.GenericNameRegex("name") + "/check-in$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the set.",
					Required:    true,
				},
				"service_account_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "The service account IDs to check in.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.operationCheckIn(true),
					Summary:  "Force check service accounts in to the library.",
				},
			},
			HelpSynopsis:    "Force checking service accounts in to the library.",
			HelpDescription: "Force checking service accounts in to the library.",
		},
	}
}

// operationCheckIn creates a callback for checking in service accounts
func (b *backend) operationCheckIn(overrideCheckInEnforcement bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
		setName := fieldData.Get("name").(string)
		lock := locksutil.LockForKey(b.checkOutLocks, setName)
		lock.Lock()
		defer lock.Unlock()

		// Get service account IDs to check in, if specified
		serviceAccountIDsRaw, serviceAccountIDsSent := fieldData.GetOk("service_account_ids")
		var serviceAccountIDs []string
		if serviceAccountIDsSent {
			serviceAccountIDs = serviceAccountIDsRaw.([]string)
		}

		// Get the set configuration
		set, err := readSet(ctx, req.Storage, setName)
		if err != nil {
			return nil, err
		}
		if set == nil {
			return logical.ErrorResponse("set %q doesn't exist", setName), nil
		}

		// If check-in enforcement is overridden or disabled at the set level, consider it disabled
		disableCheckInEnforcement := overrideCheckInEnforcement || set.DisableCheckInEnforcement

		// Track service accounts we check in for the response
		toCheckIn := make([]string, 0)

		// Build list of service accounts to check in
		if len(serviceAccountIDs) == 0 {
			// If the caller didn't specify service accounts, try to find checked out ones
			for _, setServiceAccountID := range set.ServiceAccountIDs {
				checkOut, err := b.LoadCheckOut(ctx, req.Storage, setServiceAccountID)
				if err != nil {
					return nil, err
				}
				if checkOut.IsAvailable {
					continue
				}
				if !disableCheckInEnforcement && !checkinAuthorized(req, checkOut) {
					continue
				}
				toCheckIn = append(toCheckIn, setServiceAccountID)
			}
			if len(toCheckIn) > 1 {
				return logical.ErrorResponse(`when multiple service accounts are checked out, the "service_account_ids" to check in must be provided`), nil
			}
		} else {
			for _, serviceAccountID := range serviceAccountIDs {
				checkOut, err := b.LoadCheckOut(ctx, req.Storage, serviceAccountID)
				if err != nil {
					return nil, err
				}
				// First guard that they should be able to do anything at all
				if !checkOut.IsAvailable && !disableCheckInEnforcement && !checkinAuthorized(req, checkOut) {
					return logical.ErrorResponse("%q can't be checked in because it wasn't checked out by the caller", serviceAccountID), nil
				}
				if checkOut.IsAvailable {
					continue
				}
				toCheckIn = append(toCheckIn, serviceAccountID)
			}
		}

		// Check in the service accounts
		for _, serviceAccountID := range toCheckIn {
			if err := b.CheckIn(ctx, req.Storage, serviceAccountID, set.ProjectID); err != nil {
				return nil, err
			}
			b.emitCheckinMetric(setName)
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"check_ins": toCheckIn,
			},
		}, nil
	}
}

// pathSetStatus creates a framework path for viewing checkout status
func (b *backend) pathSetStatus() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.TrimSuffix(libraryPrefix, "/") + framework.GenericNameRegex("name") + "/status$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the set.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.operationSetStatus,
					Summary:  "Check the status of the service accounts in a library set.",
				},
			},
			HelpSynopsis:    "Check the status of the service accounts in a library.",
			HelpDescription: "Check the status of the service accounts in a library.",
		},
	}
}

// operationSetStatus creates a callback for viewing checkout status
func (b *backend) operationSetStatus(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	setName := fieldData.Get("name").(string)
	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.RLock()
	defer lock.RUnlock()

	// Get the set
	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse(fmt.Sprintf(`%q doesn't exist`, setName)), nil
	}

	// Build status response
	respData := make(map[string]interface{})

	for _, serviceAccountID := range set.ServiceAccountIDs {
		checkOut, err := b.LoadCheckOut(ctx, req.Storage, serviceAccountID)
		if err != nil {
			return nil, err
		}

		status := map[string]interface{}{
			"available": checkOut.IsAvailable,
		}
		if checkOut.IsAvailable {
			// Only include availability status for available accounts
			respData[serviceAccountID] = status
			continue
		}

		// Include borrower info for checked out accounts
		if checkOut.BorrowerClientToken != "" {
			status["borrower_client_token"] = checkOut.BorrowerClientToken
		}
		if checkOut.BorrowerEntityID != "" {
			status["borrower_entity_id"] = checkOut.BorrowerEntityID
		}
		if !checkOut.CheckOutTime.IsZero() {
			status["check_out_time"] = checkOut.CheckOutTime.Format(time.RFC3339)
		}
		respData[serviceAccountID] = status
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

// renewCheckOut handles renewal requests for checkout credentials
func (b *backend) renewCheckOut(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	setName := req.Secret.InternalData["set_name"].(string)
	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.RLock()
	defer lock.RUnlock()

	// Get the set
	set, err := readSet(ctx, req.Storage, setName)
	if err != nil {
		return nil, err
	}
	if set == nil {
		return logical.ErrorResponse(fmt.Sprintf(`%q doesn't exist`, setName)), nil
	}

	// Get service account status
	serviceAccountID := req.Secret.InternalData["service_account_id"].(string)
	checkOut, err := b.LoadCheckOut(ctx, req.Storage, serviceAccountID)
	if err != nil {
		return nil, err
	}
	if checkOut.IsAvailable {
		// The service account has been checked in
		return logical.ErrorResponse(fmt.Sprintf("%s is already checked in, please call check-out to regain it", serviceAccountID)), nil
	}

	// Create response with the same TTL and MaxTTL
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = set.TTL
	resp.Secret.MaxTTL = set.MaxTTL
	return resp, nil
}

// endCheckOut handles checkout credential revocation
func (b *backend) endCheckOut(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// Defensive check for project_id
	projectIDVal, ok := req.Secret.InternalData["project_id"]
	if !ok || projectIDVal == nil {
		return nil, fmt.Errorf("project_id missing in InternalData")
	}
	projectID, ok := projectIDVal.(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project_id in InternalData is not a valid string")
	}
	// Defensive check for set_name
	setNameVal, ok := req.Secret.InternalData["set_name"]
	if !ok || setNameVal == nil {
		return nil, fmt.Errorf("set_name missing in InternalData")
	}
	setName, ok := setNameVal.(string)
	if !ok || setName == "" {
		return nil, fmt.Errorf("set_name in InternalData is not a valid string")
	}
	// Defensive check for service_account_id
	serviceAccountIDVal, ok := req.Secret.InternalData["service_account_id"]
	if !ok || serviceAccountIDVal == nil {
		return nil, fmt.Errorf("service_account_id missing in InternalData")
	}
	serviceAccountID, ok := serviceAccountIDVal.(string)
	if !ok || serviceAccountID == "" {
		return nil, fmt.Errorf("service_account_id in InternalData is not a valid string")
	}

	lock := locksutil.LockForKey(b.checkOutLocks, setName)
	lock.Lock()
	defer lock.Unlock()

	// Check in the service account
	if err := b.CheckIn(ctx, req.Storage, serviceAccountID, projectID); err != nil {
		return nil, err
	}

	return nil, nil
}

// emitCheckoutMetric emits a metric for service account check-out
func (b *backend) emitCheckoutMetric(setName string) {
	IncrCounterWithLabels(context.Background(), []string{"openai", "checkout", "checkout"}, 1, []Label{{Name: "set", Value: setName}})
}

// emitCheckinMetric emits a metric for service account check-in
func (b *backend) emitCheckinMetric(setName string) {
	IncrCounterWithLabels(context.Background(), []string{"openai", "checkout", "checkin"}, 1, []Label{{Name: "set", Value: setName}})
}

// emitUnavailableMetric emits a metric when no service accounts are available
func (b *backend) emitUnavailableMetric(setName string) {
	IncrCounterWithLabels(context.Background(), []string{"openai", "checkout", "unavailable"}, 1, []Label{{Name: "set", Value: setName}})
}
