#!/bin/bash

# Run all unit tests
echo "=== Running unit tests ==="
go test -v ./...
UNIT_TEST_RESULT=$?
# Check if unit tests passed
if [ $UNIT_TEST_RESULT -ne 0 ]; then
    echo "❌ Unit tests failed"
    exit $UNIT_TEST_RESULT
else
    echo "✅ Unit tests passed"
fi
# Run integration tests if the --integration flag is provided
# Check if we should run integration tests
if [ "$1" == "--integration" ]; then
    echo -e "\n=== Running integration tests ==="
    cat <<'EOF'

These tests run against the live OpenAI API and create real (short-lived)
service accounts in a test project. You will need three values:

  1. Admin API Key   (OPENAI_ADMIN_API_KEY)
  2. Organization ID (OPENAI_ORG_ID, starts with "org-")
  3. Test Project ID (OPENAI_TEST_PROJECT_ID, starts with "proj_")

Tip: export these as environment variables to skip the prompts next time.

EOF

    # Prompt for any values that were not provided via the environment.
    if [ -z "$OPENAI_ADMIN_API_KEY" ]; then
        echo "→ Create an Admin API Key: https://platform.openai.com/settings/organization/admin-keys"
        read -r -s -p "  Enter your OpenAI Admin API Key: " OPENAI_ADMIN_API_KEY
        echo
    fi
    if [ -z "$OPENAI_ORG_ID" ]; then
        echo "→ Find your Organization ID: https://platform.openai.com/settings/organization/general"
        read -r -p "  Enter your OpenAI Organization ID: " OPENAI_ORG_ID
    fi
    if [ -z "$OPENAI_TEST_PROJECT_ID" ]; then
        echo "→ Find a Project ID: https://platform.openai.com/settings/organization/projects"
        read -r -p "  Enter your OpenAI Test Project ID: " OPENAI_TEST_PROJECT_ID
    fi

    # Validate that every required value is present, reporting each one that is missing.
    MISSING_VARS=()
    [ -z "$OPENAI_ADMIN_API_KEY" ] && MISSING_VARS+=("OPENAI_ADMIN_API_KEY")
    [ -z "$OPENAI_ORG_ID" ] && MISSING_VARS+=("OPENAI_ORG_ID")
    [ -z "$OPENAI_TEST_PROJECT_ID" ] && MISSING_VARS+=("OPENAI_TEST_PROJECT_ID")
    if [ ${#MISSING_VARS[@]} -ne 0 ]; then
        echo "❌ ERROR: Missing required value(s): ${MISSING_VARS[*]}"
        echo "   Set them as environment variables or enter them when prompted, then re-run."
        exit 1
    fi

    # Catch common copy/paste mistakes early with friendly format warnings.
    case "$OPENAI_ADMIN_API_KEY" in
        sk-admin*) ;;
        *) echo "⚠️  Warning: OPENAI_ADMIN_API_KEY usually starts with 'sk-admin'. Did you paste an Admin API Key?" ;;
    esac
    case "$OPENAI_ORG_ID" in
        org-*) ;;
        *) echo "⚠️  Warning: OPENAI_ORG_ID usually starts with 'org-'. Got: $OPENAI_ORG_ID" ;;
    esac
    case "$OPENAI_TEST_PROJECT_ID" in
        proj_*) ;;
        *) echo "⚠️  Warning: OPENAI_TEST_PROJECT_ID usually starts with 'proj_'. Got: $OPENAI_TEST_PROJECT_ID" ;;
    esac
    echo "✅ Configuration collected. Starting Vault and running integration tests..."
    
    export VAULT_ADDR=http://127.0.0.1:8200
    export VAULT_TOKEN=root
    vault server -dev -dev-root-token-id=root \
        -dev-plugin-dir=./bin -log-level=debug \
        -dev-listen-address=127.0.0.1:8200 > vault.log 2>&1 &
    VAULT_PID=$!
    trap 'kill $VAULT_PID 2>/dev/null' EXIT
    # Wait for Vault to be ready
    for i in {1..15}; do
        if vault status > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    if ! vault status > /dev/null 2>&1; then
        echo "❌ ERROR: Vault server failed to start. See vault.log for details."
        cat vault.log
        exit 1
    fi
    # Check plugin binary exists
    if [ ! -f ./bin/vault-plugin-secrets-openai ]; then
        echo "❌ ERROR: Plugin binary not found at ./bin/vault-plugin-secrets-openai"
        exit 1
    fi
    # Register and enable the plugin
    vault secrets enable -path=openai -plugin-name=vault-plugin-secrets-openai plugin
    # Get the admin API key ID using the OpenAI API (match prefix and suffix)
    KEY_PREFIX="${OPENAI_ADMIN_API_KEY:0:8}"
    KEY_SUFFIX="${OPENAI_ADMIN_API_KEY: -4}"
    ADMIN_KEYS_RESPONSE=$(curl -s https://api.openai.com/v1/organization/admin_api_keys \
      -H "Authorization: Bearer $OPENAI_ADMIN_API_KEY" \
      -H "Content-Type: application/json")
    # If the response has no .data array, the API returned an error (bad key,
    # insufficient permissions, etc.). Surface that message instead of a generic one.
    if ! echo "$ADMIN_KEYS_RESPONSE" | jq -e '.data' > /dev/null 2>&1; then
      echo "❌ ERROR: OpenAI API did not return an admin key list."
      echo "   Check that OPENAI_ADMIN_API_KEY is a valid Admin API Key with organization access."
      echo "   API response:"
      echo "$ADMIN_KEYS_RESPONSE" | jq '.' 2>/dev/null || echo "$ADMIN_KEYS_RESPONSE"
      exit 1
    fi
    ADMIN_API_KEY_ID=$(echo "$ADMIN_KEYS_RESPONSE" | \
      jq -r --arg prefix "$KEY_PREFIX" --arg suffix "$KEY_SUFFIX" \
        '.data[] | select(.redacted_value | startswith($prefix) and endswith($suffix)) | .id' | head -n1)
    if [ -z "$ADMIN_API_KEY_ID" ]; then
      echo "❌ ERROR: Could not find an admin API key matching the provided OPENAI_ADMIN_API_KEY."
      echo "   The key is valid but its ID was not found in the organization's admin key list."
      exit 1
    fi
    # Configure the plugin with both admin_api_key and admin_api_key_id
    vault write openai/config admin_api_key="$OPENAI_ADMIN_API_KEY" admin_api_key_id="$ADMIN_API_KEY_ID" organization_id="$OPENAI_ORG_ID" rotation_period=5s
    # Rotate the OpenAI admin API key (simulate rotation)
    vault read openai/config
    echo ".: Check the admin key is being rotated here: https://platform.openai.com/settings/organization/admin-keys"

    # Echo each command below so the output shows exactly what ran.
    set -x
    sleep 20
 
    vault path-help openai
    vault path-help openai/config
    vault path-help openai/config/rotate
    echo "Forcing rotation of OpenAI admin API key..."
    vault write -force openai/config/rotate

    # Create a test role
    vault path-help openai/roles/
    vault write openai/roles/test-role project_id="$OPENAI_TEST_PROJECT_ID" \
        service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
        ttl=5s max_ttl=24h
    # Read the role to verify it was created
    vault read openai/roles/test-role

    # Issue dynamic credentials
    vault path-help openai/creds/test-role

    echo ".: Check the project keys are being created here: https://platform.openai.com/api-keys"
    for i in 1 2 3; do
        vault read openai/creds/test-role
        [ "$i" -lt 3 ] && sleep 7
    done
    # Stop echoing commands.
    set +x
fi


if [ "$1" == "--integration" ]; then
    if [ $? -ne 0 ]; then
        echo -e "\n❌ Integration tests failed"
        exit 1
    fi
fi

echo -e "\n✅ All tests passed"
exit 0
