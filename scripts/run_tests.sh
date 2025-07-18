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
    # Prompt for OpenAI admin key and org ID
    if [ -z "$OPENAI_ADMIN_API_KEY" ]; then
        read -s -p "Enter your OpenAI Admin API Key: " OPENAI_ADMIN_API_KEY
        echo
    fi
    if [ -z "$OPENAI_ORG_ID" ]; then
        read -p "Enter your OpenAI Organization ID: " OPENAI_ORG_ID
    fi
    if [ -z "$OPENAI_TEST_PROJECT_ID" ]; then
        read -p "Enter your OpenAI Test Project ID: " OPENAI_TEST_PROJECT_ID
    fi
    # Check if required environment variables are set
    if [ -z "$OPENAI_ADMIN_API_KEY" ] || [ -z "$OPENAI_ORG_ID" ] || [ -z "$OPENAI_TEST_PROJECT_ID" ]; then
        echo "❌ ERROR: OPENAI_ADMIN_API_KEY, OPENAI_ORG_ID, and OPENAI_TEST_PROJECT_ID are required for integration tests."
        exit 1
    fi
    
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
    ADMIN_API_KEY_ID=$(curl -s https://api.openai.com/v1/organization/admin_api_keys \
      -H "Authorization: Bearer $OPENAI_ADMIN_API_KEY" \
      -H "Content-Type: application/json" | \
      jq -r --arg prefix "$KEY_PREFIX" --arg suffix "$KEY_SUFFIX" \
        '.data[] | select(.redacted_value | startswith($prefix) and endswith($suffix)) | .id' | head -n1)
    if [ -z "$ADMIN_API_KEY_ID" ]; then
      echo "❌ ERROR: Could not determine admin API key ID from OpenAI API."
      exit 1
    fi
    # Configure the plugin with both admin_api_key and admin_api_key_id
    vault write openai/config admin_api_key="$OPENAI_ADMIN_API_KEY" admin_api_key_id="$ADMIN_API_KEY_ID" organization_id="$OPENAI_ORG_ID" rotation_period=5s
    # Rotate the OpenAI admin API key (simulate rotation)
    vault read openai/config
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
    vault read openai/creds/test-role

    sleep 15
fi


if [ "$1" == "--integration" ]; then
    if [ $? -ne 0 ]; then
        echo -e "\n❌ Integration tests failed"
        exit 1
    fi
fi

echo -e "\n✅ All tests passed"
exit 0
