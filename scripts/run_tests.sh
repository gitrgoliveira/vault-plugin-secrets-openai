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
        echo "❌ ERROR: Vault server failed to start. See vault-dev.log for details."
        cat vault-dev.log
        exit 1
    fi
    # Check plugin binary exists
    if [ ! -f ./bin/vault-plugin-secrets-openai ]; then
        echo "❌ ERROR: Plugin binary not found at ./bin/vault-plugin-secrets-openai"
        exit 1
    fi
    # Register and enable the plugin
    vault secrets enable -path=openai -plugin-name=vault-plugin-secrets-openai plugin
    # Configure the plugin
    vault write openai/config admin_api_key="$OPENAI_ADMIN_API_KEY" organization_id="$OPENAI_ORG_ID"
    # Register a test project
    vault write openai/project/test-project project_id="$OPENAI_TEST_PROJECT_ID" description="Test Project"
    # Create a test role
    vault write openai/roles/test-role project="test-project" service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" service_account_description="Test service account" ttl=1h max_ttl=24h
    # Issue dynamic credentials
    vault read openai/creds/test-role
fi


if [ "$1" == "--integration" ]; then
    if [ $? -ne 0 ]; then
        echo -e "\n❌ Integration tests failed"
        exit 1
    fi
fi

echo -e "\n✅ All tests passed"
exit 0
