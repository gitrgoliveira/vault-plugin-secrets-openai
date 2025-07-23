#!/bin/bash

# Test Prometheus metrics by starting Vault, performing operations, and checking metrics output
#
# Usage:
#   ./test_prometheus_metrics.sh                 # Interactive mode (prompts for credentials)
#   ./test_prometheus_metrics.sh --no-prompts    # Non-interactive mode (uses dummy credentials)
#   ./test_prometheus_metrics.sh --ci            # CI mode (same as --no-prompts)
#
# Environment Variables:
#   OPENAI_ADMIN_API_KEY     - OpenAI Admin API key for real testing
#   OPENAI_ORG_ID           - OpenAI Organization ID
#   OPENAI_TEST_PROJECT_ID  - OpenAI Project ID for testing (optional)
#
set -e

# Parse command line arguments
SKIP_PROMPTS=false
if [[ "$1" == "--no-prompts" || "$1" == "--ci" ]]; then
    SKIP_PROMPTS=true
elif [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Test Prometheus metrics integration with Vault"
    echo ""
    echo "Usage:"
    echo "  $0                 Interactive mode (prompts for credentials)"
    echo "  $0 --no-prompts    Non-interactive mode (uses dummy credentials)"
    echo "  $0 --ci            CI mode (same as --no-prompts)"
    echo "  $0 --help          Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  OPENAI_ADMIN_API_KEY     OpenAI Admin API key for real testing"
    echo "  OPENAI_ORG_ID           OpenAI Organization ID"
    echo "  OPENAI_TEST_PROJECT_ID  OpenAI Project ID for testing (optional)"
    exit 0
fi

# Colors for output
COLOR_RESET='\033[0m'
COLOR_BOLD='\033[1m'
COLOR_GREEN='\033[32m'
COLOR_YELLOW='\033[33m'
COLOR_RED='\033[31m'
COLOR_BLUE='\033[34m'

echo -e "${COLOR_BOLD}=== Prometheus Metrics Integration Test ===${COLOR_RESET}"

# Function to prompt for credentials
prompt_for_credentials() {
    echo -e "\n${COLOR_BOLD}OpenAI Credentials Setup${COLOR_RESET}"
    echo -e "${COLOR_BLUE}You can test the metrics with real OpenAI credentials for a complete test,${COLOR_RESET}"
    echo -e "${COLOR_BLUE}or use dummy credentials to test API error metrics.${COLOR_RESET}"
    echo ""
    
    read -p "$(echo -e "${COLOR_YELLOW}Do you want to use real OpenAI credentials? (y/N): ${COLOR_RESET}")" use_real
    
    if [[ "$use_real" =~ ^[Yy]$ ]]; then
        if [[ -z "$OPENAI_ADMIN_API_KEY" ]]; then
            read -s -p "$(echo -e "${COLOR_BLUE}Enter your OpenAI Admin API Key: ${COLOR_RESET}")" OPENAI_ADMIN_API_KEY
            echo ""
        fi
        
        if [[ -z "$OPENAI_ORG_ID" ]]; then
            read -p "$(echo -e "${COLOR_BLUE}Enter your OpenAI Organization ID: ${COLOR_RESET}")" OPENAI_ORG_ID
        fi
        
        if [[ -z "$OPENAI_TEST_PROJECT_ID" ]]; then
            read -p "$(echo -e "${COLOR_BLUE}Enter your OpenAI Test Project ID (optional): ${COLOR_RESET}")" OPENAI_TEST_PROJECT_ID
        fi
        
        if [[ -n "$OPENAI_ADMIN_API_KEY" && -n "$OPENAI_ORG_ID" ]]; then
            return 0  # Use real credentials
        else
            echo -e "${COLOR_YELLOW}Incomplete credentials provided. Falling back to dummy credentials.${COLOR_RESET}"
            return 1  # Use dummy credentials
        fi
    else
        echo -e "${COLOR_YELLOW}Using dummy credentials - API errors expected for testing error metrics.${COLOR_RESET}"
        return 1  # Use dummy credentials
    fi
}

# Check if we should use real credentials
USE_REAL_CREDENTIALS=false
if [[ -n "$OPENAI_ADMIN_API_KEY" && -n "$OPENAI_ORG_ID" ]]; then
    echo -e "${COLOR_BLUE}Real OpenAI credentials detected from environment - will test with actual API calls${COLOR_RESET}"
    USE_REAL_CREDENTIALS=true
elif [[ "$SKIP_PROMPTS" == "true" ]]; then
    echo -e "${COLOR_YELLOW}Running in non-interactive mode - using dummy credentials (API errors expected)${COLOR_RESET}"
    USE_REAL_CREDENTIALS=false
else
    if prompt_for_credentials; then
        echo -e "${COLOR_GREEN}✓ Real OpenAI credentials provided - will test with actual API calls${COLOR_RESET}"
        USE_REAL_CREDENTIALS=true
        export OPENAI_ADMIN_API_KEY OPENAI_ORG_ID OPENAI_TEST_PROJECT_ID
    else
        echo -e "${COLOR_YELLOW}Using dummy credentials for testing (API errors expected)${COLOR_RESET}"
        USE_REAL_CREDENTIALS=false
    fi
fi

# Configuration
VAULT_ADDR="http://127.0.0.1:8201"
VAULT_TOKEN="root"
PLUGIN_NAME="vault-plugin-secrets-openai"
PLUGIN_PATH="openai"
VAULT_LOG_FILE="vault_metrics_test.log"
METRICS_FILE="metrics_output.txt"

# Cleanup function
cleanup() {
    echo -e "\n${COLOR_YELLOW}Cleaning up...${COLOR_RESET}"
    if [[ -n "$VAULT_PID" ]]; then
        kill $VAULT_PID 2>/dev/null || true
        wait $VAULT_PID 2>/dev/null || true
    fi
    rm -f "$VAULT_LOG_FILE" "$METRICS_FILE" "vault_metrics_config.hcl"
}

trap cleanup EXIT

# Check prerequisites
echo -e "${COLOR_BLUE}Checking prerequisites...${COLOR_RESET}"

if ! command -v vault >/dev/null 2>&1; then
    echo -e "${COLOR_RED}❌ ERROR: vault command not found${COLOR_RESET}"
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo -e "${COLOR_RED}❌ ERROR: curl command not found${COLOR_RESET}"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo -e "${COLOR_RED}❌ ERROR: jq command not found${COLOR_RESET}"
    exit 1
fi

if [[ ! -f "./bin/$PLUGIN_NAME" ]]; then
    echo -e "${COLOR_RED}❌ ERROR: Plugin binary not found at ./bin/$PLUGIN_NAME${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Run 'make build' first${COLOR_RESET}"
    exit 1
fi

# Check if port 8201 is available, if not find an available port
VAULT_PORT=8201
while netstat -an 2>/dev/null | grep -q ":$VAULT_PORT.*LISTEN" || lsof -i :$VAULT_PORT >/dev/null 2>&1; do
    ((VAULT_PORT++))
    if [[ $VAULT_PORT -gt 8210 ]]; then
        echo -e "${COLOR_RED}❌ ERROR: Could not find available port between 8201-8210${COLOR_RESET}"
        exit 1
    fi
done

VAULT_ADDR="http://127.0.0.1:$VAULT_PORT"
echo -e "${COLOR_BLUE}Using Vault port: $VAULT_PORT${COLOR_RESET}"

echo -e "${COLOR_GREEN}✓ Prerequisites checked${COLOR_RESET}"

# Start Vault with telemetry enabled
echo -e "\n${COLOR_BLUE}Starting Vault with telemetry enabled...${COLOR_RESET}"

export VAULT_ADDR VAULT_TOKEN

# Create Vault config with telemetry
cat > vault_metrics_config.hcl << EOF
storage "inmem" {}

listener "tcp" {
  address = "127.0.0.1:$VAULT_PORT"
  tls_disable = true
}

telemetry {
  statsd_address = ""
  disable_hostname = true
  prometheus_retention_time = "30s"
}

plugin_directory = "./bin"
log_level = "INFO"
EOF

# Start Vault server
vault server -config=vault_metrics_config.hcl -dev -dev-root-token-id=root > "$VAULT_LOG_FILE" 2>&1 &
VAULT_PID=$!

echo -e "${COLOR_YELLOW}Vault PID: $VAULT_PID${COLOR_RESET}"

# Wait for Vault to be ready
echo -e "${COLOR_BLUE}Waiting for Vault to be ready...${COLOR_RESET}"
for i in {1..30}; do
    if vault status >/dev/null 2>&1; then
        break
    fi
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo -e "${COLOR_RED}❌ ERROR: Vault failed to start${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}Vault logs:${COLOR_RESET}"
        cat "$VAULT_LOG_FILE"
        exit 1
    fi
done

echo -e "${COLOR_GREEN}✓ Vault is ready${COLOR_RESET}"

# Register the plugin
echo -e "\n${COLOR_BLUE}Registering plugin...${COLOR_RESET}"
PLUGIN_SHA=$(shasum -a 256 "./bin/$PLUGIN_NAME" | awk '{print $1}')
vault plugin register -sha256="$PLUGIN_SHA" secret "$PLUGIN_NAME"
echo -e "${COLOR_GREEN}✓ Plugin registered${COLOR_RESET}"

# Enable the plugin
echo -e "\n${COLOR_BLUE}Enabling plugin at path '$PLUGIN_PATH'...${COLOR_RESET}"
vault secrets enable -path="$PLUGIN_PATH" "$PLUGIN_NAME"
echo -e "${COLOR_GREEN}✓ Plugin enabled${COLOR_RESET}"

# Function to get metrics and filter for openai
get_openai_metrics() {
    echo -e "\n${COLOR_BLUE}Fetching Prometheus metrics...${COLOR_RESET}"
    
    # Get metrics from Vault's metrics endpoint
    curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
        "$VAULT_ADDR/v1/sys/metrics?format=prometheus" > "$METRICS_FILE"
    
    if [[ ! -s "$METRICS_FILE" ]]; then
        echo -e "${COLOR_RED}❌ ERROR: Failed to fetch metrics or metrics file is empty${COLOR_RESET}"
        return 1
    fi
    
    # Filter for openai metrics
    openai_metrics=$(grep -i "openai\|vault.*route.*openai" "$METRICS_FILE" || true)
    
    if [[ -n "$openai_metrics" ]]; then
        echo -e "${COLOR_GREEN}✓ Found OpenAI metrics:${COLOR_RESET}"
        echo "$openai_metrics"
        return 0
    else
        echo -e "${COLOR_YELLOW}⚠ No OpenAI metrics found yet${COLOR_RESET}"
        return 1
    fi
}
# Test 1: Configure the plugin
echo -e "\n${COLOR_BOLD}=== Test 1: Plugin Configuration ===${COLOR_RESET}"
echo -e "${COLOR_BLUE}Configuring plugin with credentials...${COLOR_RESET}"

if [[ "$USE_REAL_CREDENTIALS" == "true" ]]; then
    # Use real credentials
    vault write "$PLUGIN_PATH/config" \
        admin_api_key="$OPENAI_ADMIN_API_KEY" \
        admin_api_key_id="key-test" \
        organization_id="$OPENAI_ORG_ID" || echo -e "${COLOR_YELLOW}⚠ Configuration failed${COLOR_RESET}"
else
    # Use dummy credentials that should trigger API errors
    vault write "$PLUGIN_PATH/config" \
        admin_api_key="sk-test-invalid-key-for-metrics-testing" \
        admin_api_key_id="key-test-invalid" \
        organization_id="org-test-invalid" || echo -e "${COLOR_YELLOW}⚠ Configuration failed (expected for test)${COLOR_RESET}"
fi

echo -e "${COLOR_GREEN}✓ Plugin configuration attempted${COLOR_RESET}"
get_openai_metrics
# Test 2: Create a role
echo -e "\n${COLOR_BOLD}=== Test 2: Role Creation ===${COLOR_RESET}"
echo -e "${COLOR_BLUE}Creating test role...${COLOR_RESET}"

if [[ "$USE_REAL_CREDENTIALS" == "true" && -n "$OPENAI_TEST_PROJECT_ID" ]]; then
    vault write "$PLUGIN_PATH/roles/metrics-test" \
        project_id="$OPENAI_TEST_PROJECT_ID" \
        service_account_name_template="vault-test-{{.RoleName}}-{{.RandomSuffix}}" \
        ttl=60s max_ttl=3600s || echo -e "${COLOR_YELLOW}⚠ Role creation failed${COLOR_RESET}"
else
    vault write "$PLUGIN_PATH/roles/metrics-test" \
        project_id="proj-test-invalid" \
        service_account_name_template="vault-test-{{.RoleName}}-{{.RandomSuffix}}" \
        ttl=60s max_ttl=3600s || echo -e "${COLOR_YELLOW}⚠ Role creation failed (expected for test)${COLOR_RESET}"
fi

echo -e "${COLOR_GREEN}✓ Role creation attempted${COLOR_RESET}"
get_openai_metrics
# Test 3: Try to generate credentials (this should trigger API error metrics)
echo -e "\n${COLOR_BOLD}=== Test 3: Credential Generation ===${COLOR_RESET}"
echo -e "${COLOR_BLUE}Attempting to generate credentials...${COLOR_RESET}"

vault read "$PLUGIN_PATH/creds/metrics-test" || echo -e "${COLOR_YELLOW}⚠ Credential generation failed (expected for test)${COLOR_RESET}"

echo -e "${COLOR_GREEN}✓ Credential generation attempted${COLOR_RESET}"

# Give Vault some time to process and emit metrics
echo -e "\n${COLOR_BLUE}Waiting for metrics to be processed...${COLOR_RESET}"
sleep 5

# Check for metrics
echo -e "\n${COLOR_BOLD}=== Metrics Verification ===${COLOR_RESET}"

# Try to get metrics multiple times as they might take time to appear
METRICS_FOUND=false
for attempt in {1..5}; do
    echo -e "${COLOR_BLUE}Attempt $attempt/5 to fetch metrics...${COLOR_RESET}"
    
    if get_openai_metrics; then
        METRICS_FOUND=true
        break
    fi
    
    if [[ $attempt -lt 5 ]]; then
        echo -e "${COLOR_YELLOW}Waiting 3 seconds before retry...${COLOR_RESET}"
        sleep 3
    fi
done

# Final verification
echo -e "\n${COLOR_BOLD}=== Final Results ===${COLOR_RESET}"

if [[ "$METRICS_FOUND" == "true" ]]; then
    echo -e "${COLOR_GREEN}✅ SUCCESS: OpenAI metrics are being emitted to Prometheus!${COLOR_RESET}"
    
    # Show detailed metrics analysis
    echo -e "\n${COLOR_BOLD}Detailed Metrics Analysis:${COLOR_RESET}"
    
    # Check for specific metric types
    creds_issued=$(grep -c "openai.*creds.*issued" "$METRICS_FILE" || echo "0")
    creds_revoked=$(grep -c "openai.*creds.*revoked" "$METRICS_FILE" || echo "0")
    api_errors=$(grep -c "openai.*api.*error" "$METRICS_FILE" || echo "0")
    route_metrics=$(grep -c "vault.*route.*openai" "$METRICS_FILE" || echo "0")
    
    echo -e "  ${COLOR_BLUE}Credential Issued Metrics:${COLOR_RESET} $creds_issued"
    echo -e "  ${COLOR_BLUE}Credential Revoked Metrics:${COLOR_RESET} $creds_revoked"
    echo -e "  ${COLOR_BLUE}API Error Metrics:${COLOR_RESET} $api_errors"
    echo -e "  ${COLOR_BLUE}Route Metrics:${COLOR_RESET} $route_metrics"
    
    # Show all openai metrics
    echo -e "\n${COLOR_BOLD}All OpenAI Metrics Found:${COLOR_RESET}"
    grep -i "openai" "$METRICS_FILE" | while IFS= read -r line; do
        echo -e "  ${COLOR_GREEN}$line${COLOR_RESET}"
    done
    
    exit_code=0
else
    echo -e "${COLOR_RED}❌ FAILURE: No OpenAI metrics found in Prometheus output${COLOR_RESET}"
    
    # Debug information
    echo -e "\n${COLOR_BOLD}Debug Information:${COLOR_RESET}"
    echo -e "${COLOR_BLUE}Total metrics found:${COLOR_RESET} $(wc -l < "$METRICS_FILE")"
    echo -e "${COLOR_BLUE}Sample metrics (first 10 lines):${COLOR_RESET}"
    head -10 "$METRICS_FILE" | while IFS= read -r line; do
        echo -e "  $line"
    done
    
    echo -e "\n${COLOR_BLUE}Vault logs (last 20 lines):${COLOR_RESET}"
    tail -20 "$VAULT_LOG_FILE"
    
    exit_code=1
fi

# Cleanup will be called by trap
echo -e "\n${COLOR_BLUE}Test completed.${COLOR_RESET}"
exit $exit_code
