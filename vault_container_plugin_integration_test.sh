#!/bin/bash
# vault_container_plugin_integration_test.sh
# Step-by-step script for Vault integration testing with the containerized OpenAI plugin
# Based on: https://developer.hashicorp.com/vault/docs/plugins/containerized-plugins/add-a-containerized-plugin

set -euo pipefail

# Check prerequisites
echo "🔍 Checking prerequisites..."
if [[ "$(uname)" != "Linux" ]]; then
  echo "⚠️  WARNING: Containerized plugins require Linux. This script may not work on $(uname)."
fi

# Check for runsc (gVisor)
if command -v runsc &>/dev/null; then
  echo "✓ gVisor (runsc) found"
  USE_RUNSC=true
else
  echo "⚠️  WARNING: gVisor (runsc) not found. Will try to use default Docker runtime."
  echo "   See: https://gvisor.dev/docs/user_guide/install/"
  USE_RUNSC=false
fi

# 1. Build the Docker image for the plugin
echo "[1/8] Building Docker image..."
docker build -t vault-plugin-secrets-openai:latest .

# Verify the image was built successfully
if [ $? -ne 0 ]; then
  echo "❌ ERROR: Failed to build Docker image"
  exit 1
fi

# 2. Start a Vault dev server with Docker socket access (for containerized plugins)
echo "[2/8] Starting Vault dev server..."

# Set environment variables for Vault
export VAULT_DEV_ROOT_TOKEN_ID=root
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_LOG_LEVEL=debug  # Set to debug to see more information about plugin operations

# Check for Docker socket access if running on Linux
if [[ $(uname) == "Linux" ]]; then
  if [ -S /var/run/docker.sock ]; then
    echo "✓ Docker socket found at /var/run/docker.sock"
    DOCKER_SOCKET_MOUNT="-v /var/run/docker.sock:/var/run/docker.sock"
  else
    echo "❌ ERROR: Docker socket not found at /var/run/docker.sock"
    echo "Vault needs access to the Docker socket to run containerized plugins."
    exit 1
  fi
else
  echo "⚠️  WARNING: Running on non-Linux OS. Containerized plugins require Linux for the Docker socket."
  DOCKER_SOCKET_MOUNT=""
fi

# Start Vault dev server
vault server -dev -dev-plugin-dir=$(pwd)/bin > vault-dev.log 2>&1 &
VAULT_PID=$!
echo "Vault server started with PID: $VAULT_PID"
echo "Waiting for Vault to initialize..."
sleep 5  # Give Vault more time to start up

# Verify Vault is running
if ! vault status > /dev/null 2>&1; then
  echo "❌ ERROR: Vault server failed to start properly. Check vault-dev.log for details."
  kill $VAULT_PID 2>/dev/null || true
  exit 1
fi
echo "✓ Vault server is running"

# 3. Register the containerized plugin with Vault
echo "[3/8] Registering containerized plugin..."

# Calculate SHA256 using method recommended in Vault docs
PLUGIN_SHA256=$(docker images --no-trunc --format="{{ .ID }}" vault-plugin-secrets-openai:latest | cut -d: -f2)
if [ -z "$PLUGIN_SHA256" ]; then
  echo "❌ ERROR: Failed to get SHA256 from Docker image"
  exit 1
fi
echo "Image SHA256: $PLUGIN_SHA256"

# If we found runsc earlier, we can register the plugin directly
if [ "$USE_RUNSC" = true ]; then
  echo "Using gVisor/runsc for container runtime"
  vault plugin register \
    -sha256="$PLUGIN_SHA256" \
    -oci_image="vault-plugin-secrets-openai:latest" \
    secret vault-plugin-secrets-openai
else
  # If runsc is not available, try to use the default runtime as a fallback
  echo "Using alternative runtime (registering with runc)"
  
  # Check if runtime is already registered
  if ! vault plugin runtime list | grep -q "docker-runc"; then
    echo "Registering alternative runtime 'docker-runc'"
    vault plugin runtime register \
      -oci_runtime=runc \
      -type=container docker-runc
  fi
  
  vault plugin register \
    -runtime=docker-runc \
    -sha256="$PLUGIN_SHA256" \
    -oci_image="vault-plugin-secrets-openai:latest" \
    secret vault-plugin-secrets-openai
fi

# 4. Enable the plugin secrets engine
echo "[4/8] Enabling plugin secrets engine..."
vault secrets enable -path=openai -plugin-name=vault-plugin-secrets-openai plugin

# 5. Configure the plugin (replace with your real OpenAI admin key and org ID)
echo "[5/8] Configuring plugin..."

# Check for environment variables or use defaults
OPENAI_ADMIN_API_KEY=${OPENAI_ADMIN_API_KEY:-"sk-admin-..."}
OPENAI_ORG_ID=${OPENAI_ORG_ID:-"org-123456"}

vault write openai/config \
  admin_api_key="$OPENAI_ADMIN_API_KEY" \
  organization_id="$OPENAI_ORG_ID"

# 6. Register a test OpenAI project
echo "[6/8] Registering test project..."
vault write openai/project/test-project \
  project_id="proj_test123" \
  description="Test Project"

# 7. Create a test role
echo "[7/8] Creating test role..."
vault write openai/roles/test-role \
  project="test-project" \
  service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
  service_account_description="Test service account" \
  ttl=1h \
  max_ttl=24h

# 8. Issue dynamic credentials
echo "[8/8] Issuing dynamic credentials..."
vault read openai/creds/test-role

# Cleanup function to ensure proper shutdown
cleanup() {
  echo "\nCleaning up..."
  if [[ ! -z "$VAULT_PID" ]]; then
    echo "Stopping Vault server (PID: $VAULT_PID)"
    kill $VAULT_PID 2>/dev/null || true
  fi
  echo "Done!"
}

# Register cleanup on exit
trap cleanup EXIT INT TERM

echo "\n✅ Integration test completed successfully!"
echo "You can now interact with your plugin at path 'openai/'"

# Troubleshooting guide
cat << EOF

📋 Troubleshooting Guide
-----------------------
If you encounter errors, here are some common issues and solutions:

1. "Invalid backend version error" or issues with runsc:
   - Ensure gVisor is installed: https://gvisor.dev/docs/user_guide/install/
   - Configure Docker to use runsc: https://gvisor.dev/docs/user_guide/quick_start/docker/

2. Docker permissions issues:
   - Ensure the user running Vault has permissions to access the Docker socket

3. For more help, see:
   https://developer.hashicorp.com/vault/docs/plugins/containerized-plugins/add-a-containerized-plugin#troubleshooting
EOF
