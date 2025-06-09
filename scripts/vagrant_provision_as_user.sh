#!/bin/bash
# Helper script to test the vault-plugin-secrets-openai plugin inside the Vagrant VM
set -e

cd $HOME/vault-plugin-secrets-openai

# Install Docker rootless mode for vagrant user
mkdir -p /home/vagrant/.config/docker/
systemctl --user start dbus

export PATH=/usr/bin:$PATH
export XDG_RUNTIME_DIR=/run/user/$(id -u)
dockerd-rootless-setuptool.sh install
docker context use rootless

echo 'export PATH=/usr/bin:$PATH' >> ~/.bashrc
echo 'export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock' >> ~/.bashrc

mkdir -p /home/vagrant/.config/docker/

# Use the system-wide runsc binary for rootless Docker
cat <<EOF > /home/vagrant/.config/docker/daemon.json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": [
        "--host-uds=all",
        "--network=host"
      ]
    }
  }
}
EOF

systemctl --user restart docker
sleep 3

# Test runsc runtime with hello-world, fallback to /usr/local/bin/runsc if needed
echo "Testing runsc runtime with hello-world..."
docker pull hello-world
if ! docker run --rm --runtime=runsc hello-world; then
  echo "runsc not found at /usr/bin/runsc, trying /usr/local/bin/runsc..."
  cat <<EOF > /home/vagrant/.config/docker/daemon.json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--host-uds=all",
        "--ignore-cgroups",
        "--network=host"
      ]
    }
  }
}
EOF
  systemctl --user restart docker
  sleep 3
  docker run --rm --runtime=runsc hello-world || echo "runsc runtime test failed. Please check installation."
fi


# Print Docker info for verification
docker info || true

# Setup environment variables for the vagrant user
cat <<EOF >> /home/vagrant/.bashrc
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
EOF

source /home/vagrant/.bashrc

echo "Starting Vault server..."
# Set environment variables for vault
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
export VAULT_LOG_LEVEL=debug

# Start Vault in dev mode in the background
nohup vault server -dev -dev-root-token-id=root > vault.log 2>&1 &

echo "Building plugin Docker image..."
make build-release
make release VERSION=1.0.0

echo "Getting Docker image SHA256..."
PLUGIN_SHA256=$(docker images --no-trunc --format="{{ .ID }}" vault-plugin-secrets-openai:1.0.0 | cut -d: -f2)

echo "Registering plugin with Vault..."
vault plugin runtime register -type=container -rootless=true -oci_runtime=runsc runsc
# Register the plugin with Vault
vault plugin register \
  -sha256="$PLUGIN_SHA256" \
  -oci_image="vault-plugin-secrets-openai" \
  -runtime="runsc" \
  -version="1.0.0" \
  secret vault-plugin-secrets-openai

echo "Enabling plugin..."
vault secrets enable -path=openai -plugin-name=vault-plugin-secrets-openai plugin

echo "Plugin enabled successfully!"

# Optionally configure plugin if environment variables are set
if [[ ! -z "$OPENAI_ADMIN_API_KEY" ]] && [[ ! -z "$OPENAI_ORG_ID" ]]; then
  echo "Configuring plugin with provided OpenAI credentials..."
  vault write openai/config \
    admin_api_key="$OPENAI_ADMIN_API_KEY" \
    admin_api_key_id="$OPENAI_ADMIN_API_KEY_ID" \
    organization_id="$OPENAI_ORG_ID"

  vault write openai/roles/test-role \
    project="test-project" \
    service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
    ttl=1h \
    max_ttl=24h

  echo "Testing dynamic credentials..."
  vault read openai/creds/test-role
else
  echo "The next step is to configure it with your OpenAI credentials:"
  echo "export OPENAI_ADMIN_API_KEY=your-key"
  echo "export OPENAI_ADMIN_API_KEY_ID=your-key-id"
  echo "export OPENAI_ORG_ID=your-org"
  echo "vault write openai/config admin_api_key=\$OPENAI_ADMIN_API_KEY admin_api_key_id=\$OPENAI_ADMIN_API_KEY_ID organization_id=\$OPENAI_ORG_ID"
fi

echo ""
echo "For full test commands, see vault_container_plugin_integration_test.sh"
echo ""
echo "To connect to Vault UI, visit http://localhost:8200 in your browser"
echo "Use 'root' as the token"
