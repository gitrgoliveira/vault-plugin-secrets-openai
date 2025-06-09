#!/bin/bash
# Helper script to test the vault-plugin-secrets-openai plugin inside the Vagrant VM
set -e

# Ensure Go is in PATH for all shells (non-interactive and interactive)
export PATH=/usr/local/go/bin:$PATH
if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
  echo 'export PATH=/usr/local/go/bin:$PATH' | sudo tee /etc/profile.d/go.sh
fi
source /etc/profile.d/go.sh

go version || { echo "Go is not installed or not in PATH. Aborting."; exit 1; }

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
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

mkdir -p /home/vagrant/.config/docker/

# Use the system-wide runsc binary for rootless Docker, with ignore-cgroups and cgroup-parent
cat <<EOF > /home/vagrant/.config/docker/daemon.json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": [
        "--host-uds=all",
        "--ignore-cgroups",
        "--network=host"
      ]
    }
  },
  "cgroup-parent": "/user.slice"
}
EOF

systemctl --user restart docker
sleep 3

# Test runsc runtime with hello-world, fallback to runc if needed

echo "Testing runsc runtime with hello-world..."
docker pull hello-world
if ! docker run --rm --runtime=runsc hello-world; then
  echo "[WARN] runsc runtime failed in rootless Docker. This is a known limitation (systemd/cgroup error). Falling back to default runtime (runc) for plugin build and registration.\nSee: https://github.com/google/gvisor/issues/6656"
  export VAULT_PLUGIN_RUNTIME=runc
else
  export VAULT_PLUGIN_RUNTIME=runsc
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

# Set DOCKER_HOST for rootless Docker
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock
systemctl stop vault || true
sudo systemctl stop vault || true
sudo killall vault || true
# Start Vault in dev mode in the background with correct DOCKER_HOST
nohup env DOCKER_HOST=$DOCKER_HOST vault server -dev -dev-root-token-id=root > vault.log 2>&1 &

# Ensure DOCKER_HOST is set for Vault CLI commands
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock

# Build and register plugin using the selected runtime
echo "Building plugin Docker image..."
make build-release-verbose
make release VERSION=1.0.0

echo "Getting Docker image SHA256..."
PLUGIN_SHA256=$(docker images --no-trunc --format="{{ .ID }}" vault-plugin-secrets-openai:1.0.0 | cut -d: -f2)

echo "Registering plugin with Vault..."
vault plugin runtime register -type=container -rootless=true -oci_runtime=$VAULT_PLUGIN_RUNTIME $VAULT_PLUGIN_RUNTIME
# Register the plugin with Vault
vault plugin register \
  -sha256="$PLUGIN_SHA256" \
  -oci_image="vault-plugin-secrets-openai" \
  -runtime="$VAULT_PLUGIN_RUNTIME" \
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
