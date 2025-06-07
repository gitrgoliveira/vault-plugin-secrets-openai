#!/bin/bash
set -e

# Add HashiCorp repositories
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"

# Add Docker repository
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# Update and install dependencies
apt-get update
apt-get install -y make \
    apt-transport-https \
    ca-certificates 

apt-get install -y vault docker-ce docker-ce-cli containerd.io golang-go 

# Upgrade Go to 1.24.3 if not already installed
GO_VERSION="1.24.3"
if ! go version 2>/dev/null | grep -q "go$GO_VERSION"; then
  echo "Upgrading Go to $GO_VERSION..."
  wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
  sudo rm -rf $(which go)
  sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
  rm go${GO_VERSION}.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.bashrc
fi
source /home/vagrant/.bashrc
go version

# Install rootless Docker dependencies
sudo apt-get install -y uidmap dbus-user-session

# Install gVisor/runsc for containerized plugins if not already installed
if ! command -v runsc >/dev/null 2>&1; then
  (
    set -e
    URL=https://storage.googleapis.com/gvisor/releases/release/latest
    wget ${URL}/runsc ${URL}/runsc.sha512 ${URL}/containerd-shim-runsc-v1 ${URL}/containerd-shim-runsc-v1.sha512
    sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512
    rm -f *.sha512
    chmod a+rx runsc containerd-shim-runsc-v1
    sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin
  )
fi

# Install Docker rootless mode for vagrant user
sudo -u vagrant -i bash <<'EOV'

  mkdir -p /home/vagrant/.config/docker/
  systemctl --user start dbus

  export PATH=/usr/bin:$PATH
  export XDG_RUNTIME_DIR=/run/user/$(id -u)
  dockerd-rootless-setuptool.sh install
  docker context use rootless

  echo 'export PATH=/usr/bin:$PATH' >> ~/.bashrc
  echo 'export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock' >> ~/.bashrc

  mkdir -p /home/vagrant/.config/docker/
  cat <<EOF | sudo tee /home/vagrant/.config/docker/daemon.json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--host-uds=all"
      ]
    }
  }
}
EOF

  systemctl --user restart docker

EOV

# Print Docker info for verification
sudo -u vagrant -i bash -c 'docker info || true'

# Setup environment variables for the vagrant user
cat <<EOF >> /home/vagrant/.bashrc
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
EOF

# Copy project to home directory for easier access
mkdir -p /home/vagrant/vault-plugin-secrets-openai
cp -r /vagrant/* /home/vagrant/vault-plugin-secrets-openai/
chown -R vagrant:vagrant /home/vagrant/vault-plugin-secrets-openai

echo "Setup complete! Log in with 'vagrant ssh' and run: cd vault-plugin-secrets-openai"
