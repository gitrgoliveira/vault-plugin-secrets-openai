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

# Upgrade Go to 1.24.6 if not already installed
GO_VERSION="1.24.6"
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

# Install staticcheck for Go code analysis
echo "Installing staticcheck..."
go install honnef.co/go/tools/cmd/staticcheck@latest
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> /home/vagrant/.bashrc

# Install rootless Docker dependencies
sudo apt-get install -y uidmap dbus-user-session

# Install gVisor/runsc for containerized plugins if not already installed
if ! command -v runsc >/dev/null 2>&1; then
  # Add the gVisor repository key (fix for gpg --no-tty and curl temp file)
  curl -fsSL https://gvisor.dev/archive.key -o /tmp/gvisor-archive.key
  sudo gpg --batch --yes --no-tty --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg /tmp/gvisor-archive.key
  # Add the gVisor APT repository
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
  sudo apt-get update
  sudo apt-get install -y runsc
fi


# Copy project to home directory for easier access
mkdir -p /home/vagrant/vault-plugin-secrets-openai
cp -r /vagrant/* /home/vagrant/vault-plugin-secrets-openai/
chown -R vagrant:vagrant /home/vagrant/vault-plugin-secrets-openai

echo "Setup complete! Log in with 'vagrant ssh' and run: cd vault-plugin-secrets-openai"
