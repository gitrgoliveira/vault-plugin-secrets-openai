# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  
  # Forward Vault's API port to the host
  config.vm.network "forwarded_port", guest: 8200, host: 8200

  # Shared folder configuration
  config.vm.synced_folder ".", "/vagrant", type: "rsync"
  
  # Provider-specific configuration
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "8192"  # Allocate 8GB of RAM
    vb.cpus = 6
    vb.name = "vault-plugin-openai-test"
  end

  # VM provisioning
  config.vm.provision "shell", inline: <<-SHELL
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
    apt-get install -y vault docker-ce docker-ce-cli containerd.io make jq unzip golang-go git

    # Enable docker socket access for vagrant user
    usermod -aG docker vagrant
    systemctl enable docker
    systemctl start docker

    # Install gVisor/runsc for containerized plugins
    # From: https://gvisor.dev/docs/user_guide/install/
    (
      set -e
      URL=https://storage.googleapis.com/gvisor/releases/release/latest
      wget ${URL}/runsc ${URL}/runsc.sha512 ${URL}/containerd-shim-runsc-v1 ${URL}/containerd-shim-runsc-v1.sha512
      sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512
      rm -f *.sha512
      chmod a+rx runsc containerd-shim-runsc-v1
      sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin
    )

    # Configure Docker to use gVisor/runsc runtime
    cat <<EOF | sudo tee /etc/docker/daemon.json
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
    systemctl restart docker

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
  SHELL

  # Helper script to set up and test the plugin
  config.vm.provision "shell", path: "scripts/provision_helper.sh", privileged: false
end
