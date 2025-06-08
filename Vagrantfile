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
    vb.cpus = 8 # Allocate 8 CPUs
    vb.name = "vault-plugin-openai-test"
  end

  # VM provisioning
  config.vm.provision "shell", path: "scripts/vagrant_provision_root.sh", privileged: true

  # Helper script to set up and test the plugin
  config.vm.provision "shell", path: "scripts/provision_helper.sh", privileged: false
end
