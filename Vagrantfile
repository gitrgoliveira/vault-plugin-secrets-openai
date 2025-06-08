# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.network "public_network"

  # Shared folder configuration
  config.vm.synced_folder ".", "/vagrant", type: "rsync"
  
  # Provider-specific configuration
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "16384"  # Allocate 8GB of RAM
    vb.cpus = 8 # Allocate 8 CPUs
    vb.name = "vault-plugin-openai-test"
  end

  # VM provisioning
  config.vm.provision "shell", path: "scripts/vagrant_provision_as_root.sh", privileged: true

  # Helper script to set up and test the plugin
  config.vm.provision "shell", path: "scripts/vagrant_provision_as_user.sh", privileged: false
end
