#!/bin/bash
# Additional setup script for Vagrant to prepare the VM for running tests with real credentials
# Run this script from your host machine to set up OpenAI credentials in your VM

# Verify we have the necessary environment variables
if [ -z "$OPENAI_ADMIN_API_KEY" ] || [ -z "$OPENAI_ORG_ID" ]; then
    echo "Please set OPENAI_ADMIN_API_KEY and OPENAI_ORG_ID environment variables"
    echo "Example:"
    echo "export OPENAI_ADMIN_API_KEY=sk-admin-..."
    echo "export OPENAI_ORG_ID=org-123456"
    exit 1
fi

# Use Vagrant to send environment variables to the VM
# This creates a file in the home directory that the provision_helper.sh script can source
vagrant ssh -c "echo 'export OPENAI_ADMIN_API_KEY=\"$OPENAI_ADMIN_API_KEY\"' > ~/.openai_env"
vagrant ssh -c "echo 'export OPENAI_ORG_ID=\"$OPENAI_ORG_ID\"' >> ~/.openai_env"
vagrant ssh -c "chmod 600 ~/.openai_env"  # Secure the file

echo "Credentials have been securely stored in the Vagrant VM"
echo "Run the following command in the VM to set up your credentials:"
echo "source ~/.openai_env && cd ~/vault-plugin-secrets-openai && ./scripts/provision_helper.sh"

# Optionally run the helper script directly
read -p "Do you want to run the setup script now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    vagrant ssh -c "source ~/.openai_env && cd ~/vault-plugin-secrets-openai && ./scripts/provision_helper.sh"
fi
