#!/bin/sh
set -e

# This entrypoint is for Vault containerized plugin compatibility
# It simply runs the plugin binary
exec /home/vault/vault-plugin-secrets-openai "$@"
