# Vault OpenAI Secrets Plugin

A HashiCorp Vault plugin for dynamic, secure management of OpenAI service accounts and API keys using the OpenAI Admin API. This plugin enables you to create, rotate, and revoke OpenAI project service accounts and API keys on demand, with full automation and security best practices.

---

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Installation](#installation)
- [Configuration](#configuration)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Development](#development)
- [Usage with Docker](#usage-with-docker)
- [Usage without Docker](#usage-without-docker)
- [License](#license)

---

## Features
- **Dynamic Service Accounts**: Create OpenAI service accounts (with API keys) with configurable TTLs for improved security.
- **Automatic Cleanup**: Service accounts and API keys are automatically cleaned up after use.
- **Admin API Key Rotation**: Securely rotate OpenAI admin keys manually or on a schedule.
- **Metrics and Monitoring**: Prometheus-compatible metrics for credential issuance, revocation, and API errors.
- **Containerized Deployment**: Run as a containerized Vault plugin with Docker (Linux only).

> **Note:** Only dynamic service account credentials are supported.

---

## Quick Start

### 1. Build the Plugin
```shell
make build
```

### 2. Start a Dev Vault Server and Register the Plugin
```shell
vault server -dev -dev-plugin-dir=./bin
# In another terminal
export VAULT_ADDR=http://127.0.0.1:8200
make register
make enable
```

### 3. Configure the Plugin
```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456"
```

### 4. Create a Role
```shell
vault write openai/roles/my-role \
  project_id="proj_my-project" \
  service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
  ttl=1h \
  max_ttl=24h
```

### 5. Generate an API Key
```shell
vault read openai/creds/my-role
```

---

## Usage

- **Dynamic Credentials**: Create service accounts (with API keys) on-demand with automatic cleanup.

### Dynamic Credentials Workflow
```shell
# 1. Create a role
dynamic_role_name="app-role"
vault write openai/roles/$dynamic_role_name \
  project_id="proj_my-project" \
  ttl=1h \
  max_ttl=24h

# 2. Generate a service account and API key
vault read openai/creds/$dynamic_role_name

# 3. Optional: Request a custom TTL
vault read openai/creds/$dynamic_role_name ttl=30m
```

Sample response:
```
Key                Value
---                -----
lease_id           openai/creds/app-role/abcdef12345
lease_duration     30m
lease_renewable    false
api_key            sk-...
api_key_id         api_key_abc123
service_account    vault-app-role-12345
service_account_id svc_abc123
```

---

## API Reference

### Configuration API
```
POST /openai/config
GET /openai/config
```
Parameters:
- `admin_api_key` - (Required) Admin API key for OpenAI
- `admin_api_key_id` - (Required) Admin API key ID for OpenAI
- `organization_id` - (Required) Organization ID for OpenAI
- `api_endpoint` - (Optional) URL for the OpenAI API (default: https://api.openai.com/v1)
- `rotation_period` - (Optional) Period in seconds between automatic admin API key rotations
- `rotation_window` - (Optional) Window in seconds during which rotation can occur

Example:
```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456" \
  rotation_period=604800
```

### Dynamic Credentials API
```
POST /openai/roles/:name
GET /openai/roles/:name
GET /openai/roles
DELETE /openai/roles/:name
GET /openai/creds/:role_name
```
Parameters:
- `project_id` - (Required) Project ID to use for this role
- `service_account_name_template` - (Optional) Template for service account name creation
- `ttl` - (Optional) Default TTL for generated API keys
- `max_ttl` - (Optional) Maximum TTL for generated API keys

Example:
```shell
vault write openai/roles/analytics \
  project_id="my-project" \
  service_account_name_template="analytics-{{.RoleName}}-{{.RandomSuffix}}" \
  ttl=2h \
  max_ttl=24h
```

#### Generate Credentials
```shell
vault read openai/creds/analytics ttl=1h
```

---

## Installation

### Building the Plugin
```shell
git clone https://github.com/gitrgoliveira/vault-plugin-secrets-openai.git
cd vault-plugin-secrets-openai
make build
```

### Installing in Vault
1. Copy the plugin binary to your Vault plugins directory:
   ```shell
   cp ./bin/vault-plugin-secrets-openai /path/to/vault/plugins/
   ```
2. Calculate the SHA256 sum of the plugin:
   ```shell
   SHA256=$(shasum -a 256 /path/to/vault/plugins/vault-plugin-secrets-openai | cut -d' ' -f1)
   ```
3. Register the plugin with Vault:
   ```shell
   vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-openai
   ```
4. Enable the OpenAI secrets engine:
   ```shell
   vault secrets enable -path=openai -plugin-name=vault-plugin-secrets-openai plugin
   ```

---

## Configuration

Configure the plugin with your OpenAI Admin API key, admin API key ID, and organization ID. **Both the admin API key and key ID are required and must be kept up to date for secure operation.**

```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456"
```

---

## Metrics and Monitoring
This plugin emits Prometheus-compatible metrics via Vault's telemetry system for observability and monitoring. These metrics can be scraped by Prometheus or viewed via Vault's telemetry endpoints.

---

## Development
- Go 1.24+
- Vault 1.10+ for containerized plugin support
- Docker (for containerized plugin usage)

---

## Usage with Docker

> **Note:** Building and running Vault plugins with Docker is only supported on Linux hosts. If you are on macOS or Windows, you must build the plugin binary on a Linux machine or use a Linux VM/container for plugin development and testing. See the [Vault documentation](https://developer.hashicorp.com/vault/docs/plugins#plugin-platform-support) for details.

You can run the Vault OpenAI Secrets Plugin in a containerized environment using Docker. This is the recommended approach for most users.

### 1. Build the Plugin Binary
```shell
make build
```

### 2. Build the Docker Image
A sample Dockerfile is provided. Build the image:
```shell
docker build -t vault-openai-plugin .
```

### 3. Run Vault with the Plugin
```shell
docker run --rm -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  -v $(pwd)/bin:/vault/plugins \
  vault server -dev -dev-plugin-dir=/vault/plugins
```

### 4. Register and Enable the Plugin
In another terminal:
```shell
export VAULT_ADDR=http://127.0.0.1:8200
vault plugin register -sha256=$(shasum -a 256 ./bin/vault-plugin-secrets-openai | cut -d' ' -f1) \
  secret vault-plugin-secrets-openai
vault secrets enable -path=openai -plugin-name=vault-plugin-secrets-openai plugin
```

### 5. Configure the Plugin
```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456"
```

---

## Usage without Docker

You can also run the plugin directly on your host system (Linux/macOS) without Docker.

### 1. Build the Plugin Binary
```shell
make build
```

### 2. Start a Dev Vault Server and Register the Plugin
```shell
vault server -dev -dev-plugin-dir=./bin
# In another terminal
export VAULT_ADDR=http://127.0.0.1:8200
vault plugin register -sha256=$(shasum -a 256 ./bin/vault-plugin-secrets-openai | cut -d' ' -f1) \
  secret vault-plugin-secrets-openai
vault secrets enable -path=openai -plugin-name=vault-plugin-secrets-openai plugin
```

### 3. Configure the Plugin
```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456"
```

---

## Vagrant Development Environment (Recommended for Linux Container Plugin Testing)

This project provides a robust Vagrant-based development environment for building, testing, and running the Vault OpenAI Secrets Plugin with support for rootless Docker and gVisor/runsc.

### Features
- Automated provisioning of Go, Docker (rootless), and gVisor/runsc for containerized plugin testing.
- Rootless Docker setup for the `vagrant` user, with correct socket and runtime configuration.
- gVisor/runsc installed from the official APT repository, with fallback to `runc` if runsc is not compatible with rootless mode.
- Automated plugin build, Docker image creation, and Vault plugin registration inside the VM.
- Integration and unit test scripts for plugin validation.

### Prerequisites
- [Vagrant](https://www.vagrantup.com/)
- [VirtualBox](https://www.virtualbox.org/) or another supported provider

### Quick Start (Vagrant)

1. **Start the Vagrant VM and provision:**
   ```sh
   vagrant up
   ```
   This will:
   - Install Go, Docker (rootless), and gVisor/runsc
   - Set up Docker for the `vagrant` user in rootless mode
   - Build the plugin and Docker image
   - Start Vault in dev mode and register the plugin

2. **SSH into the VM:**
   ```sh
   vagrant ssh
   cd vault-plugin-secrets-openai
   ```

3. **Run tests:**
   - **Unit tests:**
     ```sh
     ./scripts/run_tests.sh
     ```
   - **Integration tests:**
     ```sh
     ./scripts/run_tests.sh --integration
     ```
     You will be prompted for your OpenAI Admin API Key, Organization ID, and Test Project ID.

#### Notes on Docker and gVisor/runsc
- The provisioning scripts attempt to use `runsc` as the Docker runtime for containerized plugin testing.
- **gVisor/runsc is not fully compatible with rootless Docker** due to systemd/cgroup limitations. If runsc fails, the scripts will automatically fall back to the default `runc` runtime for plugin build and Vault registration.
- The correct Docker socket (`/run/user/1000/docker.sock`) is set via the `DOCKER_HOST` environment variable for all Vault and Docker operations.

#### Environment Variables
- `VAULT_ADDR`, `VAULT_TOKEN`, and `DOCKER_HOST` are set automatically in the VM for the `vagrant` user.
- For integration tests, you will need to provide:
  - `OPENAI_ADMIN_API_KEY`
  - `OPENAI_ORG_ID`
  - `OPENAI_TEST_PROJECT_ID`

#### Troubleshooting
- If you see errors about Docker socket permissions or plugin registration, ensure that `DOCKER_HOST` is set to the rootless Docker socket and that Vault is running with this environment variable.
- If you need to reprovision from scratch:
  ```sh
  vagrant destroy -f
  vagrant up
  ```

#### File Overview
- `scripts/vagrant_provision_as_root.sh`: Installs system dependencies (Go, Docker, gVisor, etc.)
- `scripts/vagrant_provision_as_user.sh`: Configures Docker rootless mode, builds the plugin, starts Vault, and registers the plugin.
- `scripts/run_tests.sh`: Runs unit and integration tests for the plugin.

---

## License
This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.
