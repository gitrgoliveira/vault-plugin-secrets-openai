# Vault OpenAI Secrets Plugin

A HashiCorp Vault plugin for dynamic, secure management of OpenAI service accounts and API keys using the OpenAI Admin API. This plugin enables you to create, rotate, and revoke OpenAI project service accounts and API keys on demand, with full automation and security best practices.

This plugin was developed and tested with Vault 1.19.4.

> [!IMPORTANT]
> Use at your own risk and conduct your own testing before deploying. This plugin is not officially supported by HashiCorp and is provided as-is.
>
---

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Installation](#installation)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Development](#development)
- [Usage with Docker](#usage-with-docker)
- [Usage without Docker](#usage-without-docker)
- [Vagrant Development Environment](#vagrant-development-environment-recommended-for-linux-container-plugin-testing)
- [License](#license)

---

## Features
- **Dynamic Service Accounts**: Create OpenAI service accounts (with API keys) with configurable TTLs for improved security.
- **Automatic Cleanup**: Service accounts and API keys are automatically cleaned up when leases expire.
- **Admin API Key Rotation**: Securely rotate OpenAI admin keys manually or on a schedule.
- **Metrics and Monitoring**: Prometheus-compatible metrics for credential issuance, revocation, and API errors.
- **Containerized Deployment**: Run as a containerized Vault plugin with Docker (Linux only).

> **Note:** Only dynamic service account credentials are supported.

---

## Quick Start

### 1. Download the Plugin
You can download the pre-built plugin binary from the [latest release page](https://github.com/gitrgoliveira/vault-plugin-secrets-openai/releases/latest).

### 2. Extract the Plugin
```shell
# Extract the plugin binary (replace VERSION with the latest release version)
mkdir -p ./bin
curl -L -o ./bin/vault-plugin-secrets-openai https://github.com/gitrgoliveira/vault-plugin-secrets-openai/releases/download/VERSION/vault-plugin-secrets-openai
chmod +x ./bin/vault-plugin-secrets-openai
```

### 3. Start a Dev Vault Server and Register the Plugin
```shell
vault server -dev -dev-plugin-dir=./bin
# In another terminal
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
vault plugin register -sha256=$(shasum -a 256 ./bin/vault-plugin-secrets-openai | cut -d' ' -f1) \
  secret vault-plugin-secrets-openai
vault secrets enable -path=openai vault-plugin-secrets-openai
```

### 4. Configure the Plugin
```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456"
```

### 5. Create a Role
```shell
vault write openai/roles/my-role \
  project_id="proj_my-project" \
  service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
  ttl=1h \
  max_ttl=24h
```

### 6. Generate an API Key
```shell
vault read openai/creds/my-role
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

#### Configure the Plugin
```
POST /openai/config
PUT /openai/config
```
Configures the OpenAI secrets engine with admin API credentials.

**Parameters:**
- `admin_api_key` (string, required) - Admin API key for OpenAI
- `admin_api_key_id` (string, required) - Admin API key ID for OpenAI  
- `organization_id` (string, required) - Organization ID for OpenAI
- `api_endpoint` (string, optional) - URL for the OpenAI API (default: `https://api.openai.com/v1`)
- `rotation_period` (duration, optional) - Period between automatic admin API key rotations
- `rotation_window` (duration, optional) - Window during which rotation can occur
- `disable_automated_rotation` (bool, optional) - Disable automated rotation of admin credentials

**Example:**
```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456" \
  rotation_period=604800
```

#### Read Configuration
```
GET /openai/config
```
Returns the current configuration (sensitive fields are not returned).

**Response Fields:**
- `api_endpoint` - The configured API endpoint
- `organization_id` - The organization ID
- `admin_api_key_id` - The admin API key ID
- `rotation_period` - Automatic rotation period (if enabled)
- `rotation_window` - Rotation window (if enabled)
- `last_rotated` - Last rotation timestamp (if automated rotation is enabled)

#### Delete Configuration
```
DELETE /openai/config
```
Removes the configuration.

#### Rotate Admin API Key
```
POST /openai/config/rotate
```
Manually rotates the admin API key. Creates a new admin API key and revokes the old one.

### Roles API

#### Create/Update Role
```
POST /openai/roles/{name}
PUT /openai/roles/{name}
```
Creates or updates a role definition for generating dynamic credentials.

**Parameters:**
- `name` (string, required) - Name of the role
- `project_id` (string, required) - OpenAI Project ID (e.g., `proj_abc123`)
- `service_account_name_template` (string, optional) - Template for service account names (default: `vault-{{.RoleName}}-{{.RandomSuffix}}`)
- `service_account_description` (string, optional) - Description for service accounts (default: `Service account created by Vault`)
- `ttl` (duration, optional) - Default TTL for API keys (default: `1h`)
- `max_ttl` (duration, optional) - Maximum TTL for API keys (default: `24h`)

**Example:**
```shell
vault write openai/roles/analytics \
  project_id="proj_abc123" \
  service_account_name_template="analytics-{{.RoleName}}-{{.RandomSuffix}}" \
  ttl=2h \
  max_ttl=24h
```

#### Read Role
```
GET /openai/roles/{name}
```
Returns the configuration for a specific role.

#### List Roles
```
GET /openai/roles
```
Lists all configured roles.

#### Delete Role
```
DELETE /openai/roles/{name}
```
Deletes a role definition.

### Dynamic Credentials API

#### Generate Credentials
```
GET /openai/creds/{role_name}
```
Generates new dynamic OpenAI credentials using the specified role.

**Parameters:**
- `role_name` (string, required) - Name of the role to use
- `ttl` (duration, optional) - Custom TTL for this credential (must not exceed role's max_ttl)

**Example:**
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

## Metrics and Monitoring
This plugin emits Prometheus-compatible metrics via Vault's telemetry system for observability and monitoring. These metrics can be scraped by Prometheus or viewed via Vault's telemetry endpoints.

---

## Development
- Go 1.24.6+
- Vault 1.19+ for containerized plugin support
- Vagrant (for containerized plugin usage)

---

## Usage with Docker

> **Note:** Building and running Vault plugins with Docker is only supported on Linux hosts. If you are on macOS or Windows, you must build the plugin binary on a Linux machine or use a Linux VM/container for plugin development and testing. See the [Vault documentation](https://developer.hashicorp.com/vault/docs/plugins#plugin-platform-support) for details.

You can run the Vault OpenAI Secrets Plugin in a containerized environment using Docker. This is the recommended approach for most users.

### 1. Build the Plugin Binary
```shell
make build-release
```

### 2. Build the Docker Image
A sample Dockerfile is provided. Build the image:
```shell
make release VERSION=0.0.3
```

### 3. Run Vault in dev mode if not already running
```shell
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
export DOCKER_HOST=unix:///run/user/1000/docker.sock # Adjust if using a different Docker socket
nohup env DOCKER_HOST=$DOCKER_HOST vault server -dev -dev-root-token-id=root > vault.log 2>&1 &

```

### 4. Register and Enable the Plugin
```bash
# Get the Docker image SHA256
PLUGIN_SHA256=$(docker images --no-trunc --format="{{ .ID }}" vault-plugin-secrets-openai:0.0.3 | cut -d: -f2)

# Register the plugin runtime (if using containerized plugins)
vault plugin runtime register -type=container -rootless=true -oci_runtime=runsc runsc

# Register the plugin with Vault (replace 0.0.3 with your version)
vault plugin register \
  -sha256="$PLUGIN_SHA256" \
  -oci_image="vault-plugin-secrets-openai" \
  -runtime="runsc" \
  -version="0.0.3" \
  secret vault-plugin-secrets-openai

# Enable the secrets engine
vault secrets enable -path=openai vault-plugin-secrets-openai
```

### 5. Configure the Plugin
```bash
# Configure with your OpenAI admin API key
vault write openai/config admin_api_key="$OPENAI_ADMIN_API_KEY" \
admin_api_key_id="$ADMIN_API_KEY_ID" \
organization_id="$OPENAI_ORG_ID" \
rotation_period="720h"

vault read openai/config
Key                           Value
---                           -----
admin_api_key_id              key_OInm3Qed3kNn4BUQ
api_endpoint                  https://api.openai.com/v1
disable_automated_rotation    false
last_rotated                  2025-07-02T15:30:45+00:00
organization_id               org-gAZ0NbaPX8FD2YcdLsHiKx8v
rotation_period               720h
rotation_schedule             n/a
rotation_window               0 
```

The admin API key is used by Vault to create and manage service accounts in your OpenAI organization. The rotation period determines how often this root credential is automatically rotated. See all supported parameters here.

You can also use `vault write -force openai/config/rotate` to force the rotation.

### 6. Create Roles
Roles define the permissions and TTL for credentials generated for specific applications:
```bash
# Create a role for your application
vault write openai/roles/my-application project_id="$OPENAI_TEST_PROJECT_ID" \
service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
      ttl=”1h” max_ttl=”24h”
```
```shell

### 7. Generate an API Key
```shell
vault read openai/creds/my-application
```

Sample response:
```
Key                Value
---                -----
lease_id           openai/creds/my-application/abcdef12345
lease_duration     1h
lease_renewable    true
api_key            sk-...
api_key_id         api_key_abc123
service_account    vault-my-application-12345
service_account_id svc_abc123
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
- [VirtualBox](https://www.virtualbox.org/)

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
