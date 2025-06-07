# Vault OpenAI Secrets Plugin

This HashiCorp Vault plugin enables dynamic management of OpenAI service accounts and their API keys using the OpenAI Admin API. Built with a standard HashiCorp plugin structure, it allows you to create project service accounts (with API keys) that have configurable TTLs and automatic cleanup.

## Features

- **Dynamic Service Accounts**: Create OpenAI service accounts (with API keys) with configurable TTLs for better security
- **Service Account Management**: Automatically create and clean up service accounts
- **Admin API Key Rotation**: Securely rotate admin keys manually or on a schedule
- **Metrics and Monitoring**: Track credential issuance, revocation, and API errors
- **Containerized Deployment**: Run as a containerized Vault plugin with Docker

> **Note:** This plugin supports only dynamic service account credentials.

## Quick Start

### Build and Install

```shell
make build
```

### Start a Dev Vault Server and Register the Plugin

```shell
vault server -dev -dev-plugin-dir=./bin
# In another terminal
export VAULT_ADDR=http://127.0.0.1:8200
make register
make enable
```

### Configure the Plugin

```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456"
```

### Create a Role

```shell
vault write openai/roles/my-role \
  project="my-project" \
  service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
  ttl=1h \
  max_ttl=24h
```

### Generate an API Key

```shell
vault read openai/creds/my-role
```

Sample response:
```
Key                Value
---                -----
lease_id           openai/creds/my-role/abcdef12345
lease_duration     1h
lease_renewable    false
api_key            sk-...
api_key_id         api_key_abc123
service_account    vault-my-role-12345
service_account_id svc_abc123
```

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

## Configuration

### Basic Configuration

Configure the plugin with your OpenAI Admin API key, admin API key ID, and organization ID. **Both the admin API key and key ID are required and must be kept up to date for secure operation.**

```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456"
```

### Create a Role

```shell
vault write openai/roles/my-role \
  project="my-project" \
  service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
  ttl=1h \
  max_ttl=24h
```

## Usage

The plugin supports only dynamic credential management:

- **Dynamic Credentials**: Create service accounts (with API keys) on-demand with automatic cleanup

### Dynamic Credentials Workflow

Dynamic credentials are ideal for ephemeral workloads or applications that need temporary access:

```shell
# 1. Create a role defining parameters for dynamic credentials
vault write openai/roles/app-role \
  project="my-project" \
  ttl=1h \
  max_ttl=24h

# 2. Generate a service account and API key when needed
vault read openai/creds/app-role

# 3. Optional: Request a custom TTL for this credential
vault read openai/creds/app-role ttl=30m
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

## API Reference

### Configuration API

```
POST /openai/config
GET /openai/config
```

Parameters:
- `admin_api_key` - (Required for POST/PUT) Admin API key for OpenAI
- `admin_api_key_id` - (Required for POST/PUT) Admin API key ID for OpenAI
- `organization_id` - (Required for POST/PUT) Organization ID for OpenAI
- `api_endpoint` - (Optional) URL for the OpenAI API (default: https://api.openai.com/v1)
- `rotation_period` - (Optional) Period in seconds between automatic admin API key rotations
- `rotation_window` - (Optional) Window in seconds during which rotation can occur

Example Create/Update:
```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  admin_api_key_id="admin-key-id-..." \
  organization_id="org-123456" \
  rotation_period=604800
```

Example Read:
```shell
vault read openai/config
```

Output:
```
Key                        Value
---                        -----
api_endpoint               https://api.openai.com/v1
rotation_period            604800
last_rotated               2025-06-01T12:00:00Z
organization_id            org-123456
```

Note: The admin API key is not returned in the read response for security reasons.

#### Rotate Admin API Key

```
POST /openai/config/rotate
```

Example:
```shell
vault write -f openai/config/rotate
```

Response:
```
Success! Admin API key has been rotated.
```

> **Note:** Only admin API key rotation is supported. The plugin manages the admin key lifecycle robustly; ensure you update both the key and key ID in the configuration when rotating.

### Dynamic Credentials API

```
POST /openai/roles/:name
GET /openai/roles/:name
GET /openai/roles
DELETE /openai/roles/:name
GET /openai/creds/:role_name
```

Parameters:
- `project` - (Required) Project to use for this role
- `service_account_name_template` - (Optional) Template for service account name creation
- `ttl` - (Optional) Default TTL for generated API keys
- `max_ttl` - (Optional) Maximum TTL for generated API keys

Example:
```shell
vault write openai/roles/analytics \
  project="my-project" \
  service_account_name_template="analytics-{{.RoleName}}-{{.RandomSuffix}}" \
  ttl=2h \
  max_ttl=24h
```

#### Generate Credentials

```shell
vault read openai/creds/analytics ttl=1h
```

Response:
```
Key                 Value
---                 -----
lease_id            openai/creds/analytics/abcdefgh12345
lease_duration      1h
lease_renewable     false
api_key             sk-abcdef123456
api_key_id          api_key_987654321
service_account     analytics-test-role-a1b2c3d4
service_account_id  svc_123456789
```

## Development

- Go 1.24+
- Vault 1.10+ for containerized plugin support
- Docker (for containerized plugin usage)

## Metrics and Monitoring

This plugin emits Prometheus-compatible metrics via Vault's telemetry system for observability and monitoring. These metrics can be scraped by Prometheus or viewed via Vault's telemetry endpoints.

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.
