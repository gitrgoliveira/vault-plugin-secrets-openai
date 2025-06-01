# Vault OpenAI Secrets Plugin

This HashiCorp Vault plugin enables dynamic management of OpenAI API keys using the OpenAI Admin API. Built with a standard HashiCorp plugin structure, it allows you to create project service accounts with API keys that have configurable TTLs and automatic cleanup.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Reference](#api-reference)
  - [Dynamic Credentials API](#dynamic-credentials-api)
  - [Static Credentials API](#static-credentials-api)
  - [Check-In/Check-Out API](#check-incheck-out-api)
- [Development](#development)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Containerized Deployment](#containerized-deployment)
- [Integration Testing with Containerized Plugin](#integration-testing-with-containerized-plugin)
- [Development with Vagrant](#development-with-vagrant)
- [License](#license)

## Features

- **Dynamic API Keys**: Create OpenAI API keys with configurable TTLs for better security
- **Service Account Management**: Automatically create and clean up service accounts
- **Key Checkout System**: Check-in/check-out mechanism for API key sharing and management
- **Admin API Key Rotation**: Securely rotate admin keys manually or on a schedule
- **Metrics and Monitoring**: Track credential issuance, revocation, and API errors
- **Containerized Deployment**: Run as a containerized Vault plugin with Docker

## Quick Start

### Build and Install

```shell
# Build the plugin
make build

# Start a dev vault server with plugin directory
vault server -dev -dev-plugin-dir=./bin

# In another terminal
export VAULT_ADDR=http://127.0.0.1:8200

# Register and enable the plugin
make register
make enable

# Configure the plugin
vault write openai/config \
  admin_api_key="sk-admin-..." \
  organization_id="org-123456"
```

### Create a Project and Role

```shell
# Register an OpenAI project
vault write openai/project/my-project \
  project_id="proj_abc123" \
  description="My OpenAI Project"

# Create a role for dynamic credentials
vault write openai/roles/my-role \
  project="my-project" \
  service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
  service_account_description="Service account created by Vault" \
  ttl=1h \
  max_ttl=24h
```

### Generate an API Key

```shell
vault read openai/creds/my-role
```

Response:
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
# Clone the repository
git clone https://github.com/gitrgoliveira/vault-plugin-secrets-openai.git
cd vault-plugin-secrets-openai

# Build the plugin binary
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

Configure the plugin with your OpenAI Admin API key and organization ID:

```shell
vault write openai/config \
  admin_api_key="sk-admin-..." \
  organization_id="org-123456"
```

### Project Configuration

Register an OpenAI project:

```shell
vault write openai/project/my-project \
    project_id="proj_abc123" \
    description="My OpenAI Project"
```

3. Create a role:

```shell
vault write openai/roles/my-role \
    project="my-project" \
    service_account_name_template="vault-{{.RoleName}}-{{.RandomSuffix}}" \
    service_account_description="Service account created by Vault" \
    ttl=1h \
    max_ttl=24h
```

## Usage

The plugin supports three main credential management approaches:

1. **Dynamic Credentials**: Create service accounts and API keys on-demand with automatic cleanup
2. **Static Credentials**: Manage API keys for existing service accounts with rotation
3. **Check-in/Check-out**: Share a pool of service accounts among multiple clients

### Dynamic Credentials Workflow

Dynamic credentials are ideal for ephemeral workloads or applications that need temporary access:

```shell
# 1. Create a role defining parameters for dynamic credentials
vault write openai/roles/app-role \
  project="my-project" \
  ttl=1h \
  max_ttl=24h

# 2. Generate an API key when needed
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

### Static Credentials Workflow

Static credentials work with existing service accounts and provide key rotation:

```shell
# 1. Create a static role for an existing service account
vault write openai/static-roles/existing-sa \
  service_account_id="svc_existing123" \
  project_id="proj_abc123" \
  rotation_period=24h

# 2. Retrieve the current API key
vault read openai/static-creds/existing-sa

# 3. Manually trigger rotation when needed
vault write -f openai/static-creds/existing-sa/rotate
```

### Service Account Checkout Workflow

For shared resources where you need exclusive access to a service account:

```shell
# 1. Create a library set with multiple service accounts
vault write openai/library-sets/shared-pool \
  project="my-project" \
  max_ttl=72h \
  service_account_names="account-1,account-2,account-3"

# 2. Check out an available service account
vault write openai/library-sets/shared-pool/checkout \
  ttl=4h

# 3. Check in when done to make it available for others
vault write openai/library-sets/shared-pool/checkin \
  service_account_id="svc_123abc"

# 4. View status of the library set
vault read openai/library-sets/shared-pool/status
```

### Admin API Key Rotation

For security best practices, periodically rotate the admin API key:

```shell
# Manually rotate the admin API key
vault write openai/config/rotate-admin-key new_admin_api_key="sk-admin-new-key"
```

### Role Configuration Options

When creating a role, you can customize the following options:

- `project` - (Required) Name of the project to use for this role
- `service_account_name_template` - Template for the service account name (default: `vault-{{.RoleName}}-{{.RandomSuffix}}`)
- `service_account_description` - Description for created service accounts (default: "Service account created by Vault")
- `ttl` - Default TTL for generated API keys (default: 1h)
- `max_ttl` - Maximum TTL for generated API keys (default: 24h)

Template variables available for `service_account_name_template`:
- `{{.RoleName}}` - The name of the role
- `{{.RandomSuffix}}` - A random string suffix (8 characters by default)
- `{{.ProjectName}}` - The name of the project

## API Reference

This section provides detailed information about the OpenAI Secrets plugin's API endpoints and how to use them.

### Dynamic Credentials API

Dynamic credentials are created on-demand for a specific TTL and automatically cleaned up when the lease expires.

#### Create a Dynamic Role

```
POST /openai/roles/:name
```

Parameters:
- `project` - (Required) Project to use for this role
- `service_account_name_template` - (Optional) Template for service account name creation
- `service_account_description` - (Optional) Description for created service accounts
- `ttl` - (Optional) Default TTL for generated API keys
- `max_ttl` - (Optional) Maximum TTL for generated API keys

Example:
```shell
vault write openai/roles/analytics \
  project="research-project" \
  service_account_name_template="analytics-{{.RoleName}}-{{.RandomSuffix}}" \
  service_account_description="Analytics service account" \
  ttl=2h \
  max_ttl=24h
```

#### List Dynamic Roles

```
GET /openai/roles
```

Example:
```shell
vault list openai/roles
```

Output:
```
Keys
----
analytics
research
test-role
```

#### Read Role Configuration

```
GET /openai/roles/:name
```

Example:
```shell
vault read openai/roles/analytics
```

Output:
```
Key                           Value
---                           -----
max_ttl                       24h
project                       research-project
service_account_description   Analytics service account
service_account_name_template analytics-{{.RoleName}}-{{.RandomSuffix}}
ttl                           2h
```

#### Generate Credentials

```
GET /openai/creds/:role_name
```

Parameters:
- `ttl` - (Optional) Custom TTL for this credential, must be <= max_ttl

Example:
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

### Static Credentials API

Static credentials allow you to manage long-lived API keys for existing OpenAI service accounts.

#### Create a Static Role

```
POST /openai/static-roles/:name
```

Parameters:
- `service_account_id` - (Required) ID of existing service account
- `project_id` - (Required) ID of project the service account belongs to
- `rotation_period` - (Optional) How often to rotate the key (default: 24h)

Example:
```shell
vault write openai/static-roles/data-science \
  service_account_id="svc_abcdef123456" \
  project_id="proj_123456789" \
  rotation_period=48h
```

#### Read Static Credentials

```
GET /openai/static-creds/:role_name
```

Example:
```shell
vault read openai/static-creds/data-science
```

Response:
```
Key                 Value
---                 -----
last_rotation       2025-05-31T23:45:22Z
rotation_period     48h
service_account_id  svc_abcdef123456
api_key             sk-cdefgh567890
api_key_id          api_key_345678901
```

#### Rotate Static Credentials

```
POST /openai/static-creds/:role_name/rotate
```

Example:
```shell
vault write -f openai/static-creds/data-science/rotate
```

Response:
```
Key                 Value
---                 -----
last_rotation       2025-06-01T00:12:33Z
rotation_period     48h
service_account_id  svc_abcdef123456
api_key             sk-fghijk098765
api_key_id          api_key_123098765
```

### Check-In/Check-Out API

The check-in/check-out system provides a way to share a pool of service accounts with API keys.

#### Create a Library Set

```
POST /openai/library-sets/:name
```

Parameters:
- `project` - (Required) Name of the project to use
- `service_account_names` - (Required) Comma-separated list of service accounts
- `max_ttl` - (Optional) Maximum checkout duration (default: 24h)

Example:
```shell
vault write openai/library-sets/research \
  project="research-team" \
  service_account_names="research-sa-1,research-sa-2,research-sa-3" \
  max_ttl=48h
```

#### Check Out a Service Account

```
POST /openai/library-sets/:name/checkout
```

Parameters:
- `ttl` - (Optional) Duration for this checkout (default: 1h, max: max_ttl of library set)

Example:
```shell
vault write openai/library-sets/research/checkout ttl=4h
```

Response:
```
Key                 Value
---                 -----
lease_id            openai/library-sets/research/checkout/abcdef123456
lease_duration      4h
lease_renewable     true
api_key             sk-mnopqr234567
api_key_id          api_key_876543210
service_account     research-sa-1
service_account_id  svc_234567890
checkout_time       2025-06-01T14:30:00Z
```

#### Check In a Service Account

```
POST /openai/library-sets/:name/checkin
```

Parameters:
- `service_account_id` - (Required) ID of the service account to check in

Example:
```shell
vault write openai/library-sets/research/checkin \
  service_account_id="svc_234567890"
```

Response:
```
Success! Service account checked in and API key rotated.
```

#### List Available Service Accounts

```
GET /openai/library-sets/:name/status
```

Example:
```shell
vault read openai/library-sets/research/status
```

Response:
```
Key                      Value
---                      -----
available_accounts       2
checked_out_accounts     1
account_status           map[research-sa-1:checked-out research-sa-2:available research-sa-3:available]
max_ttl                  48h
project                  research-team
```

#### Force Check-In (Admin Operation)

```
POST /openai/library-sets/:name/admin-checkin
```

Parameters:
- `service_account_id` - (Required) ID of the service account to forcibly check in

Example:
```shell
vault write openai/library-sets/research/admin-checkin \
  service_account_id="svc_234567890"
```

Response:
```
Success! Service account forcibly checked in and API key rotated.
```

## Development

### Prerequisites

- Go 1.24+
- Vault 1.10+ for containerized plugin support
- Docker (for containerized plugin usage)

### Repository Structure

The repository follows HashiCorp's standard plugin structure:

```
├── bin/                    # Compiled binary
├── bootstrap/              # Bootstrap and setup scripts
│   └── terraform/          # Terraform for testing infrastructure
├── cmd/                    # Plugin entry point
│   └── vault-plugin-secrets-openai/
│       └── main.go
├── plugin/                 # Core plugin code (package: openaisecrets)
│   ├── backend.go
│   ├── client.go
│   └── ...                 # Other plugin files
├── scripts/                # Helper scripts
└── tests/                  # Test files
    └── acceptance/         # Acceptance tests
```

### Package Structure

The plugin package is named `openaisecrets` to avoid conflicts with the actual OpenAI client libraries and to clearly indicate its purpose as a Vault secrets plugin.

### Security Considerations

The Admin API key is stored securely in Vault's storage with seal-wrapping when available. Note that the Admin API key grants significant privileges, so proper access controls should be configured for the secrets engine.

### Required OpenAI Permissions

The Admin API key used for this plugin must have the following permissions:
- Create project service accounts
- Delete project service accounts 
- Create API keys
- Delete API keys

### Development Workflow

1. Make changes to the code
2. Run tests:
   ```shell
   make test
   ```
3. Build the plugin:
   ```shell
   make build
   ```
4. Set up a development Vault instance:
   ```shell
   make dev-setup
   ```

### Testing with a local Vault server

1. Start a development Vault server:
   ```shell
   vault server -dev -dev-plugin-dir=./bin
   ```

2. In another terminal, export the Vault address:
   ```shell
   export VAULT_ADDR=http://127.0.0.1:8200
   ```

3. Register and enable the plugin:
   ```shell
   make register
   make enable
   ```

4. Configure the plugin:
   ```shell
   vault write openai/config \
     admin_api_key="your-admin-api-key" \
     organization_id="your-organization-id"
   ```

### Running tests

Run the unit tests:
```shell
make test
```

For more detailed test output:
```shell
go test -v ./...
```

## Metrics and Monitoring

This plugin emits Prometheus-compatible metrics via Vault's telemetry system for observability and monitoring. These metrics can be scraped by Prometheus or viewed via Vault's telemetry endpoints.

### Emitted Metrics

- **Credential Issuance**
  - `openai_creds_issued{role="<role>"}`: Counter incremented each time a dynamic credential is issued for a role.
- **Credential Revocation**
  - `openai_creds_revoked{role="<role>"}`: Counter incremented each time a dynamic credential is revoked for a role.
- **API Errors**
  - `openai_api_error{endpoint="<endpoint>",code="<code>"}`: Counter incremented for each error returned by the OpenAI API, labeled by endpoint and error code.
- **Quota Usage**
  - `openai_quota_used{project="<project>"}`: Counter incremented by the amount of quota used per project (if quota tracking is enabled).

#### Example Prometheus Queries

- Credentials issued per role:
  ```promql
  sum by (role) (openai_creds_issued)
  ```
- API errors by endpoint:
  ```promql
  sum by (endpoint, code) (openai_api_error)
  ```

#### Enabling Telemetry

To enable Vault telemetry and Prometheus metrics, configure Vault with telemetry options. See the [Vault telemetry documentation](https://www.vaultproject.io/docs/internals/telemetry)

## Containerized Deployment

This plugin can be run as a containerized plugin with Vault 1.10+ on Linux.

### Building the Docker Image

```shell
docker build -t vault-plugin-secrets-openai:latest .
```

### Registering the Containerized Plugin

```shell
vault plugin register \
  -sha256=$(docker image inspect vault-plugin-secrets-openai:latest --format '{{ index .RepoDigests 0 }}' | cut -d'@' -f2) \
  -command="/home/vault/vault-plugin-secrets-openai" \
  -args="" \
  -runtime="container" \
  secret vault-plugin-secrets-openai
```

For more details, see the [Vault Containerized Plugins Guide](https://developer.hashicorp.com/vault/docs/plugins/containerized-plugins).

## Integration Testing with Containerized Plugin

A step-by-step script for integration testing is provided in `vault_container_plugin_integration_test.sh`. This script automates:

1. Building the Docker image for the plugin
2. Starting a Vault dev server
3. Registering the containerized plugin
4. Enabling the secrets engine
5. Configuring the plugin (update with your real OpenAI admin key/org ID)
6. Registering a test project
7. Creating a test role
8. Issuing dynamic credentials

### Usage

```shell
zsh vault_container_plugin_integration_test.sh
```

- Update the `admin_api_key` and `organization_id` variables in the script before running.
- The script will print each step and output the issued credentials at the end.
- The Vault dev server will be terminated automatically after the script completes.

See the script for details and customize as needed for your environment.

## Development with Vagrant

The repository includes a Vagrantfile to create a development environment with all necessary dependencies pre-installed. This is especially useful for testing containerized plugins since they require Linux.

### Prerequisites

- [Vagrant](https://www.vagrantup.com/downloads)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or another Vagrant-compatible provider

### Starting the Vagrant Environment

```shell
# Start the VM
vagrant up

# SSH into the VM
vagrant ssh
```

### Vagrant Environment Features

The Vagrant environment comes pre-configured with:

- Ubuntu 22.04 (Jammy)
- Vault server
- Docker CE with gVisor/runsc runtime for containerized plugins
- Go development environment
- Port forwarding (8200 for Vault UI/API)

### Testing with Real Credentials

To set up the VM with your OpenAI API credentials:

1. Export your credentials on your host machine:
   ```shell
   export OPENAI_ADMIN_API_KEY="sk-admin-..."
   export OPENAI_ORG_ID="org-123456"
   ```

2. Run the setup credentials script:
   ```shell
   ./scripts/setup_vagrant_creds.sh
   ```

3. Alternatively, after SSHing into the VM:
   ```shell
   # Inside the VM
   source ~/.openai_env  # If credentials were transferred
   cd ~/vault-plugin-secrets-openai
   ./scripts/provision_helper.sh
   ```

### Accessing Vault UI

After running the provision script, you can access the Vault UI at:
- URL: http://localhost:8200
- Token: root

### Destroying the Environment

When you're done testing:

```shell
vagrant destroy
```

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.
