# Makefile for vault-plugin-secrets-openai

# Variables
GOARCH = $(shell go env GOARCH)
GOOS = $(shell go env GOOS)
BUILD_DIR = ./bin
PLUGIN_NAME = vault-plugin-secrets-openai
VERSION = 0.1.0
HASH_CMD = sha256sum
ifeq ($(GOOS), darwin)
	HASH_CMD = shasum -a 256
endif

.PHONY: all build clean test test-integration fmt vet check-fmt lint staticcheck

all: check-fmt test lint staticcheck-ci build

build:
	@echo "Building $(PLUGIN_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)

test:
	@echo "Running tests..."
	./scripts/run_tests.sh

test-integration:
	@echo "Running tests with integration..."
	./scripts/run_tests.sh --integration

fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Vetting code..."
	go vet ./...

check-fmt:
	@echo "Checking format..."
	@test -z $(shell gofmt -l .)

lint:
	@echo "Linting code..."
	go vet ./...
	go mod tidy

lint-strict: lint
	@echo "Running strict linting checks..."
	@echo "(Use 'make lint' for basic linting only)"

staticcheck:
	@echo "Running staticcheck..."
	staticcheck -f stylish -checks "all,-SA1012" ./...

staticcheck-strict: staticcheck
	@echo "Running strict staticcheck (including package documentation)..."
	staticcheck -f stylish ./...

# A more lenient version of staticcheck that ignores common warnings
staticcheck-ci:
	@echo "Running CI version of staticcheck (ignoring common issues)..."
	staticcheck -f stylish -checks "all,-SA1012,-ST1000" ./...

# Generate the plugin SHA
sha256:
	@echo "Generating SHA256 hash of the plugin binary..."
	@$(HASH_CMD) $(BUILD_DIR)/$(PLUGIN_NAME)

# Install the plugin in the development Vault instance
install-dev: build
	@echo "Installing plugin in development Vault instance..."
	@mkdir -p ~/.vault/plugins
	@cp $(BUILD_DIR)/$(PLUGIN_NAME) ~/.vault/plugins/
	@$(HASH_CMD) ~/.vault/plugins/$(PLUGIN_NAME) | awk '{print $$1}' > $(BUILD_DIR)/$(PLUGIN_NAME).sha256

# Register the plugin with a running Vault instance (VAULT_ADDR must be set)
register: install-dev
	@echo "Registering plugin with Vault..."
	@vault plugin register \
		-sha256=$$(cat $(BUILD_DIR)/$(PLUGIN_NAME).sha256) \
		secret $(PLUGIN_NAME)

# Enable the plugin at a specified path
enable:
	@echo "Enabling plugin at path 'openai'..."
	@vault secrets enable -path=openai $(PLUGIN_NAME)

# Helper to setup a complete development environment
dev-setup: register enable
	@echo "Development setup complete."
	@echo "Configure the secrets engine with:"
	@echo "vault write openai/config admin_api_key=<api-key> organization_id=<org-id>"
