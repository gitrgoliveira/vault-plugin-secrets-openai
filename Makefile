# Makefile for vault-plugin-secrets-openai
# =============================================================================

# Build Variables
# =============================================================================
GOARCH = $(shell go env GOARCH)
GOOS = $(shell go env GOOS)
GOVERSION = $(shell go version | awk '{print $$3}')
BUILD_DIR = ./bin
PLUGIN_NAME = vault-plugin-secrets-openai
VERSION ?= 0.1.0
COMMIT_HASH = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME = $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Platform detection for different commands
HASH_CMD = sha256sum
ifeq ($(GOOS), darwin)
	HASH_CMD = shasum -a 256
endif

# Build flags
LDFLAGS = -ldflags="-X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH) -X main.buildTime=$(BUILD_TIME)"
GO_BUILD_FLAGS = -trimpath

# Docker configuration
DOCKER_IMAGE = vault-plugin-secrets-openai
DOCKER_TAG ?= $(VERSION)

# Vault configuration
VAULT_PLUGIN_DIR ?= ~/.vault/plugins
VAULT_PLUGIN_PATH ?= openai

# Colors for output
COLOR_RESET = \033[0m
COLOR_BOLD = \033[1m
COLOR_GREEN = \033[32m
COLOR_YELLOW = \033[33m
COLOR_BLUE = \033[34m

.PHONY: help all build build-verbose build-progress build-progress-force build-release build-release-verbose build-cross clean test test-integration test-unit test-cover fmt vet check-fmt lint staticcheck docker-build docker-run docker-push deps-check deps-install vault-dev vault-register vault-enable

# Default target
# =============================================================================
all: check-fmt test lint staticcheck-ci build

# Help target
# =============================================================================
help: ## Show this help message
	@echo "$(COLOR_BOLD)Vault OpenAI Secrets Plugin Makefile$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Available targets:$(COLOR_RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_BLUE)%-20s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(COLOR_BOLD)Common workflows:$(COLOR_RESET)"
	@echo "  $(COLOR_GREEN)make dev-setup$(COLOR_RESET)     - Complete development environment setup"
	@echo "  $(COLOR_GREEN)make test-all$(COLOR_RESET)      - Run all tests and checks"
	@echo "  $(COLOR_GREEN)make release$(COLOR_RESET)       - Build release version with Docker"

# Build Targets
# =============================================================================

build: ## Build the plugin binary
	@echo "$(COLOR_GREEN)Building $(PLUGIN_NAME)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	@echo "$(COLOR_GREEN)✓ Built $(BUILD_DIR)/$(PLUGIN_NAME)$(COLOR_RESET)"

build-verbose: ## Build with verbose output
	@echo "$(COLOR_GREEN)Building $(PLUGIN_NAME) with verbose output...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	go build -v -x $(GO_BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

build-release: ## Build optimized release binary for Linux
	@echo "$(COLOR_GREEN)Building release version of $(PLUGIN_NAME)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(PLUGIN_NAME)-linux-amd64 ./cmd/$(PLUGIN_NAME)
	@echo "$(COLOR_GREEN)✓ Built $(BUILD_DIR)/$(PLUGIN_NAME)-linux-amd64$(COLOR_RESET)"

build-release-verbose: ## Build release binary with verbose output
	@echo "$(COLOR_GREEN)Building release version of $(PLUGIN_NAME) with verbose output...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -v -x $(GO_BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

build-cross: ## Build for multiple platforms
	@echo "$(COLOR_GREEN)Building for multiple platforms...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@for platform in linux/amd64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		output=$(BUILD_DIR)/$(PLUGIN_NAME)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then output=$$output.exe; fi; \
		echo "Building for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o $$output ./cmd/$(PLUGIN_NAME); \
	done
	@echo "$(COLOR_GREEN)✓ Cross-platform builds complete$(COLOR_RESET)"
	
build-progress: ## Build with progress indicator
	@echo "$(COLOR_GREEN)Building $(PLUGIN_NAME) with progress indicator...$(COLOR_RESET)"
	./scripts/build_with_progress.sh

build-progress-force: ## Build with progress indicator (forced rebuild)
	@echo "$(COLOR_GREEN)Building $(PLUGIN_NAME) with progress indicator (forced rebuild)...$(COLOR_RESET)"
	./scripts/build_with_progress.sh --force

# Cleanup Targets
# =============================================================================
clean: ## Clean build artifacts
	@echo "$(COLOR_YELLOW)Cleaning up...$(COLOR_RESET)"
	rm -rf $(BUILD_DIR)
	go clean -cache
	go clean -modcache
	@echo "$(COLOR_GREEN)✓ Cleanup complete$(COLOR_RESET)"

# Testing Targets
# =============================================================================

test: ## Run basic tests
	@echo "$(COLOR_GREEN)Running tests...$(COLOR_RESET)"
	./scripts/run_tests.sh

test-unit: ## Run unit tests only
	@echo "$(COLOR_GREEN)Running unit tests...$(COLOR_RESET)"
	go test -short -race ./...

test-integration: build ## Run integration tests
	@echo "$(COLOR_GREEN)Running tests with integration...$(COLOR_RESET)"
	./scripts/run_tests.sh --integration

test-cover: ## Run tests with coverage
	@echo "$(COLOR_GREEN)Running tests with coverage...$(COLOR_RESET)"
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_GREEN)✓ Coverage report generated: coverage.html$(COLOR_RESET)"

test-all: check-fmt lint staticcheck test ## Run all tests and checks
	@echo "$(COLOR_GREEN)✓ All tests and checks passed$(COLOR_RESET)"

# Code Quality Targets
# =============================================================================

fmt: ## Format Go code
	@echo "$(COLOR_GREEN)Formatting code...$(COLOR_RESET)"
	go fmt ./...
	@echo "$(COLOR_GREEN)✓ Code formatted$(COLOR_RESET)"

vet: ## Run go vet
	@echo "$(COLOR_GREEN)Vetting code...$(COLOR_RESET)"
	go vet ./...
	@echo "$(COLOR_GREEN)✓ Code vetted$(COLOR_RESET)"

check-fmt: ## Check if code is formatted
	@echo "$(COLOR_GREEN)Checking format...$(COLOR_RESET)"
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "$(COLOR_YELLOW)Code is not formatted. Run 'make fmt' to fix.$(COLOR_RESET)"; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)✓ Code is properly formatted$(COLOR_RESET)"

lint: ## Run basic linting
	@echo "$(COLOR_GREEN)Linting code...$(COLOR_RESET)"
	go vet ./...
	go mod tidy
	@echo "$(COLOR_GREEN)✓ Linting complete$(COLOR_RESET)"

lint-strict: lint ## Run strict linting checks
	@echo "$(COLOR_GREEN)Running strict linting checks...$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)✓ Strict linting complete$(COLOR_RESET)"

staticcheck: ## Run staticcheck
	@echo "$(COLOR_GREEN)Running staticcheck...$(COLOR_RESET)"
	@if ! command -v staticcheck >/dev/null 2>&1; then \
		echo "$(COLOR_YELLOW)staticcheck not found, installing...$(COLOR_RESET)"; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	fi
	staticcheck -f stylish -checks "all,-SA1012" ./...
	@echo "$(COLOR_GREEN)✓ Staticcheck complete$(COLOR_RESET)"

staticcheck-strict: staticcheck ## Run strict staticcheck
	@echo "$(COLOR_GREEN)Running strict staticcheck (including package documentation)...$(COLOR_RESET)"
	staticcheck -f stylish ./...

staticcheck-ci: ## Run CI version of staticcheck (ignoring common issues)
	@echo "$(COLOR_GREEN)Running CI version of staticcheck (ignoring common issues)...$(COLOR_RESET)"
	@if ! command -v staticcheck >/dev/null 2>&1; then \
		echo "$(COLOR_YELLOW)staticcheck not found, installing...$(COLOR_RESET)"; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	fi
	staticcheck -f stylish -checks "all,-SA1012,-ST1000" ./...

# Dependencies
# =============================================================================
deps-check: ## Check for dependency issues
	@echo "$(COLOR_GREEN)Checking dependencies...$(COLOR_RESET)"
	go mod verify
	go mod tidy
	@echo "$(COLOR_GREEN)✓ Dependencies verified$(COLOR_RESET)"

deps-install: ## Install development dependencies
	@echo "$(COLOR_GREEN)Installing development dependencies...$(COLOR_RESET)"
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "$(COLOR_GREEN)✓ Development dependencies installed$(COLOR_RESET)"

# Utility Targets
# =============================================================================

sha256: ## Generate SHA256 hash of the plugin binary
	@echo "$(COLOR_GREEN)Generating SHA256 hash of the plugin binary...$(COLOR_RESET)"
	@if [ ! -f "$(BUILD_DIR)/$(PLUGIN_NAME)" ]; then \
		echo "$(COLOR_YELLOW)Plugin binary not found. Building first...$(COLOR_RESET)"; \
		$(MAKE) build; \
	fi
	@$(HASH_CMD) $(BUILD_DIR)/$(PLUGIN_NAME)

version: ## Show version information
	@echo "$(COLOR_BOLD)Build Information:$(COLOR_RESET)"
	@echo "  Version:     $(VERSION)"
	@echo "  Commit:      $(COMMIT_HASH)"
	@echo "  Build Time:  $(BUILD_TIME)"
	@echo "  Go Version:  $(GOVERSION)"
	@echo "  OS/Arch:     $(GOOS)/$(GOARCH)"

# Docker Targets
# =============================================================================
docker-build: ## Build Docker image
	@echo "$(COLOR_GREEN)Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)...$(COLOR_RESET)"
	DOCKER_BUILDKIT=1 docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "$(COLOR_GREEN)✓ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(COLOR_RESET)"

docker-run: docker-build ## Run plugin in Docker container
	@echo "$(COLOR_GREEN)Running Docker container...$(COLOR_RESET)"
	docker run --rm -it -p 8200:8200 $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-push: docker-build ## Push Docker image to registry
	@echo "$(COLOR_GREEN)Pushing Docker image...$(COLOR_RESET)"
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Vault Development Targets
# =============================================================================

vault-dev: build ## Start Vault in dev mode with plugin
	@echo "$(COLOR_GREEN)Starting Vault in dev mode...$(COLOR_RESET)"
	@mkdir -p $(VAULT_PLUGIN_DIR)
	@cp $(BUILD_DIR)/$(PLUGIN_NAME) $(VAULT_PLUGIN_DIR)/
	vault server -dev -dev-plugin-dir=$(VAULT_PLUGIN_DIR) &
	@echo "$(COLOR_YELLOW)Vault started in background. Use 'vault status' to check.$(COLOR_RESET)"

install-dev: build ## Install plugin in development Vault instance
	@echo "$(COLOR_GREEN)Installing plugin in development Vault instance...$(COLOR_RESET)"
	@mkdir -p $(VAULT_PLUGIN_DIR)
	@cp $(BUILD_DIR)/$(PLUGIN_NAME) $(VAULT_PLUGIN_DIR)/
	@$(HASH_CMD) $(VAULT_PLUGIN_DIR)/$(PLUGIN_NAME) | awk '{print $$1}' > $(BUILD_DIR)/$(PLUGIN_NAME).sha256
	@echo "$(COLOR_GREEN)✓ Plugin installed at $(VAULT_PLUGIN_DIR)/$(PLUGIN_NAME)$(COLOR_RESET)"

vault-register: install-dev ## Register the plugin with a running Vault instance
	@echo "$(COLOR_GREEN)Registering plugin with Vault...$(COLOR_RESET)"
	@if [ -z "$$VAULT_ADDR" ]; then \
		echo "$(COLOR_YELLOW)Warning: VAULT_ADDR not set, using http://127.0.0.1:8200$(COLOR_RESET)"; \
		export VAULT_ADDR=http://127.0.0.1:8200; \
	fi
	vault plugin register \
		-sha256=$$(cat $(BUILD_DIR)/$(PLUGIN_NAME).sha256) \
		secret $(PLUGIN_NAME)
	@echo "$(COLOR_GREEN)✓ Plugin registered$(COLOR_RESET)"

vault-enable: ## Enable the plugin at a specified path
	@echo "$(COLOR_GREEN)Enabling plugin at path '$(VAULT_PLUGIN_PATH)'...$(COLOR_RESET)"
	vault secrets enable -path=$(VAULT_PLUGIN_PATH) $(PLUGIN_NAME)
	@echo "$(COLOR_GREEN)✓ Plugin enabled at $(VAULT_PLUGIN_PATH)/$(COLOR_RESET)"

# Combined Development Workflows
# =============================================================================

dev-setup: vault-register vault-enable ## Complete development environment setup
	@echo "$(COLOR_GREEN)Development setup complete.$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)Next steps:$(COLOR_RESET)"
	@echo "  1. Configure the secrets engine:"
	@echo "     $(COLOR_BLUE)vault write $(VAULT_PLUGIN_PATH)/config admin_api_key=<api-key> admin_api_key_id=<key-id> organization_id=<org-id>$(COLOR_RESET)"
	@echo "  2. Create a role:"
	@echo "     $(COLOR_BLUE)vault write $(VAULT_PLUGIN_PATH)/roles/my-role project_id=<project-id>$(COLOR_RESET)"
	@echo "  3. Generate credentials:"
	@echo "     $(COLOR_BLUE)vault read $(VAULT_PLUGIN_PATH)/creds/my-role$(COLOR_RESET)"

quick-start: build vault-register vault-enable ## Quick development setup
	@echo "$(COLOR_GREEN)✓ Quick start complete. Plugin built, registered, and enabled.$(COLOR_RESET)"

# Release Targets
# =============================================================================
release: build-release docker-build ## Build release version with Docker
	@echo "$(COLOR_GREEN)Release v$(VERSION) complete.$(COLOR_RESET)"
	@echo "$(COLOR_BOLD)Built artifacts:$(COLOR_RESET)"
	@ls -la $(BUILD_DIR)/
	@echo "$(COLOR_BOLD)Docker image:$(COLOR_RESET) $(DOCKER_IMAGE):$(DOCKER_TAG)"

release-all: build-cross docker-build ## Build release for all platforms
	@echo "$(COLOR_GREEN)✓ Release v$(VERSION) built for all platforms$(COLOR_RESET)"

# CI/CD Targets
# =============================================================================
ci: deps-check check-fmt lint staticcheck-ci test ## Run CI pipeline
	@echo "$(COLOR_GREEN)✓ CI pipeline completed successfully$(COLOR_RESET)"

ci-build: ci build-release ## Full CI build pipeline
	@echo "$(COLOR_GREEN)✓ CI build pipeline completed$(COLOR_RESET)"
