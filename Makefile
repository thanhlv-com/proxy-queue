# Proxy Queue Makefile
# Build for multiple platforms

APP_NAME=proxy-queue
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_VERSION := $(shell go version | cut -d ' ' -f 3)

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GoVersion=$(GO_VERSION)"

# Directories
BUILD_DIR=build
DIST_DIR=dist

# Default target
.PHONY: all
all: clean build

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@go clean

# Build for current platform
.PHONY: build
build:
	@echo "Building $(APP_NAME) for current platform..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) main.go

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

# Run with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	@go test -race -v ./...

# Lint the code
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Vet code
.PHONY: vet
vet:
	@echo "Vetting code..."
	@go vet ./...

# Build for Linux (x86_64)
.PHONY: build-linux
build-linux:
	@echo "Building $(APP_NAME) for Linux (x86_64)..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 main.go

# Build for Linux (ARM64)
.PHONY: build-linux-arm64
build-linux-arm64:
	@echo "Building $(APP_NAME) for Linux (ARM64)..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 main.go

# Build for Ubuntu (same as Linux x86_64)
.PHONY: build-ubuntu
build-ubuntu: build-linux
	@echo "Ubuntu build completed (same as Linux x86_64)"

# Build for macOS (x86_64)
.PHONY: build-macos
build-macos:
	@echo "Building $(APP_NAME) for macOS (x86_64)..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 main.go

# Build for macOS (ARM64 - Apple Silicon)
.PHONY: build-macos-arm64
build-macos-arm64:
	@echo "Building $(APP_NAME) for macOS (ARM64)..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 main.go

# Build for Windows (x86_64)
.PHONY: build-windows
build-windows:
	@echo "Building $(APP_NAME) for Windows (x86_64)..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe main.go

# Build for Windows (ARM64)
.PHONY: build-windows-arm64
build-windows-arm64:
	@echo "Building $(APP_NAME) for Windows (ARM64)..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-arm64.exe main.go

# Build for all platforms
.PHONY: build-all
build-all: build-linux build-linux-arm64 build-macos build-macos-arm64 build-windows build-windows-arm64
	@echo "All platform builds completed"

# Create distribution packages
.PHONY: dist
dist: build-all
	@echo "Creating distribution packages..."
	@mkdir -p $(DIST_DIR)
	
	# Linux x86_64
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR) $(APP_NAME)-linux-amd64
	
	# Linux ARM64
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-linux-arm64.tar.gz -C $(BUILD_DIR) $(APP_NAME)-linux-arm64
	
	# macOS x86_64
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(BUILD_DIR) $(APP_NAME)-darwin-amd64
	
	# macOS ARM64
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-darwin-arm64.tar.gz -C $(BUILD_DIR) $(APP_NAME)-darwin-arm64
	
	# Windows x86_64
	@cd $(BUILD_DIR) && zip ../$(DIST_DIR)/$(APP_NAME)-$(VERSION)-windows-amd64.zip $(APP_NAME)-windows-amd64.exe
	
	# Windows ARM64
	@cd $(BUILD_DIR) && zip ../$(DIST_DIR)/$(APP_NAME)-$(VERSION)-windows-arm64.zip $(APP_NAME)-windows-arm64.exe
	
	@echo "Distribution packages created in $(DIST_DIR)/"

# Run the application
.PHONY: run
run: build
	@echo "Running $(APP_NAME)..."
	@$(BUILD_DIR)/$(APP_NAME)

# Run with example configuration
.PHONY: run-example
run-example: build
	@echo "Running $(APP_NAME) with example configuration..."
	@$(BUILD_DIR)/$(APP_NAME) -port=6789 -target-host=httpbin.org -target-port=443 -https=true -delay-min=1000 -delay-max=5000

# Development build (with debug info)
.PHONY: dev
dev:
	@echo "Building $(APP_NAME) for development..."
	@mkdir -p $(BUILD_DIR)
	@go build -gcflags="all=-N -l" -o $(BUILD_DIR)/$(APP_NAME)-dev main.go

# Check Go version compatibility
.PHONY: check-version
check-version:
	@echo "Go version: $(GO_VERSION)"
	@echo "Required: go1.19 or later"

# Show build information
.PHONY: info
info:
	@echo "Application: $(APP_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(GO_VERSION)"

# Install the binary to GOPATH/bin
.PHONY: install
install:
	@echo "Installing $(APP_NAME) to GOPATH/bin..."
	@go install $(LDFLAGS) .

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all              - Clean and build for current platform"
	@echo "  build            - Build for current platform"
	@echo "  build-linux      - Build for Linux (x86_64)"
	@echo "  build-linux-arm64- Build for Linux (ARM64)"
	@echo "  build-ubuntu     - Build for Ubuntu (alias for Linux x86_64)"
	@echo "  build-macos      - Build for macOS (x86_64)"
	@echo "  build-macos-arm64- Build for macOS (ARM64)"
	@echo "  build-windows    - Build for Windows (x86_64)"
	@echo "  build-windows-arm64 - Build for Windows (ARM64)"
	@echo "  build-all        - Build for all platforms"
	@echo "  clean            - Clean build artifacts"
	@echo "  deps             - Install dependencies"
	@echo "  dev              - Development build with debug info"
	@echo "  dist             - Create distribution packages"
	@echo "  fmt              - Format code"
	@echo "  help             - Show this help message"
	@echo "  info             - Show build information"
	@echo "  install          - Install binary to GOPATH/bin"
	@echo "  lint             - Run linter"
	@echo "  run              - Build and run the application"
	@echo "  run-example      - Run with example configuration"
	@echo "  test             - Run tests"
	@echo "  test-race        - Run tests with race detection"
	@echo "  vet              - Vet code"
	@echo "  check-version    - Check Go version compatibility"