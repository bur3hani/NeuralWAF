# NeuralWAF Enterprise Production Makefile
# High-Performance Go Deep Learning Web Application Firewall

.PHONY: all build test bench proto docker-build run clean help

APP_NAME := edge-proxy
BIN_DIR := bin
CONFIG_FILE := configs/waf.yaml

# Go build parameters
GO := go
GOFLAGS := -v
LDFLAGS := -s -w -X main.Version=2.4.0 -X main.BuildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

all: proto build test

## help: Display available Makefile commands
help:
	@echo "NeuralWAF Enterprise Build Automation"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## //'

## build: Compile high-performance edge-proxy binary
build:
	@echo "==> Compiling $(APP_NAME) for Linux/AMD64..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(APP_NAME) cmd/edge-proxy/main.go
	@echo "==> Successfully built $(BIN_DIR)/$(APP_NAME)"

## test: Execute all unit and race condition tests
test:
	@echo "==> Running Go test suites with race detector..."
	$(GO) test -v -race -timeout 30s ./...

## bench: Run zero-allocation memory benchmarks
bench:
	@echo "==> Running zero-allocation memory benchmarks..."
	$(GO) test -v -bench=. -benchmem -run=^$$ ./internal/tokenizer/

## proto: Generate gRPC protobuf Go bindings from api/inference.proto
proto:
	@echo "==> Compiling api/inference.proto via protoc..."
	@which protoc > /dev/null || (echo "Error: protoc not found in PATH" && exit 1)
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       api/inference.proto
	@echo "==> Protocol buffers compiled successfully."

## docker-build: Build minimal hardened Docker container
docker-build:
	@echo "==> Building Docker image enterprise/neuralwaf:latest..."
	docker build -t enterprise/neuralwaf:latest -t enterprise/neuralwaf:v2.4.0 .

## run: Run edge-proxy locally using configs/waf.yaml
run: build
	@echo "==> Launching NeuralWAF Edge Proxy (:8080 Data Plane, :9090 Control Plane)..."
	./$(BIN_DIR)/$(APP_NAME) -config $(CONFIG_FILE) -port 8080 -upstream http://127.0.0.1:8000

## clean: Remove compiled binaries and build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@echo "==> Clean complete."
