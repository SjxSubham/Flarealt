.PHONY: build test clean run docker-build docker-up docker-down

# Build variables
BINARY_DIR=bin
EDGE_NODE_BINARY=$(BINARY_DIR)/edge-node
CONTROL_PLANE_BINARY=$(BINARY_DIR)/control-plane
DNS_SERVER_BINARY=$(BINARY_DIR)/dns-server

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

all: build

build: build-edge-node

build-edge-node:
	@echo "Building Edge Node..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(EDGE_NODE_BINARY) ./cmd/edge-node

build-control-plane:
	@echo "Building Control Plane..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(CONTROL_PLANE_BINARY) ./cmd/control-plane

build-dns:
	@echo "Building DNS Server..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(DNS_SERVER_BINARY) ./cmd/dns-server

test:
	$(GOTEST) -v -race -coverprofile=coverage.txt -covermode=atomic ./...

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BINARY_DIR)
	rm -f coverage.txt

run: build-edge-node
	$(EDGE_NODE_BINARY) --config configs/config.yaml

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

lint:
	golangci-lint run

fmt:
	gofmt -s -w .

# Development helpers
dev-redis:
	docker run -d --name edgeguard-redis -p 6379:6379 redis:7-alpine

dev-postgres:
	docker run -d --name edgeguard-postgres \
		-e POSTGRES_PASSWORD=changeme \
		-e POSTGRES_USER=edgeguard \
		-e POSTGRES_DB=edgeguard \
		-p 5432:5432 postgres:15-alpine

dev-nats:
	docker run -d --name edgeguard-nats -p 4222:4222 nats:latest

dev-stop:
	docker stop edgeguard-redis edgeguard-postgres edgeguard-nats || true
	docker rm edgeguard-redis edgeguard-postgres edgeguard-nats || true

help:
	@echo "EdgeGuard Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build              - Build all binaries"
	@echo "  build-edge-node    - Build edge node binary"
	@echo "  build-control-plane- Build control plane binary"
	@echo "  build-dns          - Build DNS server binary"
	@echo "  test               - Run tests"
	@echo "  clean              - Clean build artifacts"
	@echo "  run                - Run edge node"
	@echo "  deps               - Download dependencies"
	@echo "  docker-build       - Build Docker images"
	@echo "  docker-up          - Start Docker services"
	@echo "  docker-down        - Stop Docker services"
	@echo "  dev-redis          - Start Redis for development"
	@echo "  dev-postgres       - Start PostgreSQL for development"
	@echo "  dev-nats           - Start NATS for development"
	@echo "  dev-stop           - Stop all dev services"
