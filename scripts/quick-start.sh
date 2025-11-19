#!/bin/bash

set -e

echo "🚀 EdgeGuard Quick Start Script"
echo "================================"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21+ first."
    exit 1
fi

echo "✅ Go found: $(go version)"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker not found. Will skip Docker setup."
    DOCKER_AVAILABLE=false
else
    echo "✅ Docker found: $(docker --version)"
    DOCKER_AVAILABLE=true
fi
echo ""

# Install dependencies
echo "📦 Installing Go dependencies..."
go mod download
go mod tidy
echo "✅ Dependencies installed"
echo ""

# Start Redis
if [ "$DOCKER_AVAILABLE" = true ]; then
    echo "🔴 Starting Redis..."
    docker run -d --name edgeguard-redis -p 6379:6379 redis:7-alpine 2>/dev/null || echo "Redis already running"
    sleep 2
    echo "✅ Redis started"
    echo ""
fi

# Build
echo "🔨 Building EdgeGuard..."
make build
echo "✅ Build complete"
echo ""

# Check Redis connection
if [ "$DOCKER_AVAILABLE" = true ]; then
    if docker exec edgeguard-redis redis-cli ping > /dev/null 2>&1; then
        echo "✅ Redis is responding"
    else
        echo "⚠️  Redis not responding, but continuing..."
    fi
    echo ""
fi

echo "🎉 Setup complete!"
echo ""
echo "To start EdgeGuard:"
echo "  make run"
echo ""
echo "Or manually:"
echo "  ./bin/edge-node --config configs/config.yaml"
echo ""
echo "The service will be available at:"
echo "  HTTP:    http://localhost:8080"
echo "  Admin:   http://localhost:9090"
echo "  Health:  http://localhost:9090/health"
echo "  Stats:   http://localhost:9090/stats"
echo "  Metrics: http://localhost:9090/metrics"
echo ""
echo "Quick test commands:"
echo "  curl http://localhost:8080/get"
echo "  curl http://localhost:9090/health | jq"
echo "  curl http://localhost:9090/stats | jq"
echo ""
echo "To stop Redis:"
echo "  make dev-stop"
echo ""
echo "See TESTING.md for comprehensive testing instructions."
