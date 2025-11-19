# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o edge-node ./cmd/edge-node

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/edge-node .

# Copy configs
COPY configs ./configs

# Expose ports
EXPOSE 8080 8443 9090

# Run the application
CMD ["./edge-node", "--config", "configs/config.yaml"]
