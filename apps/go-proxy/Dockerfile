# Build stage - using latest stable Go with security updates
FROM golang:1.24-alpine3.21 AS builder

# Install build dependencies with specific versions and security updates
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
    git=~2.43 \
    ca-certificates \
    tzdata && \
    rm -rf /var/cache/apk/*
    
# Set working directory
WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies with verification
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static" -X main.version=$(date +%Y%m%d)' \
    -a -installsuffix cgo \
    -trimpath \
    -buildmode=pie \
    -o redis-proxy \
    .

# Final stage - using scratch for absolute minimal attack surface
FROM scratch

# Copy CA certificates and timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary from builder stage
COPY --from=builder /app/redis-proxy /redis-proxy

# Copy configuration files
COPY --from=builder /app/config/ /config/

# Expose ports
EXPOSE 8080 9090

# No health check possible with scratch image - implement in orchestration layer
# HEALTHCHECK requires shell which scratch doesn't have

# Run the application
ENTRYPOINT ["/redis-proxy"]