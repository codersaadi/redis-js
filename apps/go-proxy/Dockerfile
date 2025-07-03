# Build stage - using a recent stable Go version
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk update && apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application, creating a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o redis-proxy .

# Final stage - using distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

# Copy CA certificates and timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/redis-proxy .

# Copy TLS certificates
COPY --chown=nonroot:nonroot certs ./certs

# Expose ports
EXPOSE 8080 9090

# Use distroless nonroot user
USER nonroot

# Health check using the binary itself
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/redis-proxy", "healthcheck"]

# Run the application
ENTRYPOINT ["/app/redis-proxy"]