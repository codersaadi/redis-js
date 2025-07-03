# Variables
BINARY_NAME=redis-proxy
DOCKER_IMAGE=redis-proxy
DOCKER_TAG=latest
GO_VERSION=1.21
PLATFORMS=linux/amd64,linux/arm64

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags="-w -s"
BUILD_FLAGS=-a -installsuffix cgo

.PHONY: all build clean test deps docker-build docker-run docker-push compose-up compose-down help

# Default target
all: clean deps test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) .

# Build for multiple platforms
build-multi:
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	docker system prune -f

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage
test-coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Benchmark tests
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) verify
	$(GOMOD) tidy

# Update dependencies
deps-update:
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

# Security audit
security:
	@echo "Running security audit..."
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

# Lint code
lint:
	@echo "Running linter..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	$(GOCMD) vet ./...

# Run the application locally
run:
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME)

# Run with development config
run-dev:
	@echo "Running in development mode..."
	LOG_LEVEL=debug \
	REDIS_ADDR=localhost:6379 \
	PORT=8080 \
	METRICS_ENABLED=true \
	ENABLE_LOCAL_CACHE=true \
	./$(BINARY_NAME)

# Docker targets
docker-build:
	@echo "Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Build multi-platform Docker image
docker-build-multi:
	@echo "Building multi-platform Docker image..."
	docker buildx create --use --name multibuilder || true
	docker buildx build --platform $(PLATFORMS) --push -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker run -p 8080:8080 -p 9090:9090 --env-file .env $(DOCKER_IMAGE):$(DOCKER_TAG)

# Push Docker image
docker-push:
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Docker Compose targets
compose-up:
	@echo "Starting services with Docker Compose..."
	docker-compose up -d

# Start with monitoring stack
compose-up-monitoring:
	@echo "Starting services with monitoring..."
	docker-compose --profile monitoring up -d

# Start with cluster mode
compose-up-cluster:
	@echo "Starting with Redis cluster..."
	docker-compose --profile cluster up -d

# Start with load balancer
compose-up-lb:
	@echo "Starting with load balancer..."
	docker-compose --profile loadbalancer up -d

# Start all services
compose-up-all:
	@echo "Starting all services..."
	docker-compose --profile monitoring --profile loadbalancer up -d

# Stop Docker Compose services
compose-down:
	@echo "Stopping Docker Compose services..."
	docker-compose down

# Stop and remove volumes
compose-down-volumes:
	@echo "Stopping services and removing volumes..."
	docker-compose down -v

# View logs
compose-logs:
	@echo "Viewing logs..."
	docker-compose logs -f

# View specific service logs
compose-logs-proxy:
	docker-compose logs -f redis-proxy

compose-logs-redis:
	docker-compose logs -f redis

# Restart services
compose-restart:
	@echo "Restarting services..."
	docker-compose restart

# Scale proxy instances
compose-scale:
	@echo "Scaling proxy to 3 instances..."
	docker-compose up -d --scale redis-proxy=3

# Health check
health-check:
	@echo "Checking service health..."
	curl -f http://localhost:8080/health || echo "Service is not healthy"
	curl -f http://localhost:8080/ready || echo "Service is not ready"

# Load test
load-test:
	@echo "Running load test..."
	@command -v hey >/dev/null 2>&1 || { echo "Installing hey..."; go install github.com/rakyll/hey@latest; }
	hey -n 10000 -c 100 -m POST -H "Content-Type: application/json" -d '{"command":["GET","test"]}' http://localhost:8080/

# Deployment targets
deploy-staging:
	@echo "Deploying to staging..."
	docker-compose -f docker-compose.yml -f docker-compose.staging.yml up -d

deploy-production:
	@echo "Deploying to production..."
	docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d

# Backup Redis data
backup:
	@echo "Creating Redis backup..."
	docker-compose exec redis redis-cli BGSAVE
	docker cp $$(docker-compose ps -q redis):/data/dump.rdb ./backups/redis-backup-$$(date +%Y%m%d-%H%M%S).rdb

# Restore Redis data
restore:
	@echo "Restoring Redis data..."
	@read -p "Enter backup file path: " backup_file; \
	docker-compose stop redis; \
	docker cp $$backup_file $$(docker-compose ps -q redis):/data/dump.rdb; \
	docker-compose start redis

# Generate certificates for TLS
generate-certs:
	@echo "Generating TLS certificates..."
	mkdir -p certs
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout certs/server.key \
		-out certs/server.crt \
		-subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Setup development environment
setup-dev:
	@echo "Setting up development environment..."
	cp .env.example .env
	make deps
	make generate-certs
	make compose-up

# Database migration (if needed)
migrate:
	@echo "Running migrations..."
	# Add migration commands here

# Install tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/rakyll/hey@latest
	go install github.com/swaggo/swag/cmd/swag@latest

# Generate documentation
docs:
	@echo "Generating documentation..."
	@command -v swag >/dev/null 2>&1 || make install-tools
	swag init -g main.go

# Release
release: clean deps test security lint build docker-build
	@echo "Creating release..."
	@echo "Version: $(shell git describe --tags --always)"
	git tag -a v$(shell date +%Y.%m.%d) -m "Release v$(shell date +%Y.%m.%d)"

# Show help
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  build-multi    - Build for multiple platforms"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  bench          - Run benchmarks"
	@echo "  deps           - Download dependencies"
	@echo "  deps-update    - Update dependencies"
	@echo "  security       - Run security audit"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  vet            - Vet code"
	@echo "  run            - Run the application"
	@echo "  run-dev        - Run in development mode"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  docker-push    - Push Docker image"
	@echo "  compose-up     - Start with Docker Compose"
	@echo "  compose-down   - Stop Docker Compose"
	@echo "  compose-logs   - View logs"
	@echo "  health-check   - Check service health"
	@echo "  load-test      - Run load test"
	@echo "  setup-dev      - Setup development environment"
	@echo "  help           - Show this help"