package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)
type RedisProxy struct {
	config          *ProxyConfig
	redisClient     redis.UniversalClient
	readReplicas    []redis.UniversalClient
	syncTokens      sync.Map
	commandHandlers map[string]CommandHandler
	rateLimiter     *rate.Limiter
	logger          *zap.Logger
	metrics         *ProxyMetrics
	cache           *LocalCache
	mu              sync.RWMutex
	httpServer      *http.Server
	replicaCounter  uint64
	isHealthy       int32
	upgrader        websocket.Upgrader
}

// Command handling
type CommandHandler func(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error)

// JWT Claims
type JWTClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// Metrics
type ProxyMetrics struct {
	RequestsTotal      prometheus.Counter
	RequestDuration    prometheus.Histogram
	ErrorsTotal        *prometheus.CounterVec
	ActiveConnections  prometheus.Gauge
	CacheHits          prometheus.Counter
	CacheMisses        prometheus.Counter
	RedisConnections   prometheus.Gauge
	ReplicaConnections prometheus.Gauge
	CommandsTotal      *prometheus.CounterVec
}

// Local cache for frequently accessed data
type LocalCache struct {
	data      sync.Map
	ttl       time.Duration
	maxSize   int
	size      int64
	mutex     sync.RWMutex
	hits      uint64
	misses    uint64
}

type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
	AccessCount int64
}

// Initialize metrics
func NewProxyMetrics() *ProxyMetrics {
	return &ProxyMetrics{
		RequestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "upstash_proxy_requests_total",
			Help: "Total number of requests processed",
		}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "upstash_proxy_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}),
		ErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upstash_proxy_errors_total",
			Help: "Total number of errors by type",
		}, []string{"type"}),
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "upstash_proxy_active_connections",
			Help: "Number of active connections",
		}),
		CacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "upstash_proxy_cache_hits_total",
			Help: "Total number of cache hits",
		}),
		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "upstash_proxy_cache_misses_total",
			Help: "Total number of cache misses",
		}),
		RedisConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "upstash_proxy_redis_connections",
			Help: "Number of active Redis connections",
		}),
		ReplicaConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "upstash_proxy_replica_connections",
			Help: "Number of active replica connections",
		}),
		CommandsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upstash_proxy_commands_total",
			Help: "Total number of Redis commands by type",
		}, []string{"command"}),
	}
}

func (m *ProxyMetrics) Register() {
	prometheus.MustRegister(
		m.RequestsTotal,
		m.RequestDuration,
		m.ErrorsTotal,
		m.ActiveConnections,
		m.CacheHits,
		m.CacheMisses,
		m.RedisConnections,
		m.ReplicaConnections,
		m.CommandsTotal,
	)
}

// Initialize local cache
func NewLocalCache(ttl time.Duration, maxSize int) *LocalCache {
	cache := &LocalCache{
		ttl:     ttl,
		maxSize: maxSize,
	}
	// Start cleanup goroutine
	go cache.cleanup()
	return cache
}

func (c *LocalCache) Get(key string) (interface{}, bool) {
	if val, ok := c.data.Load(key); ok {
		entry := val.(CacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			atomic.AddInt64(&entry.AccessCount, 1)
			atomic.AddUint64(&c.hits, 1)
			return entry.Value, true
		}
		c.data.Delete(key)
		atomic.AddInt64(&c.size, -1)
	}
	atomic.AddUint64(&c.misses, 1)
	return nil, false
}

func (c *LocalCache) Set(key string, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if atomic.LoadInt64(&c.size) >= int64(c.maxSize) {
		c.evictLRU()
	}

	entry := CacheEntry{
		Value:       value,
		ExpiresAt:   time.Now().Add(c.ttl),
		AccessCount: 1,
	}
	c.data.Store(key, entry)
	atomic.AddInt64(&c.size, 1)
}

func (c *LocalCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.evictExpired()
	}
}

func (c *LocalCache) evictExpired() {
	now := time.Now()
	c.data.Range(func(key, value interface{}) bool {
		entry := value.(CacheEntry)
		if now.After(entry.ExpiresAt) {
			c.data.Delete(key)
			atomic.AddInt64(&c.size, -1)
		}
		return true
	})
}

func (c *LocalCache) evictLRU() {
	var oldestKey interface{}
	var oldestAccess int64 = time.Now().Unix()

	c.data.Range(func(key, value interface{}) bool {
		entry := value.(CacheEntry)
		if entry.AccessCount < oldestAccess {
			oldestAccess = entry.AccessCount
			oldestKey = key
		}
		return true
	})

	if oldestKey != nil {
		c.data.Delete(oldestKey)
		atomic.AddInt64(&c.size, -1)
	}
}

func (c *LocalCache) Stats() (hits, misses uint64, size int64) {
	return atomic.LoadUint64(&c.hits), atomic.LoadUint64(&c.misses), atomic.LoadInt64(&c.size)
}

// Initialize Redis proxy
func NewRedisProxy(config *ProxyConfig) (*RedisProxy, error) {
	// Initialize logger
	var logger *zap.Logger
	var err error
	switch config.LogLevel {
	case "debug":
		logger, err = zap.NewDevelopment()
	case "production":
		logger, err = zap.NewProduction()
	default:
		logger, err = zap.NewProduction()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize Redis client
	var rdb redis.UniversalClient
	if config.RedisClusterMode {
		rdb = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:        config.RedisClusterNodes,
			Password:     config.RedisPassword,
			MaxRetries:   config.MaxRetries,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
			PoolSize:     config.PoolSize,
			MaxConnAge:   config.MaxConnAge,
			IdleTimeout:  config.IdleTimeout,
			TLSConfig: func() *tls.Config {
				if config.RedisTLSEnabled {
					return &tls.Config{InsecureSkipVerify: false}
				}
				return nil
			}(),
		})
	} else {
		rdb = redis.NewClient(&redis.Options{
			Addr:         config.RedisAddr,
			Password:     config.RedisPassword,
			DB:           config.RedisDB,
			MaxRetries:   config.MaxRetries,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
			PoolSize:     config.PoolSize,
			MaxConnAge:   config.MaxConnAge,
			IdleTimeout:  config.IdleTimeout,
			TLSConfig: func() *tls.Config {
				if config.RedisTLSEnabled {
					return &tls.Config{InsecureSkipVerify: false}
				}
				return nil
			}(),
		})
	}

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Initialize rate limiter
	var rateLimiter *rate.Limiter
	if config.RateLimitEnabled {
		rateLimiter = rate.NewLimiter(rate.Limit(config.RateLimitRPS), config.RateLimitBurst)
	}

	// Initialize metrics
	var metrics *ProxyMetrics
	if config.MetricsEnabled {
		metrics = NewProxyMetrics()
		metrics.Register()
	}

	// Initialize cache
	var cache *LocalCache
	if config.EnableLocalCache {
		cache = NewLocalCache(config.CacheTTL, config.CacheSize)
	}
	proxy := &RedisProxy{
		config:          config,
		redisClient:     rdb,
		commandHandlers: make(map[string]CommandHandler),
		rateLimiter:     rateLimiter,
		logger:          logger,
		metrics:         metrics,
		cache:           cache,
		isHealthy:       1,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}

	// Initialize read replicas
	if config.EnableReadReplicas {
		if err := proxy.initReadReplicas(); err != nil {
			logger.Warn("Failed to initialize read replicas", zap.Error(err))
		}
	}

	// Register command handlers
	proxy.registerCommandHandlers()

	// Start health check
	go proxy.startHealthCheck()

	return proxy, nil
}

func (p *RedisProxy) initReadReplicas() error {
	if len(p.config.ReadReplicaNodes) == 0 {
		// Use main client as fallback
		p.readReplicas = []redis.UniversalClient{p.redisClient}
		return nil
	}

	p.readReplicas = make([]redis.UniversalClient, 0, len(p.config.ReadReplicaNodes))
	
	for _, addr := range p.config.ReadReplicaNodes {
		replica := redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     p.config.RedisPassword,
			DB:           p.config.RedisDB,
			MaxRetries:   p.config.MaxRetries,
			ReadTimeout:  p.config.ReadTimeout,
			WriteTimeout: p.config.WriteTimeout,
			PoolSize:     p.config.PoolSize,
			MaxConnAge:   p.config.MaxConnAge,
			IdleTimeout:  p.config.IdleTimeout,
			TLSConfig: func() *tls.Config {
				if p.config.RedisTLSEnabled {
					return &tls.Config{InsecureSkipVerify: false}
				}
				return nil
			}(),
		})

		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := replica.Ping(ctx).Err(); err != nil {
			cancel()
			p.logger.Warn("Failed to connect to read replica", zap.String("addr", addr), zap.Error(err))
			continue
		}
		cancel()

		p.readReplicas = append(p.readReplicas, replica)
	}

	if len(p.readReplicas) == 0 {
		return fmt.Errorf("no read replicas available")
	}

	p.logger.Info("Initialized read replicas", zap.Int("count", len(p.readReplicas)))
	return nil
}

func (p *RedisProxy) startHealthCheck() {
	if p.config.HealthCheckInterval == 0 {
		p.config.HealthCheckInterval = 30 * time.Second
	}

	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.performHealthCheck()
	}
}

func (p *RedisProxy) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check main Redis connection
	if err := p.redisClient.Ping(ctx).Err(); err != nil {
		atomic.StoreInt32(&p.isHealthy, 0)
		p.logger.Error("Main Redis health check failed", zap.Error(err))
		if p.metrics != nil {
			p.metrics.ErrorsTotal.WithLabelValues("health_check").Inc()
		}
		return
	}

	// Check read replicas
	healthyReplicas := 0
	for _, replica := range p.readReplicas {
		if err := replica.Ping(ctx).Err(); err == nil {
			healthyReplicas++
		}
	}

	if healthyReplicas == 0 && len(p.readReplicas) > 0 {
		p.logger.Warn("No healthy read replicas available")
	}

	atomic.StoreInt32(&p.isHealthy, 1)
}

func (p *RedisProxy) registerCommandHandlers() {
	// Read-only commands that can use read replicas
	readOnlyCommands := map[string]bool{
		"GET": true, "MGET": true, "EXISTS": true, "TTL": true, "PTTL": true,
		"STRLEN": true, "GETRANGE": true, "GETBIT": true, "HGET": true,
		"HMGET": true, "HGETALL": true, "HKEYS": true, "HVALS": true,
		"LRANGE": true, "LLEN": true, "LINDEX": true, "SCARD": true,
		"SMEMBERS": true, "SISMEMBER": true, "ZCARD": true, "ZCOUNT": true,
		"ZRANGE": true, "ZREVRANGE": true, "ZSCORE": true, "ZRANK": true,
		"ZREVRANK": true, "TYPE": true, "SCAN": true, "SSCAN": true,
		"HSCAN": true, "ZSCAN": true, "KEYS": true, "RANDOMKEY": true,
	}

	// Register handlers for special commands
	p.commandHandlers["SET"] = p.handleSetCommand
	p.commandHandlers["MGET"] = p.handleMGetCommand
	p.commandHandlers["MSET"] = p.handleMSetCommand
	p.commandHandlers["EVAL"] = p.handleEvalCommand
	p.commandHandlers["EVALSHA"] = p.handleEvalShaCommand
	p.commandHandlers["PING"] = p.handlePingCommand
	p.commandHandlers["INFO"] = p.handleInfoCommand
	p.commandHandlers["FLUSHALL"] = p.handleFlushAllCommand
	p.commandHandlers["FLUSHDB"] = p.handleFlushDBCommand

	// Register read-only command handler
	for cmd := range readOnlyCommands {
		p.commandHandlers[cmd] = p.handleReadOnlyCommand
	}
}

// HTTP Server setup
func (p *RedisProxy) setupHTTPServer() *http.Server {
	router := mux.NewRouter()

	// CORS setup
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	// Apply middlewares
	router.Use(p.loggingMiddleware)
	if p.config.MetricsEnabled {
		router.Use(p.metricsMiddleware)
	}
	if p.config.RateLimitEnabled {
		router.Use(p.rateLimitMiddleware)
	}
	router.Use(p.authMiddleware)

	// Routes
	router.HandleFunc("/", p.handleRedisCommand).Methods("POST", "OPTIONS")
	router.HandleFunc("/pipeline", p.handlePipeline).Methods("POST", "OPTIONS")
	router.HandleFunc("/multi-exec", p.handleMultiExec).Methods("POST", "OPTIONS")
	
	// Health and metrics endpoints
	router.HandleFunc("/health", p.handleHealth).Methods("GET")
	router.HandleFunc("/ready", p.handleReady).Methods("GET")
	router.HandleFunc("/stats", p.handleStats).Methods("GET")
	
	if p.config.MetricsEnabled {
		router.Handle("/metrics", promhttp.Handler()).Methods("GET")
	}

	// WebSocket endpoint for streaming (if enabled)
	if p.config.EnableStreaming {
		router.HandleFunc("/stream", p.handleWebSocket).Methods("GET")
	}

	handler := c.Handler(router)

	server := &http.Server{
		Addr:         ":" + p.config.Port,
		Handler:      handler,
		ReadTimeout:  p.config.ReadTimeout,
		WriteTimeout: p.config.WriteTimeout,
		IdleTimeout:  p.config.IdleTimeout,
	}

	return server
}

// Start the proxy server
func (p *RedisProxy) Start() error {
	p.httpServer = p.setupHTTPServer()

	p.logger.Info("Starting Upstash-compatible Redis proxy",
		zap.String("port", p.config.Port),
		zap.Bool("tls_enabled", p.config.TLSCertFile != ""),
		zap.Bool("cluster_mode", p.config.RedisClusterMode),
		zap.Int("read_replicas", len(p.readReplicas)),
	)

	// Graceful shutdown
	go p.handleShutdown()

	if p.config.TLSCertFile != "" && p.config.TLSKeyFile != "" {
		return p.httpServer.ListenAndServeTLS(p.config.TLSCertFile, p.config.TLSKeyFile)
	}

	return p.httpServer.ListenAndServe()
}

func (p *RedisProxy) handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	p.logger.Info("Received shutdown signal, gracefully shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := p.httpServer.Shutdown(ctx); err != nil {
		p.logger.Error("Server shutdown error", zap.Error(err))
	}

	// Close Redis connections
	if err := p.redisClient.Close(); err != nil {
		p.logger.Error("Error closing Redis client", zap.Error(err))
	}

	for _, replica := range p.readReplicas {
		if err := replica.Close(); err != nil {
			p.logger.Error("Error closing replica client", zap.Error(err))
		}
	}

	p.logger.Info("Server shutdown complete")
	os.Exit(0)
}

// Middleware functions
func (p *RedisProxy) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		p.logger.Debug("Request processed",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Duration("duration", time.Since(start)),
			zap.String("remote_addr", r.RemoteAddr),
		)
	})
}

func (p *RedisProxy) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health checks and metrics
		if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		if p.config.AuthToken == "" && p.config.JWTSecret == "" && !p.config.EnableHMAC {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			p.sendErrorResponse(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		// Handle Bearer token
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			
			// Simple token validation
			if p.config.AuthToken != "" && token == p.config.AuthToken {
				next.ServeHTTP(w, r)
				return
			}

			// JWT validation
			if p.config.JWTSecret != "" {
				if p.validateJWT(token) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// Handle HMAC authentication
		if p.config.EnableHMAC {
			if p.validateHMAC(r) {
				next.ServeHTTP(w, r)
				return
			}
		}

		p.sendErrorResponse(w, "Invalid authentication", http.StatusUnauthorized)
	})
}

func (p *RedisProxy) validateJWT(tokenString string) bool {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.config.JWTSecret), nil
	})

	if err != nil {
		return false
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims.ExpiresAt.After(time.Now())
	}

	return false
}

func (p *RedisProxy) validateHMAC(r *http.Request) bool {
	signature := r.Header.Get("X-Upstash-Signature")
	if signature == "" {
		return false
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}

	// Reset body for further reading
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	mac := hmac.New(sha256.New, []byte(p.config.HMACSecret))
	mac.Write(body)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func (p *RedisProxy) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.rateLimiter != nil {
			if !p.rateLimiter.Allow() {
				p.sendErrorResponse(w, "Rate limit exceeded", http.StatusTooManyRequests)
				if p.metrics != nil {
					p.metrics.ErrorsTotal.WithLabelValues("rate_limit").Inc()
				}
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
// Core structures
type UpstashRequest struct {
	Command []interface{} `json:"command"`
}

type UpstashResponse struct {
	Result interface{} `json:"result"`
	Error  string      `json:"error,omitempty"`
}

type PipelineRequest []UpstashRequest

type MultiExecRequest struct {
	Commands []UpstashRequest `json:"commands"`
}

type ProxyConfig struct {
	// Redis Configuration
	RedisAddr         string        `json:"redis_addr" env:"REDIS_ADDR"`
	RedisPassword     string        `json:"redis_password" env:"REDIS_PASSWORD"`
	RedisDB           int           `json:"redis_db" env:"REDIS_DB"`
	RedisClusterMode  bool          `json:"redis_cluster_mode" env:"REDIS_CLUSTER_MODE"`
	RedisClusterNodes []string      `json:"redis_cluster_nodes" env:"REDIS_CLUSTER_NODES"`
	RedisTLSEnabled   bool          `json:"redis_tls_enabled" env:"REDIS_TLS_ENABLED"`

	// Server Configuration
	Port        string `json:"port" env:"PORT"`
	TLSCertFile string `json:"tls_cert_file" env:"TLS_CERT_FILE"`
	TLSKeyFile  string `json:"tls_key_file" env:"TLS_KEY_FILE"`

	// Authentication & Security
	AuthToken  string `json:"auth_token" env:"AUTH_TOKEN"`
	JWTSecret  string `json:"jwt_secret" env:"JWT_SECRET"`
	EnableHMAC bool   `json:"enable_hmac" env:"ENABLE_HMAC"`
	HMACSecret string `json:"hmac_secret" env:"HMAC_SECRET"`

	// Performance
	MaxRetries   int           `json:"max_retries" env:"MAX_RETRIES"`
	RetryBackoff time.Duration `json:"retry_backoff" env:"RETRY_BACKOFF"`
	ReadTimeout  time.Duration `json:"read_timeout" env:"READ_TIMEOUT"`
	WriteTimeout time.Duration `json:"write_timeout" env:"WRITE_TIMEOUT"`
	PoolSize     int           `json:"pool_size" env:"POOL_SIZE"`
	MaxConnAge   time.Duration `json:"max_conn_age" env:"MAX_CONN_AGE"`
	IdleTimeout  time.Duration `json:"idle_timeout" env:"IDLE_TIMEOUT"`

	// Features
	ResponseEncoding   string `json:"response_encoding" env:"RESPONSE_ENCODING"`
	EnablePipeline     bool   `json:"enable_pipeline" env:"ENABLE_PIPELINE"`
	EnableStreaming    bool   `json:"enable_streaming" env:"ENABLE_STREAMING"`
	EnableReadReplicas bool   `json:"enable_read_replicas" env:"ENABLE_READ_REPLICAS"`

	// Rate Limiting
	RateLimitEnabled bool `json:"rate_limit_enabled" env:"RATE_LIMIT_ENABLED"`
	RateLimitRPS     int  `json:"rate_limit_rps" env:"RATE_LIMIT_RPS"`
	RateLimitBurst   int  `json:"rate_limit_burst" env:"RATE_LIMIT_BURST"`

	// Monitoring
	MetricsEnabled bool   `json:"metrics_enabled" env:"METRICS_ENABLED"`
	LogLevel       string `json:"log_level" env:"LOG_LEVEL"`

	// Caching
	EnableLocalCache bool          `json:"enable_local_cache" env:"ENABLE_LOCAL_CACHE"`
	CacheTTL         time.Duration `json:"cache_ttl" env:"CACHE_TTL"`
	CacheSize        int           `json:"cache_size" env:"CACHE_SIZE"`

	// Connection Pool
	ReadReplicaNodes []string `json:"read_replica_nodes" env:"READ_REPLICA_NODES"`

	// Health Check
	HealthCheckInterval time.Duration `json:"health_check_interval" env:"HEALTH_CHECK_INTERVAL"`
}




// Continue from the main Redis command handler
func (p *RedisProxy) handleRedisCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.sendErrorResponse(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var upstashReq UpstashRequest
	if err := json.Unmarshal(body, &upstashReq); err != nil {
		p.sendErrorResponse(w, "Invalid JSON in request body", http.StatusBadRequest)
		return
	}

	if len(upstashReq.Command) == 0 {
		p.sendErrorResponse(w, "Empty command", http.StatusBadRequest)
		return
	}

	// Handle sync token for read-your-writes consistency
	syncToken := r.Header.Get("upstash-sync-token")
	if syncToken != "" {
		p.waitForSyncToken(syncToken)
	}

	// Execute command
	result, err := p.executeCommand(r.Context(), upstashReq.Command)
	if err != nil {
		p.sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate new sync token for write operations
	newSyncToken := p.generateSyncToken(upstashReq.Command)

	response := UpstashResponse{Result: result}
	p.sendJSONResponse(w, response, newSyncToken)
}

func (p *RedisProxy) executeCommand(ctx context.Context, command []interface{}) (interface{}, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	cmdName := strings.ToUpper(fmt.Sprintf("%v", command[0]))
	args := command[1:]

	// Update metrics
	if p.metrics != nil {
		p.metrics.CommandsTotal.WithLabelValues(cmdName).Inc()
	}

	// Check local cache first for read operations
	if p.cache != nil && p.isReadOnlyCommand(cmdName) {
		cacheKey := p.buildCacheKey(command)
		if cached, found := p.cache.Get(cacheKey); found {
			if p.metrics != nil {
				p.metrics.CacheHits.Inc()
			}
			return cached, nil
		}
		if p.metrics != nil {
			p.metrics.CacheMisses.Inc()
		}
	}

	// Use command handler if available
	if handler, exists := p.commandHandlers[cmdName]; exists {
		result, err := handler(ctx, p.redisClient, args)
		if err == nil && p.cache != nil && p.isReadOnlyCommand(cmdName) {
			cacheKey := p.buildCacheKey(command)
			p.cache.Set(cacheKey, result)
		}
		return result, err
	}

	// Default command execution
	client := p.selectClient(cmdName)
	cmd := client.Do(ctx, command...)
	if cmd != nil {
		result, err := cmd.Result()
		if err != nil {
			return nil, err
		}
		if p.cache != nil && p.isReadOnlyCommand(cmdName) {
			cacheKey := p.buildCacheKey(command)
			p.cache.Set(cacheKey, result)
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown command result type")
}

func (p *RedisProxy) selectClient(cmdName string) redis.UniversalClient {
	if p.isReadOnlyCommand(cmdName) && len(p.readReplicas) > 0 {
		// Round-robin selection of read replicas
		index := atomic.AddUint64(&p.replicaCounter, 1) % uint64(len(p.readReplicas))
		return p.readReplicas[index]
	}
	return p.redisClient
}

func (p *RedisProxy) isReadOnlyCommand(cmdName string) bool {
	readOnlyCommands := map[string]bool{
		"GET": true, "MGET": true, "EXISTS": true, "TTL": true, "PTTL": true,
		"STRLEN": true, "GETRANGE": true, "GETBIT": true, "HGET": true, "HMGET": true,
		"HGETALL": true, "HKEYS": true, "HVALS": true, "LRANGE": true, "LLEN": true,
		"LINDEX": true, "SCARD": true, "SMEMBERS": true, "SISMEMBER": true, "ZCARD": true,
		"ZCOUNT": true, "ZRANGE": true, "ZREVRANGE": true, "ZSCORE": true, "ZRANK": true,
		"ZREVRANK": true, "TYPE": true, "SCAN": true, "SSCAN": true, "HSCAN": true,
		"ZSCAN": true, "KEYS": true, "RANDOMKEY": true, "PING": true, "INFO": true,
	}
	return readOnlyCommands[cmdName]
}

func (p *RedisProxy) buildCacheKey(command []interface{}) string {
	var keyParts []string
	for _, part := range command {
		keyParts = append(keyParts, fmt.Sprintf("%v", part))
	}
	return strings.Join(keyParts, ":")
}

// Command handlers
func (p *RedisProxy) handleSetCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("SET requires at least 2 arguments")
	}
	
	key := fmt.Sprintf("%v", args[0])
	value := args[1]
	
	// Handle SET with options (EX, PX, NX, XX, etc.)
	cmd := redis.NewStatusCmd(ctx, append([]interface{}{"SET", key, value}, args[2:]...)...)
	client.Process(ctx, cmd)
	return cmd.Result()
}

func (p *RedisProxy) handleMGetCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("MGET requires at least 1 argument")
	}
	
	keys := make([]string, len(args))
	for i, arg := range args {
		keys[i] = fmt.Sprintf("%v", arg)
	}
	
	return client.MGet(ctx, keys...).Result()
}

func (p *RedisProxy) handleMSetCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	if len(args)%2 != 0 {
		return nil, fmt.Errorf("MSET requires an even number of arguments")
	}
	
	pairs := make([]interface{}, len(args))
	copy(pairs, args)
	
	return client.MSet(ctx, pairs...).Result()
}

func (p *RedisProxy) handleEvalCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("EVAL requires at least 2 arguments")
	}
	
	script := fmt.Sprintf("%v", args[0])
	numKeys, err := strconv.Atoi(fmt.Sprintf("%v", args[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid number of keys: %v", err)
	}
	
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		if i+2 >= len(args) {
			return nil, fmt.Errorf("not enough keys provided")
		}
		keys[i] = fmt.Sprintf("%v", args[i+2])
	}
	
	values := args[numKeys+2:]
	
	return client.Eval(ctx, script, keys, values...).Result()
}

func (p *RedisProxy) handleEvalShaCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("EVALSHA requires at least 2 arguments")
	}
	
	sha := fmt.Sprintf("%v", args[0])
	numKeys, err := strconv.Atoi(fmt.Sprintf("%v", args[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid number of keys: %v", err)
	}
	
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		if i+2 >= len(args) {
			return nil, fmt.Errorf("not enough keys provided")
		}
		keys[i] = fmt.Sprintf("%v", args[i+2])
	}
	
	values := args[numKeys+2:]
	
	return client.EvalSha(ctx, sha, keys, values...).Result()
}

func (p *RedisProxy) handlePingCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	if len(args) == 0 {
		return client.Ping(ctx).Result()
	}
	// message := fmt.Sprintf("%v", args[0])
	return client.Ping(ctx).Result() // Redis PING with message not directly supported, return PONG
}

func (p *RedisProxy) handleInfoCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	if len(args) == 0 {
		return client.Info(ctx).Result()
	}
	section := fmt.Sprintf("%v", args[0])
	return client.Info(ctx, section).Result()
}

func (p *RedisProxy) handleFlushAllCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	return client.FlushAll(ctx).Result()
}

func (p *RedisProxy) handleFlushDBCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	return client.FlushDB(ctx).Result()
}

func (p *RedisProxy) handleReadOnlyCommand(ctx context.Context, client redis.UniversalClient, args []interface{}) (interface{}, error) {
	// Use read replica if available
	readClient := p.selectClient("GET") // Use GET as proxy for read-only
	cmd := readClient.Do(ctx, args...)
	return cmd.Result()
}

// Pipeline handling
func (p *RedisProxy) handlePipeline(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		return
	}

	if !p.config.EnablePipeline {
		p.sendErrorResponse(w, "Pipeline is disabled", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.sendErrorResponse(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var pipelineReq PipelineRequest
	if err := json.Unmarshal(body, &pipelineReq); err != nil {
		p.sendErrorResponse(w, "Invalid JSON in request body", http.StatusBadRequest)
		return
	}

	if len(pipelineReq) == 0 {
		p.sendErrorResponse(w, "Empty pipeline", http.StatusBadRequest)
		return
	}

	// Execute pipeline
	results := make([]UpstashResponse, len(pipelineReq))
	pipe := p.redisClient.Pipeline()

	// Add commands to pipeline
	cmds := make([]redis.Cmder, len(pipelineReq))
	for i, req := range pipelineReq {
		if len(req.Command) == 0 {
			results[i] = UpstashResponse{Error: "empty command"}
			continue
		}
		cmds[i] = pipe.Do(r.Context(), req.Command...)
	}

	// Execute pipeline
	_, err = pipe.Exec(r.Context())
	if err != nil && err != redis.Nil {
		p.logger.Error("Pipeline execution failed", zap.Error(err))
	}

	// Collect results
	for i, cmd := range cmds {
		if cmd == nil {
			continue
		}
		if resCmd, ok := cmd.(interface{ Result() (interface{}, error) }); ok {
			result, err := resCmd.Result()
			if err != nil {
				results[i] = UpstashResponse{Error: err.Error()}
			} else {
				results[i] = UpstashResponse{Result: result}
			}
		} else {
			results[i] = UpstashResponse{Error: "unknown command result type"}
		}
	}

	p.sendJSONResponse(w, results, "")
}

// Multi-Exec handling
func (p *RedisProxy) handleMultiExec(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.sendErrorResponse(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var multiReq MultiExecRequest
	if err := json.Unmarshal(body, &multiReq); err != nil {
		p.sendErrorResponse(w, "Invalid JSON in request body", http.StatusBadRequest)
		return
	}

	if len(multiReq.Commands) == 0 {
		p.sendErrorResponse(w, "Empty transaction", http.StatusBadRequest)
		return
	}

	// Execute transaction
	tx := p.redisClient.TxPipeline()
	cmds := make([]redis.Cmder, len(multiReq.Commands))

	for i, req := range multiReq.Commands {
		if len(req.Command) == 0 {
			continue
		}
		cmds[i] = tx.Do(r.Context(), req.Command...)
	}

	results, err := tx.Exec(r.Context())
	if err != nil {
		p.sendErrorResponse(w, fmt.Sprintf("Transaction failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert results to Upstash format
	response := make([]UpstashResponse, len(results))
	for i, result := range results {
		if cmd, ok := result.(interface{ Result() (interface{}, error) }); ok {
			val, err := cmd.Result()
			if err != nil {
				response[i] = UpstashResponse{Error: err.Error()}
			} else {
				response[i] = UpstashResponse{Result: val}
			}
		} else {
			response[i] = UpstashResponse{Error: "unknown command result type"}
		}
	}

	p.sendJSONResponse(w, response, "")
}

// WebSocket handling for streaming
func (p *RedisProxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !p.config.EnableStreaming {
		p.sendErrorResponse(w, "Streaming is disabled", http.StatusForbidden)
		return
	}

	conn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.logger.Error("WebSocket upgrade failed", zap.Error(err))
		return
	}
	defer conn.Close()

	p.logger.Info("WebSocket connection established", zap.String("remote_addr", r.RemoteAddr))

	for {
		var req UpstashRequest
		if err := conn.ReadJSON(&req); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				p.logger.Error("WebSocket read error", zap.Error(err))
			}
			break
		}

		// Execute command
		result, err := p.executeCommand(r.Context(), req.Command)
		
		var response UpstashResponse
		if err != nil {
			response = UpstashResponse{Error: err.Error()}
		} else {
			response = UpstashResponse{Result: result}
		}

		if err := conn.WriteJSON(response); err != nil {
			p.logger.Error("WebSocket write error", zap.Error(err))
			break
		}
	}
}

// Health and status endpoints
func (p *RedisProxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&p.isHealthy) == 1 {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("UNHEALTHY"))
	}
}

func (p *RedisProxy) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := p.redisClient.Ping(ctx).Err(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("NOT READY"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("READY"))
}

func (p *RedisProxy) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"uptime":             time.Since(time.Now()).String(), // This would need to be tracked properly
		"total_connections":  "N/A", // Would need connection tracking
		"healthy":            atomic.LoadInt32(&p.isHealthy) == 1,
		"read_replicas":      len(p.readReplicas),
		"cluster_mode":       p.config.RedisClusterMode,
		"cache_enabled":      p.config.EnableLocalCache,
		"pipeline_enabled":   p.config.EnablePipeline,
		"streaming_enabled":  p.config.EnableStreaming,
		"metrics_enabled":    p.config.MetricsEnabled,
		"rate_limit_enabled": p.config.RateLimitEnabled,
	}

	if p.cache != nil {
		hits, misses, size := p.cache.Stats()
		stats["cache_stats"] = map[string]interface{}{
			"hits":   hits,
			"misses": misses,
			"size":   size,
		}
	}

	p.sendJSONResponse(w, stats, "")
}

// Sync token management for read-your-writes consistency
func (p *RedisProxy) generateSyncToken(command []interface{}) string {
	if len(command) == 0 {
		return ""
	}

	cmdName := strings.ToUpper(fmt.Sprintf("%v", command[0]))
	if p.isReadOnlyCommand(cmdName) {
		return ""
	}

	// Generate a simple timestamp-based token
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	p.syncTokens.Store(token, time.Now())
	return token
}

func (p *RedisProxy) waitForSyncToken(token string) {
	if val, ok := p.syncTokens.Load(token); ok {
		tokenTime := val.(time.Time)
		// Simple wait - in production, you might want more sophisticated sync mechanisms
		elapsed := time.Since(tokenTime)
		if elapsed < 100*time.Millisecond {
			time.Sleep(100*time.Millisecond - elapsed)
		}
	}
}


func (p *RedisProxy) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.metrics == nil {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		p.metrics.ActiveConnections.Inc()
		defer func() {
			p.metrics.ActiveConnections.Dec()
			p.metrics.RequestsTotal.Inc()
			p.metrics.RequestDuration.Observe(time.Since(start).Seconds())
		}()

		next.ServeHTTP(w, r)
	})
}

// Utility functions
func (p *RedisProxy) sendJSONResponse(w http.ResponseWriter, data interface{}, syncToken string) {
	w.Header().Set("Content-Type", "application/json")
	if syncToken != "" {
		w.Header().Set("upstash-sync-token", syncToken)
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		p.logger.Error("Failed to encode JSON response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (p *RedisProxy) sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := UpstashResponse{Error: message}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.logger.Error("Failed to encode error response", zap.Error(err))
	}

	if p.metrics != nil {
		p.metrics.ErrorsTotal.WithLabelValues(fmt.Sprintf("%d", statusCode)).Inc()
	}
}

// Configuration loading
func LoadConfig() *ProxyConfig {
	config := &ProxyConfig{
		// Default values
		RedisAddr:           getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:       getEnv("REDIS_PASSWORD", ""),
		RedisDB:             getEnvInt("REDIS_DB", 0),
		RedisClusterMode:    getEnvBool("REDIS_CLUSTER_MODE", false),
		RedisTLSEnabled:     getEnvBool("REDIS_TLS_ENABLED", false),
		Port:                getEnv("PORT", "8080"),
		TLSCertFile:         getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:          getEnv("TLS_KEY_FILE", ""),
		AuthToken:           getEnv("AUTH_TOKEN", ""),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		EnableHMAC:          getEnvBool("ENABLE_HMAC", false),
		HMACSecret:          getEnv("HMAC_SECRET", ""),
		MaxRetries:          getEnvInt("MAX_RETRIES", 3),
		RetryBackoff:        getEnvDuration("RETRY_BACKOFF", 100*time.Millisecond),
		ReadTimeout:         getEnvDuration("READ_TIMEOUT", 30*time.Second),
		WriteTimeout:        getEnvDuration("WRITE_TIMEOUT", 30*time.Second),
		PoolSize:            getEnvInt("POOL_SIZE", 10),
		MaxConnAge:          getEnvDuration("MAX_CONN_AGE", 30*time.Minute),
		IdleTimeout:         getEnvDuration("IDLE_TIMEOUT", 5*time.Minute),
		ResponseEncoding:    getEnv("RESPONSE_ENCODING", "json"),
		EnablePipeline:      getEnvBool("ENABLE_PIPELINE", true),
		EnableStreaming:     getEnvBool("ENABLE_STREAMING", true),
		EnableReadReplicas:  getEnvBool("ENABLE_READ_REPLICAS", false),
		RateLimitEnabled:    getEnvBool("RATE_LIMIT_ENABLED", false),
		RateLimitRPS:        getEnvInt("RATE_LIMIT_RPS", 1000),
		RateLimitBurst:      getEnvInt("RATE_LIMIT_BURST", 100),
		MetricsEnabled:      getEnvBool("METRICS_ENABLED", true),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
		EnableLocalCache:    getEnvBool("ENABLE_LOCAL_CACHE", false),
		CacheTTL:            getEnvDuration("CACHE_TTL", 5*time.Minute),
		CacheSize:           getEnvInt("CACHE_SIZE", 10000),
		HealthCheckInterval: getEnvDuration("HEALTH_CHECK_INTERVAL", 30*time.Second),
	}

	// Parse cluster nodes
	if clusterNodes := getEnv("REDIS_CLUSTER_NODES", ""); clusterNodes != "" {
		config.RedisClusterNodes = strings.Split(clusterNodes, ",")
	}

	// Parse read replica nodes
	if replicaNodes := getEnv("READ_REPLICA_NODES", ""); replicaNodes != "" {
		config.ReadReplicaNodes = strings.Split(replicaNodes, ",")
	}

	return config
}

// Environment variable helpers
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration		
		}
	}
	return defaultValue
}

// Main function
func main() {
	config := LoadConfig()

	proxy, err := NewRedisProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}