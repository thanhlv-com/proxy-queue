package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type Config struct {
	ListenPort        int
	TargetHost        string
	TargetPort        int
	DelayMin          time.Duration
	DelayMax          time.Duration
	UseHTTPS          bool
	MaxQueueSize      int
	MetricsPort       int
	HealthPort        int
	LogLevel          string
	SharedHealthPort  bool
	SharedMetricsPort bool
	HeaderQueues      []string      // Headers to create separate queues for (e.g., ["X-Amz-Security-Token", "X-Amz-Content-Sha256"])
	Timeout           time.Duration // Request timeout (0 = infinite)
}

type ProxyRequest struct {
	ID       string
	Type     string // "http", "https", "socket"
	Data     interface{}
	Response chan ProxyResponse
}

type ProxyResponse struct {
	Data  interface{}
	Error error
}

type ProxyQueue struct {
	requests       chan ProxyRequest
	config         *Config
	mu             sync.RWMutex
	running        bool
	logger         *logrus.Logger
	metrics        *Metrics
	startTime      time.Time
	processedCount int64
	errorCount     int64
}

type QueueManager struct {
	mainQueue    *ProxyQueue
	headerQueues map[string]*ProxyQueue // key: header_name:header_value, value: dedicated queue
	config       *Config
	logger       *logrus.Logger
	mu           sync.RWMutex
}

type Metrics struct {
	requestsTotal   prometheus.Counter
	requestDuration prometheus.Histogram
	queueSize       prometheus.Gauge
	errorTotal      prometheus.Counter
	concurrentReqs  prometheus.Gauge
}

func NewMetrics() *Metrics {
	m := &Metrics{
		requestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total number of proxy requests processed",
		}),
		requestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "proxy_request_duration_seconds",
			Help:    "Duration of proxy requests in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		queueSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_queue_size",
			Help: "Current number of requests in queue",
		}),
		errorTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "proxy_errors_total",
			Help: "Total number of proxy errors",
		}),
		concurrentReqs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "proxy_concurrent_requests",
			Help: "Number of concurrent requests being processed",
		}),
	}

	prometheus.MustRegister(m.requestsTotal)
	prometheus.MustRegister(m.requestDuration)
	prometheus.MustRegister(m.queueSize)
	prometheus.MustRegister(m.errorTotal)
	prometheus.MustRegister(m.concurrentReqs)

	return m
}

func getIntFromEnvOrFlag(envKey string, flagValue *int) int {
	if envValue := os.Getenv(envKey); envValue != "" {
		if val, err := strconv.Atoi(envValue); err == nil {
			return val
		}
	}
	return *flagValue
}

func getStringFromEnvOrFlag(envKey string, flagValue *string) string {
	if envValue := os.Getenv(envKey); envValue != "" {
		return envValue
	}
	return *flagValue
}

func getBoolFromEnvOrFlag(envKey string, flagValue *bool) bool {
	if envValue := os.Getenv(envKey); envValue != "" {
		if val, err := strconv.ParseBool(envValue); err == nil {
			return val
		}
	}
	return *flagValue
}

func setupLogger(logLevel string) *logrus.Logger {
	logger := logrus.New()
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{})
	return logger
}

func (pq *ProxyQueue) logHTTPRequest(requestID string, data HTTPRequestData) {
	if pq.logger.Level < logrus.DebugLevel {
		return
	}

	r := data.Request

	// Read and log request body (if any)
	var bodyStr string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			bodyStr = string(bodyBytes)
			// Restore the body for further processing
			r.Body = io.NopCloser(strings.NewReader(bodyStr))
		}
	}

	// Prepare headers for logging
	headers := make(map[string]string)
	for key, values := range r.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// Log comprehensive request details
	pq.logger.WithFields(logrus.Fields{
		"request_id":     requestID,
		"method":         r.Method,
		"url":            r.URL.String(),
		"proto":          r.Proto,
		"headers":        headers,
		"content_length": r.ContentLength,
		"host":           r.Host,
		"remote_addr":    r.RemoteAddr,
		"request_uri":    r.RequestURI,
		"user_agent":     r.UserAgent(),
		"referer":        r.Referer(),
		"body":           bodyStr,
		"remote_ip":      data.RemoteIP,
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
	}).Debug("📥 HTTP Request Details")
}

func (pq *ProxyQueue) logHTTPResponse(requestID string, resp *http.Response, remoteIP string) {
	if pq.logger.Level < logrus.DebugLevel {
		return
	}

	// Read response body for logging
	var bodyStr string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyStr = string(bodyBytes)
			// Restore the body for further processing
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// Prepare headers for logging
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// Log comprehensive response details
	pq.logger.WithFields(logrus.Fields{
		"request_id":     requestID,
		"status_code":    resp.StatusCode,
		"status":         resp.Status,
		"proto":          resp.Proto,
		"headers":        headers,
		"content_length": resp.ContentLength,
		"body":           bodyStr,
		"remote_ip":      remoteIP,
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
	}).Debug("📤 HTTP Response Details")
}

func (pq *ProxyQueue) logSocketConnection(requestID string, data SocketRequestData, direction string, message string) {
	if pq.logger.Level < logrus.DebugLevel {
		return
	}

	pq.logger.WithFields(logrus.Fields{
		"request_id": requestID,
		"direction":  direction,
		"remote_ip":  data.RemoteIP,
		"local_addr": data.ClientConn.LocalAddr().String(),
		"message":    message,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
	}).Debug("🔌 Socket Connection Details")
}

func NewProxyQueue(config *Config) *ProxyQueue {
	return &ProxyQueue{
		requests:  make(chan ProxyRequest, config.MaxQueueSize),
		config:    config,
		running:   false,
		logger:    setupLogger(config.LogLevel),
		metrics:   NewMetrics(),
		startTime: time.Now(),
	}
}

func NewQueueManager(config *Config) *QueueManager {
	// Create shared metrics for all queues
	sharedMetrics := NewMetrics()

	// Create main queue with shared metrics
	mainQueue := &ProxyQueue{
		requests:  make(chan ProxyRequest, config.MaxQueueSize),
		config:    config,
		running:   false,
		logger:    setupLogger(config.LogLevel),
		metrics:   sharedMetrics,
		startTime: time.Now(),
	}

	return &QueueManager{
		mainQueue:    mainQueue,
		headerQueues: make(map[string]*ProxyQueue),
		config:       config,
		logger:       setupLogger(config.LogLevel),
	}
}

func (qm *QueueManager) Start(ctx context.Context) {
	qm.logger.Info("Starting queue manager")
	qm.mainQueue.Start(ctx)
}

func (qm *QueueManager) Stop() {
	qm.logger.Info("Stopping queue manager")
	qm.mainQueue.Stop()

	qm.mu.Lock()
	defer qm.mu.Unlock()
	for key, queue := range qm.headerQueues {
		qm.logger.WithField("queue_key", key).Debug("Stopping header queue")
		queue.Stop()
	}
}

func (qm *QueueManager) getQueueKey(headerName, headerValue string) string {
	return fmt.Sprintf("%s:%s", headerName, headerValue)
}

func (qm *QueueManager) getOrCreateHeaderQueue(ctx context.Context, headerName, headerValue string) *ProxyQueue {
	queueKey := qm.getQueueKey(headerName, headerValue)

	qm.mu.Lock()
	defer qm.mu.Unlock()

	if queue, exists := qm.headerQueues[queueKey]; exists {
		return queue
	}

	// Create new queue for this header value using shared metrics
	queue := &ProxyQueue{
		requests:  make(chan ProxyRequest, qm.config.MaxQueueSize),
		config:    qm.config,
		running:   false,
		logger:    setupLogger(qm.config.LogLevel),
		metrics:   qm.mainQueue.metrics, // Share metrics with main queue
		startTime: time.Now(),
	}

	qm.headerQueues[queueKey] = queue
	queue.Start(ctx)

	qm.logger.WithFields(logrus.Fields{
		"header_name":  headerName,
		"header_value": headerValue,
		"queue_key":    queueKey,
	}).Debug("🎟️ Created new header-based queue")

	return queue
}

func (qm *QueueManager) AddRequest(ctx context.Context, req ProxyRequest, headers map[string]string) error {
	// Check if request has any of the configured header queues
	for _, headerName := range qm.config.HeaderQueues {
		if headerValue, exists := headers[headerName]; exists && headerValue != "" {
			queue := qm.getOrCreateHeaderQueue(ctx, headerName, headerValue)
			qm.logger.WithFields(logrus.Fields{
				"request_id":   req.ID,
				"header_name":  headerName,
				"header_value": headerValue,
				"queue_type":   "header_queue",
			}).Debug("🚶‍♂️ Routing request to header-based queue")
			return queue.AddRequest(req)
		}
	}

	// Fallback to main queue
	qm.logger.WithFields(logrus.Fields{
		"request_id": req.ID,
		"queue_type": "main_queue",
	}).Debug("🔄 Routing request to main queue")
	return qm.mainQueue.AddRequest(req)
}

func (qm *QueueManager) getHealthStatus() map[string]interface{} {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	mainHealth := qm.mainQueue.getHealthStatus()
	headerQueueCount := len(qm.headerQueues)

	headerQueueStats := make(map[string]interface{})
	for key, queue := range qm.headerQueues {
		headerQueueStats[key] = queue.getHealthStatus()
	}

	return map[string]interface{}{
		"main_queue":         mainHealth,
		"header_queues":      headerQueueStats,
		"header_queue_count": headerQueueCount,
		"configured_headers": qm.config.HeaderQueues,
	}
}

func (pq *ProxyQueue) Start(ctx context.Context) {
	pq.mu.Lock()
	pq.running = true
	pq.mu.Unlock()

	pq.logger.Info("Starting proxy queue")
	go pq.processQueue(ctx)
}

func (pq *ProxyQueue) Stop() {
	pq.mu.Lock()
	pq.running = false
	pq.mu.Unlock()
	pq.logger.Info("Stopping proxy queue")
	close(pq.requests)
}

func (pq *ProxyQueue) AddRequest(req ProxyRequest) error {
	pq.mu.RLock()
	defer pq.mu.RUnlock()

	if !pq.running {
		pq.logger.Warn("Attempt to add request to stopped queue")
		return fmt.Errorf("proxy queue is not running")
	}

	select {
	case pq.requests <- req:
		pq.metrics.queueSize.Inc()
		pq.logger.WithFields(logrus.Fields{
			"request_id": req.ID,
			"type":       req.Type,
		}).Debug("Request added to queue")
		return nil
	default:
		pq.logger.Warn("Queue is full, rejecting request")
		return fmt.Errorf("queue is full")
	}
}

func (pq *ProxyQueue) processQueue(ctx context.Context) {
	pq.logger.Debug("🔄 Queue processing started")

	for {
		select {
		case <-ctx.Done():
			pq.logger.Info("Queue processing stopped due to context cancellation")
			return
		case req, ok := <-pq.requests:
			if !ok {
				pq.logger.Info("Queue processing stopped - channel closed")
				return
			}

			pq.metrics.queueSize.Dec()
			pq.metrics.concurrentReqs.Inc()
			start := time.Now()

			// Log queue processing details
			pq.logger.WithFields(logrus.Fields{
				"request_id":      req.ID,
				"request_type":    req.Type,
				"queue_length":    len(pq.requests),
				"processed_count": atomic.LoadInt64(&pq.processedCount),
				"timestamp":       start.UTC().Format(time.RFC3339Nano),
			}).Debug("⚙️ Processing request from queue")

			pq.processRequest(req)

			duration := time.Since(start)
			pq.metrics.requestDuration.Observe(duration.Seconds())
			pq.metrics.concurrentReqs.Dec()
			atomic.AddInt64(&pq.processedCount, 1)

			// Log processing completion
			pq.logger.WithFields(logrus.Fields{
				"request_id":      req.ID,
				"duration":        duration,
				"processed_count": atomic.LoadInt64(&pq.processedCount),
			}).Debug("✅ Request processing completed")

			// Add delay between requests
			delay := pq.calculateDelay()
			if delay > 0 {
				pq.logger.WithFields(logrus.Fields{
					"delay":      delay,
					"request_id": req.ID,
				}).Debug("⏳ Applying delay between requests")
				time.Sleep(delay)
			}
		}
	}
}

func (pq *ProxyQueue) calculateDelay() time.Duration {
	if pq.config.DelayMin == pq.config.DelayMax {
		return pq.config.DelayMin
	}

	diff := pq.config.DelayMax - pq.config.DelayMin
	randomDelay := time.Duration(time.Now().UnixNano() % int64(diff))
	return pq.config.DelayMin + randomDelay
}

func (pq *ProxyQueue) processRequest(req ProxyRequest) {
	pq.logger.WithFields(logrus.Fields{
		"request_id": req.ID,
		"type":       req.Type,
	}).Debug("Processing request")

	switch req.Type {
	case "http", "https":
		pq.processHTTPRequest(req)
	case "socket":
		pq.processSocketRequest(req)
	default:
		pq.logger.WithFields(logrus.Fields{
			"request_id": req.ID,
			"type":       req.Type,
		}).Error("Unsupported request type")
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
		req.Response <- ProxyResponse{
			Error: fmt.Errorf("unsupported request type: %s", req.Type),
		}
	}
	pq.metrics.requestsTotal.Inc()
}

func getHeaderQueuesFromEnv() []string {
	headerQueuesStr := os.Getenv("PROXY_HEADER_QUEUES")
	if headerQueuesStr == "" {
		return []string{}
	}
	return strings.Split(headerQueuesStr, ",")
}

func main() {
	var (
		listenPort        = flag.Int("port", 6789, "Port to listen on")
		targetHost        = flag.String("target-host", "localhost", "Target host to proxy to")
		targetPort        = flag.Int("target-port", 443, "Target port to proxy to")
		delayMin          = flag.Int("delay-min", 1000, "Minimum delay between requests (ms)")
		delayMax          = flag.Int("delay-max", 5000, "Maximum delay between requests (ms)")
		useHTTPS          = flag.Bool("https", true, "Use HTTPS for target")
		maxQueueSize      = flag.Int("queue-size", 1000, "Maximum queue size")
		metricsPort       = flag.Int("metrics-port", 9090, "Port for Prometheus metrics")
		healthPort        = flag.Int("health-port", 8081, "Port for health checks")
		logLevel          = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
		sharedHealthPort  = flag.Bool("shared-health-port", false, "Serve health checks on the same port as HTTP proxy")
		sharedMetricsPort = flag.Bool("shared-metrics-port", false, "Serve metrics on the same port as HTTP proxy")
		headerQueues      = flag.String("header-queues", "X-Amz-Security-Token", "Comma-separated list of headers to create separate queues for (e.g., 'X-Amz-Security-Token,Authorization')")
		timeout           = flag.Int("timeout", 0, "Request timeout in seconds (0 = infinite ⏳)")
	)
	flag.Parse()

	// Parse header queues from flag or environment
	var headerQueuesList []string
	if *headerQueues != "" {
		headerQueuesList = strings.Split(*headerQueues, ",")
	} else {
		headerQueuesList = getHeaderQueuesFromEnv()
	}

	config := &Config{
		ListenPort:        getIntFromEnvOrFlag("PROXY_LISTEN_PORT", listenPort),
		TargetHost:        getStringFromEnvOrFlag("PROXY_TARGET_HOST", targetHost),
		TargetPort:        getIntFromEnvOrFlag("PROXY_TARGET_PORT", targetPort),
		DelayMin:          time.Duration(getIntFromEnvOrFlag("PROXY_DELAY_MIN", delayMin)) * time.Millisecond,
		DelayMax:          time.Duration(getIntFromEnvOrFlag("PROXY_DELAY_MAX", delayMax)) * time.Millisecond,
		UseHTTPS:          getBoolFromEnvOrFlag("PROXY_USE_HTTPS", useHTTPS),
		MaxQueueSize:      getIntFromEnvOrFlag("PROXY_MAX_QUEUE_SIZE", maxQueueSize),
		MetricsPort:       getIntFromEnvOrFlag("PROXY_METRICS_PORT", metricsPort),
		HealthPort:        getIntFromEnvOrFlag("PROXY_HEALTH_PORT", healthPort),
		LogLevel:          getStringFromEnvOrFlag("PROXY_LOG_LEVEL", logLevel),
		SharedHealthPort:  getBoolFromEnvOrFlag("PROXY_SHARED_HEALTH_PORT", sharedHealthPort),
		SharedMetricsPort: getBoolFromEnvOrFlag("PROXY_SHARED_METRICS_PORT", sharedMetricsPort),
		HeaderQueues:      headerQueuesList,
		Timeout:           time.Duration(getIntFromEnvOrFlag("PROXY_TIMEOUT", timeout)) * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	queueManager := NewQueueManager(config)

	// Log detailed configuration at startup
	queueManager.logger.WithFields(logrus.Fields{
		"config": map[string]interface{}{
			"listen_port":         config.ListenPort,
			"target_host":         config.TargetHost,
			"target_port":         config.TargetPort,
			"delay_min":           config.DelayMin,
			"delay_max":           config.DelayMax,
			"use_https":           config.UseHTTPS,
			"max_queue_size":      config.MaxQueueSize,
			"metrics_port":        config.MetricsPort,
			"health_port":         config.HealthPort,
			"log_level":           config.LogLevel,
			"shared_health_port":  config.SharedHealthPort,
			"shared_metrics_port": config.SharedMetricsPort,
			"header_queues":       config.HeaderQueues,
			"timeout":             config.Timeout,
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}).Debug("🚀 Proxy Queue Manager Configuration Loaded")

	queueManager.Start(ctx)
	defer queueManager.Stop()

	// Start metrics server (only if not using shared port)
	if !config.SharedMetricsPort {
		queueManager.logger.Debug("📊 Starting dedicated metrics server")
		go startMetricsServer(config)
	} else {
		queueManager.logger.Debug("📊 Metrics will be served on HTTP proxy port")
	}

	// Start health check server (only if not using shared port)
	if !config.SharedHealthPort {
		queueManager.logger.Debug("❤️ Starting dedicated health server")
		go startHealthServer(queueManager, config)
	} else {
		queueManager.logger.Debug("❤️ Health checks will be served on HTTP proxy port")
	}

	// Start HTTP/HTTPS proxy server
	queueManager.logger.WithFields(logrus.Fields{
		"port": config.ListenPort,
		"protocol": map[string]bool{
			"http":  true,
			"https": config.UseHTTPS,
		},
	}).Debug("🌐 Starting HTTP proxy server")
	go startHTTPProxy(queueManager, config, ctx)

	// Start socket proxy server
	socketPort := config.ListenPort + 10
	queueManager.logger.WithFields(logrus.Fields{
		"port": socketPort,
	}).Debug("🔌 Starting socket proxy server")
	go startSocketProxy(queueManager, config, ctx)

	queueManager.logger.WithFields(logrus.Fields{
		"listen_port":   config.ListenPort,
		"socket_port":   socketPort,
		"target_host":   config.TargetHost,
		"target_port":   config.TargetPort,
		"delay_min":     config.DelayMin,
		"delay_max":     config.DelayMax,
		"log_level":     config.LogLevel,
		"header_queues": config.HeaderQueues,
		"timeout":       config.Timeout,
		"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
	}).Info("🎯 Proxy server started and ready to accept connections")

	select {}
}

type HTTPRequestData struct {
	Request  *http.Request
	Writer   http.ResponseWriter
	RemoteIP string
}

func startMetricsServer(config *Config) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.MetricsPort),
		Handler: mux,
	}

	logrus.WithField("port", config.MetricsPort).Info("Starting metrics server")
	if err := server.ListenAndServe(); err != nil {
		logrus.WithError(err).Error("Metrics server error")
	}
}

func startHealthServer(queueManager *QueueManager, config *Config) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health := queueManager.getHealthStatus()
		w.Header().Set("Content-Type", "application/json")

		// Determine overall status based on main queue
		mainQueue := health["main_queue"].(map[string]interface{})
		if mainQueue["status"] == "healthy" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Create comprehensive health response including header queues
		healthResponse := map[string]interface{}{
			"status":             mainQueue["status"],
			"uptime":             mainQueue["uptime"],
			"main_queue":         mainQueue,
			"header_queues":      health["header_queues"],
			"header_queue_count": health["header_queue_count"],
			"configured_headers": health["configured_headers"],
		}

		// Convert to JSON
		if jsonData, err := json.Marshal(healthResponse); err == nil {
			w.Write(jsonData)
		} else {
			fmt.Fprint(w, `{"status":"error","message":"failed to serialize health data"}`)
		}
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		queueManager.mu.RLock()
		running := queueManager.mainQueue.running
		queueManager.mu.RUnlock()

		if running {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Ready")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "Not Ready")
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.HealthPort),
		Handler: mux,
	}

	logrus.WithField("port", config.HealthPort).Info("Starting health check server")
	if err := server.ListenAndServe(); err != nil {
		logrus.WithError(err).Error("Health server error")
	}
}

func (pq *ProxyQueue) getHealthStatus() map[string]interface{} {
	pq.mu.RLock()
	running := pq.running
	pq.mu.RUnlock()

	processedCount := atomic.LoadInt64(&pq.processedCount)
	errorCount := atomic.LoadInt64(&pq.errorCount)
	uptime := time.Since(pq.startTime)
	queueLength := len(pq.requests)

	status := "healthy"
	if !running {
		status = "unhealthy"
	} else if errorCount > 0 && float64(errorCount)/float64(processedCount) > 0.1 {
		status = "degraded"
	}

	return map[string]interface{}{
		"status":             status,
		"uptime":             uptime.String(),
		"processed_requests": processedCount,
		"error_count":        errorCount,
		"queue_running":      running,
		"queue_length":       queueLength,
	}
}

func (pq *ProxyQueue) processHTTPRequest(req ProxyRequest) {
	data, ok := req.Data.(HTTPRequestData)
	if !ok {
		pq.logger.WithField("request_id", req.ID).Error("Invalid HTTP request data")
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
		req.Response <- ProxyResponse{
			Error: fmt.Errorf("invalid HTTP request data"),
		}
		return
	}

	// Log detailed request information at debug level
	pq.logHTTPRequest(req.ID, data)

	scheme := "http"
	if pq.config.UseHTTPS {
		scheme = "https"
	}

	targetURL := fmt.Sprintf("%s://%s:%d", scheme, pq.config.TargetHost, pq.config.TargetPort)
	target, err := url.Parse(targetURL)
	if err != nil {
		pq.logger.WithFields(logrus.Fields{
			"request_id": req.ID,
			"error":      err,
		}).Error("Failed to parse target URL")
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
		req.Response <- ProxyResponse{
			Error: err,
		}
		return
	}

	// Create new request to target
	targetReq := data.Request.Clone(data.Request.Context())
	targetReq.URL.Scheme = target.Scheme
	targetReq.URL.Host = target.Host
	targetReq.Host = target.Host
	targetReq.RequestURI = ""

	// Create HTTP client with configurable timeout
	timeout := 30 * time.Second // default timeout
	if pq.config.Timeout == 0 {
		timeout = pq.config.Timeout
	} else if pq.config.Timeout > 0 {
		timeout = pq.config.Timeout * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Forward the request
	resp, err := client.Do(targetReq)
	if err != nil {
		pq.logger.WithFields(logrus.Fields{
			"request_id": req.ID,
			"error":      err,
			"target_url": targetURL,
		}).Error("Failed to forward HTTP request")
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
		req.Response <- ProxyResponse{
			Error: err,
		}
		return
	}
	defer resp.Body.Close()

	// Log detailed response information at debug level
	pq.logHTTPResponse(req.ID, resp, data.RemoteIP)

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			data.Writer.Header().Add(key, value)
		}
	}

	// Set status code
	data.Writer.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(data.Writer, resp.Body)

	if err != nil {
		pq.logger.WithFields(logrus.Fields{
			"request_id": req.ID,
			"error":      err,
		}).Error("Failed to copy response body")
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
	} else {
		pq.logger.WithFields(logrus.Fields{
			"request_id":  req.ID,
			"status_code": resp.StatusCode,
			"remote_ip":   data.RemoteIP,
		}).Info("HTTP request processed successfully")
	}

	req.Response <- ProxyResponse{
		Data:  "HTTP request processed",
		Error: err,
	}
}

func registerHealthEndpoints(mux *http.ServeMux, queueManager *QueueManager) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health := queueManager.getHealthStatus()
		w.Header().Set("Content-Type", "application/json")

		// Determine overall status based on main queue
		mainQueue := health["main_queue"].(map[string]interface{})
		if mainQueue["status"] == "healthy" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		// Create comprehensive health response including header queues
		healthResponse := map[string]interface{}{
			"status":             mainQueue["status"],
			"uptime":             mainQueue["uptime"],
			"main_queue":         mainQueue,
			"header_queues":      health["header_queues"],
			"header_queue_count": health["header_queue_count"],
			"configured_headers": health["configured_headers"],
		}

		// Convert to JSON
		if jsonData, err := json.Marshal(healthResponse); err == nil {
			w.Write(jsonData)
		} else {
			fmt.Fprint(w, `{"status":"error","message":"failed to serialize health data"}`)
		}
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		queueManager.mu.RLock()
		running := queueManager.mainQueue.running
		queueManager.mu.RUnlock()

		if running {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Ready")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "Not Ready")
		}
	})
}

func registerMetricsEndpoints(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}

func startHTTPProxy(queueManager *QueueManager, config *Config, ctx context.Context) {
	mux := http.NewServeMux()

	// Register health endpoints if shared port is enabled
	if config.SharedHealthPort {
		registerHealthEndpoints(mux, queueManager)
		queueManager.logger.Info("Health endpoints registered on HTTP proxy port")
	}

	// Register metrics endpoints if shared port is enabled
	if config.SharedMetricsPort {
		registerMetricsEndpoints(mux)
		queueManager.logger.Info("Metrics endpoint registered on HTTP proxy port")
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Skip proxy processing for health and metrics endpoints when using shared ports
		if config.SharedHealthPort && (r.URL.Path == "/health" || r.URL.Path == "/ready") {
			// These are handled by registered health endpoints above
			return
		}
		if config.SharedMetricsPort && r.URL.Path == "/metrics" {
			// This is handled by registered metrics endpoint above
			return
		}

		requestID := fmt.Sprintf("http-%d", time.Now().UnixNano())
		startTime := time.Now()

		// Extract headers for queue routing
		headers := make(map[string]string)
		for key, values := range r.Header {
			if len(values) > 0 {
				headers[key] = values[0] // Use first value for header routing
			}
		}

		// Log incoming request at debug level with header info
		logFields := logrus.Fields{
			"request_id": requestID,
			"method":     r.Method,
			"url":        r.URL.String(),
			"remote_ip":  getClientIP(r),
			"user_agent": r.UserAgent(),
			"timestamp":  startTime.UTC().Format(time.RFC3339Nano),
		}

		// Add configured headers to log if they exist
		for _, headerName := range config.HeaderQueues {
			if headerValue, exists := headers[headerName]; exists {
				logFields[fmt.Sprintf("header_%s", strings.ToLower(headerName))] = headerValue
			}
		}

		queueManager.logger.WithFields(logFields).Debug("🌐 Incoming HTTP Request")

		responseChan := make(chan ProxyResponse, 1)

		proxyReq := ProxyRequest{
			ID:   requestID,
			Type: "http",
			Data: HTTPRequestData{
				Request:  r,
				Writer:   w,
				RemoteIP: getClientIP(r),
			},
			Response: responseChan,
		}

		err := queueManager.AddRequest(ctx, proxyReq, headers)
		if err != nil {
			queueManager.logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"error":      err,
				"remote_ip":  getClientIP(r),
				"duration":   time.Since(startTime),
			}).Warn("Failed to add HTTP request to queue")
			http.Error(w, fmt.Sprintf("Queue error: %v", err), http.StatusServiceUnavailable)
			return
		}

		// Wait for response with configurable timeout
		httpTimeout := 60 * time.Second // default timeout
		if config.Timeout == 0 {
			httpTimeout = 60 * time.Minute // default timeout
		} else if config.Timeout > 0 {
			httpTimeout = config.Timeout * time.Second
		}

		select {
		case response := <-responseChan:
			if response.Error != nil {
				queueManager.logger.WithFields(logrus.Fields{
					"request_id": requestID,
					"error":      response.Error,
					"duration":   time.Since(startTime),
				}).Error("HTTP proxy error")
				http.Error(w, fmt.Sprintf("Proxy error: %v", response.Error), http.StatusBadGateway)
			} else {
				queueManager.logger.WithFields(logrus.Fields{
					"request_id": requestID,
					"duration":   time.Since(startTime),
				}).Debug("✅ HTTP Request Completed Successfully")
			}
		case <-time.After(httpTimeout):
			queueManager.logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"duration":   time.Since(startTime),
				"timeout":    httpTimeout,
			}).Warn("HTTP request timeout")
			http.Error(w, "Request timeout", http.StatusGatewayTimeout)
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.ListenPort),
		Handler: mux,
	}

	logrus.WithField("port", config.ListenPort).Info("HTTP proxy server starting")
	if err := server.ListenAndServe(); err != nil {
		logrus.WithError(err).Error("HTTP server error")
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Use remote address
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

type SocketRequestData struct {
	ClientConn net.Conn
	RemoteIP   string
}

func (pq *ProxyQueue) processSocketRequest(req ProxyRequest) {
	data, ok := req.Data.(SocketRequestData)
	if !ok {
		pq.logger.WithField("request_id", req.ID).Error("Invalid socket request data")
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
		req.Response <- ProxyResponse{
			Error: fmt.Errorf("invalid socket request data"),
		}
		return
	}

	// Log socket connection initiation
	pq.logSocketConnection(req.ID, data, "incoming", "Client connection established")

	targetAddr := fmt.Sprintf("%s:%d", pq.config.TargetHost, pq.config.TargetPort)

	// Connect to target server with configurable timeout
	socketTimeout := 30 * time.Second // default timeout
	if pq.config.Timeout == 0 {
		socketTimeout = 30 * time.Minute
	} else if pq.config.Timeout > 0 {
		socketTimeout = pq.config.Timeout * time.Second
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, socketTimeout)
	if err != nil {
		pq.logger.WithFields(logrus.Fields{
			"request_id":  req.ID,
			"target_addr": targetAddr,
			"error":       err,
		}).Error("Failed to connect to target server")
		pq.logSocketConnection(req.ID, data, "outgoing", fmt.Sprintf("Failed to connect to target: %v", err))
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
		req.Response <- ProxyResponse{
			Error: fmt.Errorf("failed to connect to target: %v", err),
		}
		return
	}
	defer targetConn.Close()

	// Log successful target connection
	pq.logSocketConnection(req.ID, data, "outgoing", fmt.Sprintf("Connected to target server: %s", targetAddr))

	// Start bidirectional copying with enhanced logging
	done := make(chan error, 2)
	var bytesClientToTarget, bytesTargetToClient int64

	// Copy from client to target
	go func() {
		bytes, err := pq.copyWithLogging(targetConn, data.ClientConn, req.ID, data, "client-to-target")
		atomic.AddInt64(&bytesClientToTarget, bytes)
		done <- err
	}()

	// Copy from target to client
	go func() {
		bytes, err := pq.copyWithLogging(data.ClientConn, targetConn, req.ID, data, "target-to-client")
		atomic.AddInt64(&bytesTargetToClient, bytes)
		done <- err
	}()

	// Wait for either direction to finish
	err = <-done

	totalBytes := atomic.LoadInt64(&bytesClientToTarget) + atomic.LoadInt64(&bytesTargetToClient)

	if err != nil {
		pq.logger.WithFields(logrus.Fields{
			"request_id":        req.ID,
			"remote_ip":         data.RemoteIP,
			"error":             err,
			"bytes_transferred": totalBytes,
		}).Error("Socket connection error")
		pq.logSocketConnection(req.ID, data, "disconnect", fmt.Sprintf("Connection terminated with error: %v, bytes transferred: %d", err, totalBytes))
		pq.metrics.errorTotal.Inc()
		atomic.AddInt64(&pq.errorCount, 1)
	} else {
		pq.logger.WithFields(logrus.Fields{
			"request_id":        req.ID,
			"remote_ip":         data.RemoteIP,
			"bytes_transferred": totalBytes,
		}).Info("Socket connection processed successfully")
		pq.logSocketConnection(req.ID, data, "disconnect", fmt.Sprintf("Connection completed successfully, bytes transferred: %d", totalBytes))
	}

	req.Response <- ProxyResponse{
		Data:  "Socket connection processed",
		Error: err,
	}
}

func (pq *ProxyQueue) copyWithLogging(dst io.Writer, src io.Reader, requestID string, data SocketRequestData, direction string) (int64, error) {
	buffer := make([]byte, 32*1024) // 32KB buffer
	var totalBytes int64

	for {
		nr, err := src.Read(buffer)
		if nr > 0 {
			nw, ew := dst.Write(buffer[0:nr])
			if nw > 0 {
				totalBytes += int64(nw)
			}
			if ew != nil {
				pq.logSocketConnection(requestID, data, direction, fmt.Sprintf("Write error after %d bytes: %v", totalBytes, ew))
				return totalBytes, ew
			}
			if nr != nw {
				pq.logSocketConnection(requestID, data, direction, fmt.Sprintf("Short write: read %d, wrote %d", nr, nw))
				return totalBytes, io.ErrShortWrite
			}

			// Log data transfer at debug level
			if pq.logger.Level <= logrus.DebugLevel {
				pq.logger.WithFields(logrus.Fields{
					"request_id":   requestID,
					"direction":    direction,
					"bytes":        nw,
					"total_bytes":  totalBytes,
					"data_preview": fmt.Sprintf("%q", string(buffer[0:min(nr, 100)])), // Preview first 100 bytes
					"timestamp":    time.Now().UTC().Format(time.RFC3339Nano),
				}).Debug("📊 Socket Data Transfer")
			}
		}
		if err != nil {
			if err != io.EOF {
				pq.logSocketConnection(requestID, data, direction, fmt.Sprintf("Read error after %d bytes: %v", totalBytes, err))
			}
			return totalBytes, err
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func startSocketProxy(queueManager *QueueManager, config *Config, ctx context.Context) {
	socketPort := config.ListenPort + 10
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", socketPort))
	if err != nil {
		logrus.WithError(err).Error("Failed to start socket proxy")
		return
	}
	defer listener.Close()

	logrus.WithField("port", socketPort).Info("Socket proxy server starting")

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			logrus.WithError(err).Error("Failed to accept socket connection")
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			requestID := fmt.Sprintf("socket-%d", time.Now().UnixNano())
			responseChan := make(chan ProxyResponse, 1)

			proxyReq := ProxyRequest{
				ID:   requestID,
				Type: "socket",
				Data: SocketRequestData{
					ClientConn: conn,
					RemoteIP:   getSocketClientIP(conn),
				},
				Response: responseChan,
			}

			// Socket connections don't have headers, so always use main queue
			err := queueManager.AddRequest(ctx, proxyReq, make(map[string]string))
			if err != nil {
				queueManager.logger.WithFields(logrus.Fields{
					"error":     err,
					"remote_ip": getSocketClientIP(conn),
				}).Warn("Failed to add socket request to queue")
				return
			}

			// Wait for processing with configurable timeout
			socketConnTimeout := 300 * time.Second // default timeout
			if config.Timeout == 0 {
				socketConnTimeout = config.Timeout
			} else if config.Timeout > 0 {
				socketConnTimeout = config.Timeout * time.Second
			}

			select {
			case response := <-responseChan:
				if response.Error != nil {
					queueManager.logger.WithFields(logrus.Fields{
						"request_id": requestID,
						"error":      response.Error,
					}).Error("Socket proxy error")
				}
			case <-time.After(socketConnTimeout):
				queueManager.logger.WithFields(logrus.Fields{
					"request_id": requestID,
					"timeout":    socketConnTimeout,
				}).Warn("Socket connection timeout")
			}
		}(clientConn)
	}
}

func getSocketClientIP(conn net.Conn) string {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		addr := tcpConn.RemoteAddr()
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr.IP.String()
		}
	}
	return conn.RemoteAddr().String()
}
