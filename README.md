# Proxy Queue 🚀

A high-performance Go-based middleware proxy server that supports HTTP, HTTPS, and raw socket connections with
advanced queue-based request processing, comprehensive monitoring, and flexible configuration options.

## Features

- 🔗 **Multi-protocol support**: HTTP, HTTPS, and raw socket connections
- 📥 **Queue-based processing**: All requests are queued and processed sequentially with configurable queue size
  and header-based routing
- ⏱ **Configurable delays**: Set random delays between requests (min/max range in milliseconds)
- ⚙️ **Flexible configuration**: Environment variables and command-line flags with precedence handling
- 🛡️ **Connection management**: Proper timeout handling, resource cleanup, and context-based cancellation
- 📊 **Prometheus metrics**: Built-in metrics collection for monitoring request throughput, errors, and
  performance
- ❤️ **Health checks**: Comprehensive health and readiness endpoints with detailed status information
- 🌐 **Flexible port configuration**: Support for shared or dedicated ports for health checks and metrics
- 📝 **Structured logging**: JSON-formatted logs with configurable levels and detailed request/response tracking
- 🐳 **Docker support**: Ready-to-use Docker images with multi-stage builds and health checks
- 🔧 **Cross-platform builds**: Support for multiple architectures (Linux, macOS, Windows on AMD64/ARM64)

## Building

### Prerequisites

- Go 1.23.0 or later (using toolchain go1.24.7)
- Make (optional, for using Makefile)
- Docker and Docker Compose (optional, for containerized deployment)

### Quick Build

```bash
# Build for current platform
go build -o proxy-queue main.go

# Or use Makefile
make build
```

### Cross-Platform Building

Use the provided Makefile to build for different platforms:

```bash
# Build for specific platforms
make build-linux          # Linux x86_64
make build-linux-arm64     # Linux ARM64
make build-ubuntu          # Ubuntu (same as Linux x86_64)
make build-macos           # macOS x86_64
make build-macos-arm64     # macOS ARM64 (Apple Silicon)
make build-windows         # Windows x86_64
make build-windows-arm64   # Windows ARM64

# Build for all platforms
make build-all

# Create distribution packages
make dist
```

### Available Make Targets

```bash
make help                  # Show all available targets
make clean                 # Clean build artifacts
make deps                  # Install dependencies
make test                  # Run tests
make test-race             # Run tests with race detection
make lint                  # Run linter (requires golangci-lint)
make fmt                   # Format code
make vet                   # Vet code
make dev                   # Development build with debug info
make install               # Install to GOPATH/bin
make info                  # Show build information
make check-version         # Check Go version compatibility
```

## Usage

### Basic Usage

```bash
# Run with default settings (proxy to localhost:443 with HTTPS)
./proxy-queue

# Run with custom target
./proxy-queue -target-host=example.com -target-port=8080

# Run with HTTPS target
./proxy-queue -target-host=api.example.com -target-port=443 -https=true

# Configure delays and queue size
./proxy-queue -delay-min=1000 -delay-max=3000 -queue-size=500

# Configure request timeout (30 seconds for all timeout types)
./proxy-queue -timeout=30 -target-host=api.example.com

# Set longer timeout for slow APIs (120 seconds)
./proxy-queue -timeout=120 -target-host=slow-api.example.com

# Configure header-based queues for AWS requests
./proxy-queue -header-queues="X-Amz-Security-Token,Authorization" -target-host=api.example.com

# Full configuration example with timeout
./proxy-queue -target-host=thanhlv.com -target-port=443 -port=6789 -delay-min=1 -delay-max=5 -timeout=60

# Quick run with Makefile
make run                   # Build and run with defaults
make run-example           # Run with example configuration
```

### Configuration Options 🌍

The application supports both **environment variables** (prioritized) and **command line flags**. Environment
variables take precedence when both are provided.

| Environment Variable        | Command Line Flag      | Default              | Description                                  |
|-----------------------------|------------------------|----------------------|----------------------------------------------|
| `PROXY_LISTEN_PORT`         | `-port`                | 6789                 | Port to listen on                            |
| `PROXY_TARGET_HOST`         | `-target-host`         | localhost            | Target host to proxy to                      |
| `PROXY_TARGET_PORT`         | `-target-port`         | 443                  | Target port to proxy to                      |
| `PROXY_DELAY_MIN`           | `-delay-min`           | 1000                 | Minimum delay between requests (ms)          |
| `PROXY_DELAY_MAX`           | `-delay-max`           | 5000                 | Maximum delay between requests (ms)          |
| `PROXY_USE_HTTPS`           | `-https`               | true                 | Use HTTPS for target connections             |
| `PROXY_MAX_QUEUE_SIZE`      | `-queue-size`          | 1000                 | Maximum queue size                           |
| `PROXY_METRICS_PORT`        | `-metrics-port`        | 9090                 | Port for Prometheus metrics                  |
| `PROXY_HEALTH_PORT`         | `-health-port`         | 8081                 | Port for health checks                       |
| `PROXY_LOG_LEVEL`           | `-log-level`           | info                 | Log level (debug, info, warn, error)         |
| `PROXY_SHARED_HEALTH_PORT`  | `-shared-health-port`  | false                | Serve health checks on HTTP proxy port 🚩    |
| `PROXY_SHARED_METRICS_PORT` | `-shared-metrics-port` | false                | Serve metrics on HTTP proxy port 📊          |
| `PROXY_HEADER_QUEUES`       | `-header-queues`       | X-Amz-Security-Token | Comma-separated headers for dedicated queues |
| `PROXY_TIMEOUT`             | `-timeout`             | 0                    | Request timeout in seconds (0 = infinite ⏳)  |

### Header-Based Queue Routing 📤

The proxy supports routing requests to dedicated queues based on specific HTTP headers. This is particularly
useful for managing different authentication systems or API providers that require rate limiting.

#### Supported Headers by System

| System                          | Headers                                        | Description                                                              |
|---------------------------------|------------------------------------------------|--------------------------------------------------------------------------|
| **AWS Services, claude cli** 🔑 | `X-Amz-Security-Token`                         | Routes AWS API requests with temporary credentials or IAM authentication |
| **ChatGPT/OpenAI** 🤖           | `Authorization`, `OpenAI-Organization`         | Handles OpenAI API requests with API keys and organization routing       |
| **Claude/Anthropic** 🌐         | `Authorization`, `anthropic-version`           | Manages Anthropic API requests with proper versioning                    |
| **Google Cloud** ☁️             | `Authorization`, `X-Goog-User-Project`         | Routes Google Cloud API requests with project-specific billing           |
| **Azure** 🟦                    | `Authorization`, `Ocp-Apim-Subscription-Key`   | Handles Azure API Management requests                                    |
| **Custom APIs** 🔧              | `X-API-Key`, `Authorization`, `X-Custom-Token` | Generic headers for custom authentication systems                        |

#### Configuration Examples

```bash
# AWS-specific configuration
./proxy-queue -header-queues="X-Amz-Security-Token,Authorization" -target-host=xxx

# Environment variable approach 
export PROXY_HEADER_QUEUES="Authorization,X-Amz-Security-Token,OpenAI-Organization"
./proxy-queue
```

#### How Header Routing Works

1. **Request Analysis**: Incoming requests are inspected for configured headers
2. **Queue Selection**: Requests with matching headers are routed to dedicated queues
3. **Isolated Processing**: Each header-based queue processes requests independently
4. **Rate Limiting**: Different queues can have different processing rates and delays
5. **Fallback**: Requests without matching headers go to the main queue

#### Environment Configuration Example

```bash
# Copy and modify the example environment file
cp .env.example .env

# Or set environment variables directly
export PROXY_TARGET_HOST=api.example.com
export PROXY_TARGET_PORT=443
export PROXY_LOG_LEVEL=debug
export PROXY_HEADER_QUEUES=X-Amz-Security-Token
export PROXY_TIMEOUT=45  # 45 seconds timeout for all operations
./proxy-queue
```

### Service Ports

- **HTTP/HTTPS Proxy**: Listens on the specified port (default: 6789) 🌐
- **Socket Proxy**: Listens on the specified port + 10 (default: 6799)
- **Health Checks**: Listens on health-port (default: 8081) OR on HTTP proxy port if `-shared-health-port=true`
  🚩
- **Metrics**: Listens on metrics-port (default: 9090) OR on HTTP proxy port if `-shared-metrics-port=true` 📊

## Examples

### HTTP Proxy

```bash
# Start proxy
./proxy-queue -target-host=httpbin.org -target-port=80 -https=false

# Test with curl
curl http://localhost:6789/get
```

### HTTPS Proxy

```bash
# Start HTTPS proxy
./proxy-queue -target-host=httpbin.org -target-port=443 -https=true

# Test with curl
curl http://localhost:6789/get
```

### Socket Proxy

```bash
# Start proxy
./proxy-queue -target-host=example.com -target-port=22

# Test with telnet or netcat (socket proxy runs on port + 10)
telnet localhost 6799
```

### Health Checks and Metrics

#### Separate Ports (Default) 🔄

```bash
# Check application health
curl http://localhost:8081/health

# Check readiness
curl http://localhost:8081/ready

# View Prometheus metrics
curl http://localhost:9090/metrics
```

#### Shared Port Mode 🌐

```bash
# Start proxy with shared ports
./proxy-queue -shared-health-port=true -shared-metrics-port=true

# Check application health (now on proxy port)
curl http://localhost:6789/health

# Check readiness (now on proxy port)
curl http://localhost:6789/ready

# View Prometheus metrics (now on proxy port)
curl http://localhost:6789/metrics
```

### Available Metrics

The application exposes the following Prometheus metrics:

- **`proxy_requests_total`** (Counter): Total number of proxy requests processed
- **`proxy_request_duration_seconds`** (Histogram): Duration of proxy requests in seconds
- **`proxy_queue_size`** (Gauge): Current number of requests in queue
- **`proxy_errors_total`** (Counter): Total number of proxy errors
- **`proxy_concurrent_requests`** (Gauge): Number of concurrent requests being processed

These metrics can be scraped by Prometheus and visualized using Grafana dashboards.

### Logging

The application uses structured JSON logging with the following features:

- **Configurable log levels**: `debug`, `info`, `warn`, `error`
- **Request tracking**: Each request gets a unique ID for end-to-end tracing
- **Detailed request/response logging**: At debug level, full HTTP headers, bodies, and socket data are logged
- **Performance metrics**: Request duration, queue length, and processing statistics
- **Connection details**: Client IPs, connection states, and data transfer amounts

Example debug log output:

```json
{
  "level": "debug",
  "msg": "📥 HTTP Request Details",
  "request_id": "http-1672531200123456789",
  "method": "GET",
  "url": "/api/data",
  "headers": { "User-Agent": "curl/7.81.0" },
  "remote_ip": "192.168.1.100",
  "timestamp": "2023-01-01T12:00:00.123456789Z"
}
```

#### Mixed Configuration

```bash
# Only health checks on shared port, metrics separate
./proxy-queue -shared-health-port=true

# Health checks on proxy port: http://localhost:6789/health
# Metrics still on separate port: http://localhost:9090/metrics
```

### Development

```bash
# Development build with debug info
make dev

# Run tests
make test

# Run tests with race detection
make test-race

# Format and lint code
make fmt
make lint
make vet
```

## How It Works

1. **Queue System**: All incoming requests (HTTP, HTTPS, socket) are added to either the main queue or
   header-specific queues based on configured header routing
2. **Header-Based Routing**: Requests with specific headers (e.g., `X-Amz-Security-Token`, `Authorization`)
   can be routed to dedicated queues for isolated processing
3. **Sequential Processing**: Requests are processed one by one in FIFO order by dedicated goroutines for each
   queue
4. **Configurable Delays**: After processing each request, the system waits for a random delay calculated
   between the configured min/max values
5. **Connection Forwarding**:
    - HTTP/HTTPS requests are forwarded with proper header and body copying, including SSL/TLS support
    - Socket connections use bidirectional data copying with enhanced logging and error handling
6. **Request Tracking**: Each request gets a unique ID for tracking throughout the processing pipeline
7. **Metrics Collection**: Real-time metrics are collected for requests, errors, queue size, processing
   duration, and concurrent operations across all queues
8. **Health Monitoring**: Continuous health status monitoring with automatic degradation detection based on
   error rates, including per-queue status

## Docker Support 🐳

### Quick Start with Docker

```bash
# Build and run with default configuration
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f proxy-queue

# Stop services
docker-compose down
```

### Docker Compose Profiles

```bash
# Run with local development profile
docker-compose --profile local up

# Run with monitoring stack (Prometheus + Grafana)
docker-compose --profile monitoring up

# Run all services
docker-compose --profile local --profile monitoring up
```

### Custom Docker Configuration

```bash
# Build custom image
docker build -t my-proxy-queue .

# Run with custom environment variables
docker run -d \
  -p 6789:6789 \
  -p 6799:6799 \
  -e PROXY_TARGET_HOST=api.example.com \
  -e PROXY_TARGET_PORT=443 \
  -e PROXY_LOG_LEVEL=debug \
  my-proxy-queue
```

### Environment File for Docker

```bash
# Copy and modify environment file
cp .env.example .env

# Use with docker-compose
docker-compose --env-file .env up
```

### Monitoring with Docker

Access the monitoring stack:

- **Proxy Queue**: http://localhost:6789
- **Prometheus**: http://localhost:9091
- **Grafana**: http://localhost:3000 (admin/admin)

## Architecture

### Core Components

- **`QueueManager`**: Main orchestrator managing multiple queues (main + header-based queues)
- **`ProxyQueue`**: Individual queue manager with thread-safe operations, metrics collection, and request
  processing
- **`Config`**: Configuration structure supporting both environment variables and command-line flags
- **`HTTPRequestData`/`SocketRequestData`**: Type-safe request data structures with client information
- **`ProxyRequest`/`ProxyResponse`**: Queue communication protocol with response channels
- **`Metrics`**: Prometheus metrics collection with counters, histograms, and gauges (shared across queues)

### Runtime Architecture

- **Main Goroutine**: Configuration loading, server initialization, and coordination
- **Queue Manager**: Orchestrates multiple queues and routes requests based on headers
- **Queue Processors**: Dedicated goroutines for each queue (main + header-based) with sequential processing
- **HTTP Proxy Server**: Goroutine handling HTTP/HTTPS requests on the main port with header-based routing
- **Socket Proxy Server**: Goroutine handling raw socket connections on port+10 (uses main queue)
- **Health Server**: Optional dedicated goroutine for health checks (port 8081)
- **Metrics Server**: Optional dedicated goroutine for Prometheus metrics (port 9090)
- **Connection Handlers**: Per-connection goroutines for socket bidirectional copying

### Key Features

- **Context-based Cancellation**: Proper shutdown handling across all components
- **Thread-safe Operations**: Mutex-protected shared state and atomic counters
- **Request Identification**: Unique request IDs with timestamp-based generation
- **Comprehensive Logging**: Structured JSON logging with configurable levels and detailed request/response
  tracking
- **Error Handling**: Graceful error recovery with metrics tracking and client notification
- **Resource Management**: Proper connection cleanup and timeout handling

## Dependencies

The project uses minimal external dependencies to ensure reliability and security:

- **[logrus](https://github.com/sirupsen/logrus)** v1.9.3: Structured logging with JSON formatting
- **[prometheus/client_golang](https://github.com/prometheus/client_golang)** v1.23.2: Metrics collection and
  exposition

All dependencies are automatically managed through Go modules (`go.mod`/`go.sum`).

## Security & Performance Considerations

### Security Features

- **TLS Support**: Configurable HTTPS/TLS for target connections with `InsecureSkipVerify` option
- **Client IP Detection**: Proper client IP extraction supporting `X-Forwarded-For` and `X-Real-IP` headers
- **Resource Limits**: Configurable queue size limits to prevent memory exhaustion
- **Timeout Protection**: Configurable timeouts for HTTP requests (default 30s), socket connections (default 30s), HTTP proxy responses (default 60s), and socket connection handling (default 300s) - all customizable via `-timeout` flag
- **Connection Cleanup**: Proper resource cleanup and connection closing

### Performance Optimizations

- **Buffered Channels**: Queue implementation uses buffered channels for efficient request handling
- **Connection Pooling**: HTTP client with configurable transport settings
- **Concurrent Processing**: Separate goroutines for different protocol handlers
- **Memory Management**: 32KB buffers for socket data copying to balance memory usage and performance
- **Atomic Operations**: Lock-free counters for high-frequency metrics updates

### Operational Considerations

- **Queue Sizing**: Choose appropriate `PROXY_MAX_QUEUE_SIZE` based on expected load and available memory
- **Delay Configuration**: Set `PROXY_DELAY_MIN`/`PROXY_DELAY_MAX` according to target server capacity
- **Timeout Configuration**: Set appropriate `PROXY_TIMEOUT` values based on target server response times. Different timeout defaults apply:
  - HTTP client requests: 30s default
  - HTTP proxy responses: 60s default  
  - Socket connections: 30s default
  - Socket connection handling: 300s default
  - Set to 0 for infinite timeout (not recommended for production)
- **Log Level**: Use `debug` level cautiously in production as it logs full request/response bodies
- **Health Checks**: Configure monitoring systems to use `/health` and `/ready` endpoints
- **Resource Monitoring**: Monitor queue size and error rate metrics for capacity planning
