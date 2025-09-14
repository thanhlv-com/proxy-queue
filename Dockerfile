# Build stage
FROM golang:1.23-alpine AS builder

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates git

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o proxy-queue .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/proxy-queue .

# Expose ports
EXPOSE 6789 6799 8081 9090

# Set default environment variables
ENV PROXY_LISTEN_PORT=6789 \
    PROXY_TARGET_HOST=localhost \
    PROXY_TARGET_PORT=443 \
    PROXY_DELAY_MIN=1000 \
    PROXY_DELAY_MAX=5000 \
    PROXY_USE_HTTPS=true \
    PROXY_MAX_QUEUE_SIZE=1000 \
    PROXY_METRICS_PORT=9090 \
    PROXY_HEALTH_PORT=8081 \
    PROXY_LOG_LEVEL=info \
    PROXY_SHARED_HEALTH_PORT=true \
    PROXY_SHARED_METRICS_PORT=true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:$PROXY_LISTEN_PORT/health || exit 1

# Run the application
CMD ["./proxy-queue"]