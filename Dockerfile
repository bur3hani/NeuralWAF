# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Cache go modules
COPY go.mod ./
# If go.sum exists, copy it
RUN go mod download || true

# Copy source tree
COPY . .

# Build statically linked binary with stripped debug symbols
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/edge-proxy cmd/edge-proxy/main.go

# Production runtime stage (Distroless / Minimal Alpine)
FROM alpine:3.19 AS runner

RUN apk add --no-cache ca-certificates tzdata curl && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

WORKDIR /app

# Copy binary from builder
COPY --from=builder /bin/edge-proxy /app/edge-proxy
COPY configs/waf.yaml /app/configs/waf.yaml

# Set unprivileged security context
USER appuser:appgroup

# Data Plane (:8080) and Control Plane (:9090)
EXPOSE 8080 9090

# Health check probe against Control Plane /healthz
HEALTHCHECK --interval=5s --timeout=2s --start-period=3s --retries=3 \
  CMD curl -f http://127.0.0.1:9090/healthz || exit 1

ENTRYPOINT ["/app/edge-proxy"]
CMD ["-config", "/app/configs/waf.yaml"]
