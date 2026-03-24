# ── Stage 1: Build ─────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install git for GONOSUMDB downloads
RUN apk add --no-cache git ca-certificates

# Copy module files first for layer caching
COPY go.mod go.sum* ./
RUN GONOSUMDB='*' GOPROXY='direct' go mod download 2>/dev/null || true

# Copy source
COPY . .

# Build server
RUN GONOSUMDB='*' GOPROXY='direct' CGO_ENABLED=0 GOOS=linux \
    go build -mod=mod \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /out/xtunnel-server ./server/cmd

# Build agent
RUN GONOSUMDB='*' GOPROXY='direct' CGO_ENABLED=0 GOOS=linux \
    go build -mod=mod \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /out/xtunnel ./agent/cmd

# ── Stage 2: Server image ───────────────────────────────────────────────────
FROM alpine:3.20 AS server

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/xtunnel-server /usr/local/bin/xtunnel-server
COPY configs/server.json /etc/xtunnel/server.json

# Ports: HTTP proxy, HTTPS, control WS, SSH gateway, API
EXPOSE 8080 8443 7000 2222 7001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:7001/api/health || exit 1

ENTRYPOINT ["xtunnel-server"]
CMD ["--config", "/etc/xtunnel/server.json"]

# ── Stage 3: Agent image ────────────────────────────────────────────────────
FROM alpine:3.20 AS agent

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/xtunnel /usr/local/bin/xtunnel

ENTRYPOINT ["xtunnel"]
