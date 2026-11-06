# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Cross-platform Docker + Linux monitoring — single embedded-binary image.
# Build context MUST be the `backend/` directory (that is where go.mod lives):
#   docker build -t monitor ./backend
# The compiled React SPA is embedded into the Go binary via `-tags embed`, so
# the running container serves both the UI and the API/WS from one port.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: build the React SPA (Vite → frontend/dist) ───────────────────────
FROM node:22-alpine AS web
WORKDIR /app/frontend
# Install deps from the lockfile first for better layer caching.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build                      # → /app/frontend/dist

# ── Stage 2: build the Go binary, embedding the SPA ───────────────────────────
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates tzdata
COPY go.mod go.sum ./
# proxy.golang.org can intermittently drop large module zips ("unexpected EOF");
# retry a few times and fall back to a mirror + direct so builds are robust.
ENV GOPROXY=https://proxy.golang.org,https://goproxy.io,direct
RUN --mount=type=cache,target=/go/pkg/mod \
    until go mod download; do echo "go mod download failed, retrying..."; sleep 3; done
COPY . .
# Put the built SPA where //go:embed all:dist expects it (cmd/server/dist).
COPY --from=web /app/frontend/dist ./cmd/server/dist
# modernc.org/sqlite is pure Go, so a static CGO-free binary is fine.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -tags embed -ldflags="-s -w" -o /out/monitor ./cmd/server

# ── Stage 3: minimal runtime ──────────────────────────────────────────────────
FROM alpine:3.20 AS runtime
# INSTALL_TRIVY=true adds the Phase 6 image scanner (≈70 MB + a CVE DB on first
# scan). Set --build-arg INSTALL_TRIVY=false for a lean, scan-free image.
ARG INSTALL_TRIVY=true
RUN apk add --no-cache ca-certificates tzdata wget && \
    if [ "$INSTALL_TRIVY" = "true" ]; then \
      wget -qO - https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin ; \
    fi

# The app talks to the Docker daemon over the mounted Unix socket (no CLI
# needed), reads host metrics from /proc & /sys, and stores state in SQLite.
COPY --from=build /out/monitor /usr/local/bin/monitor

ENV MONITOR_DB=/data/monitoring.db \
    TRIVY_CACHE_DIR=/trivy-cache \
    TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db,public.ecr.aws/aquasecurity/trivy-db
EXPOSE 8080

# /data holds the SQLite DB, /trivy-cache holds the scanner DB — bind/volume
# mount both so scans and history survive container restarts.
VOLUME ["/data", "/trivy-cache"]

ENTRYPOINT ["/usr/local/bin/monitor"]
CMD ["-addr", ":8080", "-db", "/data/monitoring.db"]
