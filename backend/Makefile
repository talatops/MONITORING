# Makefile — cross-platform monitoring backend + embedded SPA
# Run from: f:/MONITORING/backend  (Windows) or /mnt/f/MONITORING/backend (WSL)

GOOS   ?= $(shell go env GOOS)
BINARY = monitoring-server

.PHONY: all dev build-frontend embed-build clean

# ── Default: full production build (embeds the SPA into the Go binary) ─────
all: build-frontend embed-build

# ── 1. Build React SPA via Vite and copy into Go embed path ────────────────
build-frontend:
	cd frontend && npm ci && npm run build
	rm -rf cmd/server/dist
	cp -r frontend/dist cmd/server/dist

# ── 2. Compile the single-binary server with embedded frontend ─────────────
embed-build:
	go mod tidy
	CGO_ENABLED=0 go build -tags embed -ldflags "-s -w" \
		-o $(BINARY) ./cmd/server
	@echo "✓ $(BINARY) built for $(GOOS) with embedded SPA"

# ── 3. Dev: run Go API only (no embed); start Vite separately ─────────────
dev:
	go mod tidy
	go run ./cmd/server

# ── 4. Dev frontend (hot-reload proxy → :8080) ────────────────────────────
frontend-dev:
	cd frontend && npm run dev

# ── Clean build artefacts ───────────────────────────────────────────────────
clean:
	rm -rf cmd/server/dist
	rm -f $(BINARY) monitoring.db
	cd frontend && rm -rf dist node_modules
