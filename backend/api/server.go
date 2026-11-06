package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/monitoring/backend/collector"
	"github.com/monitoring/backend/storage"
)

// Config bundles the knobs exposed via CLI flags / environment variables.
type Config struct {
	Addr        string // HTTP listen address, e.g. ":8080"
	DockerHost  string // empty → auto-detect
	DBPath      string // path to SQLite file
	Retention   time.Duration
	PollInterval time.Duration // host-metric poll interval
	AdminToken   string        // bearer token required on mutating endpoints; empty disables them
	EnrollToken  string        // shared secret agents present to connect; empty disables agent access
	LocalHostID  string        // id used to tag the hub's own host in WS messages
	LocalHostName string       // display name for the local host

	// Image vulnerability scanning (Phase 6). TrivyBinary is looked up on PATH
	// on the host that owns the image (local daemon or a remote agent).
	TrivyBinary    string        // trivy binary name/path; empty → "trivy"
	ScanSeverities string        // comma list of Trivy severities to report
	ScanTimeout    time.Duration // per-scan deadline

	// Phase 7: scanner modes + local-only background scheduler. ScanModes maps to
	// Trivy --scanners (e.g. "vuln,secret,misconfig"). AutoScan, when true, scans
	// the local host's in-use images every ScanInterval (default off).
	ScanModes    string        // Trivy scanner modes; empty → "vuln"
	AutoScan     bool          // enable the background scan scheduler
	ScanInterval time.Duration // scheduler interval; floored at 5m

	// Phase 8: alerting. AlertInterval is the rule-evaluation tick (floored at
	// 10s). SMTP* configure the email notification channel; the password is
	// supplied via flag/env only and never stored in the database.
	AlertInterval time.Duration
	SMTPHost      string
	SMTPPort      int
	SMTPFrom      string
	SMTPUser      string
	SMTPPassword  string
}

// DefaultConfig returns the baseline configuration derived from general.md.
func DefaultConfig() Config {
	return Config{
		Addr:         ":8080",
		DBPath:       "monitoring.db",
		Retention:    24 * time.Hour,
		PollInterval: time.Second,
		LocalHostID:  "local",
		LocalHostName: "This host",
		TrivyBinary:    "trivy",
		ScanSeverities: "CRITICAL,HIGH,MEDIUM,LOW",
		ScanTimeout:    10 * time.Minute,
		ScanModes:      "vuln",
		AutoScan:       false,
		ScanInterval:   24 * time.Hour,
		AlertInterval:  30 * time.Second,
		SMTPPort:       587,
	}
}

// Server owns the HTTP listener, WebSocket hub, and references to every
// collector and the storage layer.
type Server struct {
	cfg        Config
	hub        *Hub
	dc         *collector.DockerClient
	hc         *collector.HostCollector
	agg        *collector.ContainerStatsAggregator
	db         *storage.DB
	agents     *AgentRegistry
	httpServer *http.Server
	upgrader   websocket.Upgrader
	staticFS   fs.FS // nil in non-embed builds
	ctx        context.Context // server lifecycle context (for WebSocket pumps)

	// lastContainerList caches the most recent container list so that new
	// WebSocket clients receive it immediately on connect.
	lastContainerList []collector.ContainerInfo

	// statsMu guards lastStats, the most recent live snapshot per container,
	// consumed by the Prometheus /metrics endpoint.
	statsMu   sync.Mutex
	lastStats map[string]collector.ContainerStatsSnapshot

	// Alerting (Phase 8). alertMu guards the in-memory evaluation state that
	// implements the sustained-window ("for"), cooldown and fire/resolve
	// transitions; lastContainerState tracks prior container states so exits
	// are detected by polling (Docker events are not used).
	notifier           *Notifier
	alertMu            sync.Mutex
	alertState         map[string]*alertRuntime
	lastContainerState map[string]string
}

// New initialises all subsystems and returns a ready-to-Start Server.
// Callers must pass a DockerClient and HostCollector that have already been
// constructed (so they can be reused elsewhere, e.g. tests).
func New(cfg Config, hub *Hub, dc *collector.DockerClient, hc *collector.HostCollector, db *storage.DB) *Server {
	s := &Server{
		cfg: cfg,
		hub: hub,
		dc:  dc,
		hc:  hc,
		db:  db,
		agg: collector.NewContainerStatsAggregator(),
		agents: NewAgentRegistry(),
		lastStats: map[string]collector.ContainerStatsSnapshot{},
		alertState:         map[string]*alertRuntime{},
		lastContainerState: map[string]string{},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			// Allow all origins in development; tighten for production.
			CheckOrigin: func(_ *http.Request) bool { return true },
		},
	}
	// The notifier resolves SMTP settings lazily so UI-saved credentials
	// (which need s.db) take effect without a restart.
	s.notifier = NewNotifier(cfg, s.smtpConfig)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/host", s.handleHost)
	mux.HandleFunc("GET /api/v1/host/history", s.handleHostHistory)
	mux.HandleFunc("GET /api/v1/containers", s.handleContainers)
	mux.HandleFunc("GET /api/v1/containers/{id}/logs", s.handleContainerLogs)
	mux.HandleFunc("GET /api/v1/containers/{id}/stats", s.handleContainerStatsOneShot)
	mux.HandleFunc("GET /api/v1/containers/{id}/top", s.handleContainerTop)
	mux.HandleFunc("GET /api/v1/containers/{id}/inspect", s.handleContainerInspect)
	mux.HandleFunc("GET /api/v1/containers/{id}/cgroup", s.handleContainerCgroup)
	mux.HandleFunc("GET /api/v1/system/df", s.handleSystemDf)
	mux.HandleFunc("GET /api/v1/networks/topology", s.handleTopology)
	mux.HandleFunc("GET /api/v1/volumes", s.handleVolumes)
	mux.HandleFunc("GET /api/v1/images", s.handleImages)
	mux.HandleFunc("GET /api/v1/images/layers", s.handleImageLayers)
	mux.HandleFunc("GET /api/v1/images/vulns", s.handleImageVulns)
	mux.HandleFunc("GET /api/v1/images/history", s.handleImageHistory)
	mux.HandleFunc("GET /api/v1/images/sbom", s.handleImageSBOM)
	mux.HandleFunc("POST /api/v1/images/scan", s.requireAdmin(s.handleImageScan))
	mux.HandleFunc("GET /api/v1/security/overview", s.handleSecurityOverview)
	mux.HandleFunc("GET /api/v1/security/report", s.handleSecurityReport)
	mux.HandleFunc("POST /api/v1/images/pull", s.requireAdmin(s.handleImagePull))
	mux.HandleFunc("POST /api/v1/images/prune", s.requireAdmin(s.handleImagePrune))
	mux.HandleFunc("POST /api/v1/images/pruneAll", s.requireAdmin(s.handleImagePruneAll))
	mux.HandleFunc("DELETE /api/v1/images", s.requireAdmin(s.handleImageDelete))
	mux.HandleFunc("POST /api/v1/containers/{id}/action", s.requireAdmin(s.handleContainerAction))
	mux.HandleFunc("DELETE /api/v1/volumes/{name}", s.requireAdmin(s.handleVolumeDelete))
	// Phase 8: alerting. Reads are open; mutations require the admin token.
	mux.HandleFunc("GET /api/v1/alerts/rules", s.handleListAlertRules)
	mux.HandleFunc("POST /api/v1/alerts/rules", s.requireAdmin(s.handleSaveAlertRule))
	mux.HandleFunc("DELETE /api/v1/alerts/rules/{id}", s.requireAdmin(s.handleDeleteAlertRule))
	mux.HandleFunc("GET /api/v1/alerts/channels", s.handleListAlertChannels)
	mux.HandleFunc("POST /api/v1/alerts/channels", s.requireAdmin(s.handleSaveAlertChannel))
	mux.HandleFunc("DELETE /api/v1/alerts/channels/{id}", s.requireAdmin(s.handleDeleteAlertChannel))
	mux.HandleFunc("GET /api/v1/alerts", s.handleListAlerts)
	mux.HandleFunc("GET /api/v1/alerts/active", s.handleActiveAlerts)
	mux.HandleFunc("POST /api/v1/alerts/test", s.requireAdmin(s.handleTestAlert))
	mux.HandleFunc("GET /api/v1/alerts/smtp", s.handleGetSMTP)
	mux.HandleFunc("POST /api/v1/alerts/smtp", s.requireAdmin(s.handleSaveSMTP))
	mux.HandleFunc("POST /api/v1/alerts/smtp/test", s.requireAdmin(s.handleTestSMTP))
	mux.HandleFunc("POST /api/v1/alerts/{id}/ack", s.requireAdmin(s.handleAckAlert))
	mux.HandleFunc("POST /api/v1/alerts/{id}/resolve", s.requireAdmin(s.handleResolveAlert))
	mux.HandleFunc("GET /api/v1/hosts", s.handleHosts)
	mux.HandleFunc("GET /ws/agent", s.handleAgentStream)
	mux.HandleFunc("GET /ws/stream", s.handleWebSocket)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	// SPA catch-all: must be registered last; Go 1.22 ServeMux always
	// prefers the most-specific pattern match, so /api/v1/* routes win.
	mux.HandleFunc("GET /", s.handleStatic)

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // 0 = no timeout; WebSocket connections need long writes
		IdleTimeout:  120 * time.Second,
	}

	s.seedAlertDefaults()

	return s
}

// Start launches the hub, host collector, stats aggregator, and HTTP listener.
// It blocks until ctx is cancelled or a fatal server error occurs.
func (s *Server) Start(ctx context.Context) error {
	s.ctx = ctx // store for WebSocket handlers
	// 1. Hub event loop
	go s.hub.Run(ctx)

	// 2. Host collector → broadcast to WS + persist to DB
	go s.hc.Start(ctx)
	hostCh := s.hc.Subscribe()
	go func() {
		for m := range hostCh {
			s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgHostMetrics, m)
			mm := m // capture for closure
			s.db.QueueWrite(func() error { return s.db.SaveHostMetrics(mm) })
		}
	}()

	// 3. Auto-start per-container stats + log streams for all running containers
	go s.discoverAndStream(ctx)

	// 3b. Background image scanner (Phase 7) — local host only, opt-in.
	if s.cfg.AutoScan {
		go s.startScanScheduler(ctx)
	}

	// 3c. Alert rule evaluator (Phase 8) — runs whenever enabled rules exist.
	go s.startAlertScheduler(ctx)

	// 4. Periodic stats aggregator → hub broadcast
	go func() {
		for snap := range s.agg.Output() {
			s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgContainerStats, snap)
			s.statsMu.Lock()
			s.lastStats[snap.ContainerID] = snap
			s.statsMu.Unlock()
		}
	}()

	// 4b. Kernel/OOM log miner → hub broadcast. Linux reads the journal/kmsg;
	// the non-Linux stub just parks until ctx ends, so this is safe everywhere.
	go func() {
		kernelCh := make(chan collector.KernelEvent, 64)
		go collector.StreamKernelEvents(ctx, kernelCh)
		for ev := range kernelCh {
			s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgKernelEvent, ev)
		}
	}()

	// 5. Background DB pruning
	s.db.StartPruneTicker(ctx, time.Hour)

	// 6. HTTP shutdown on context cancel
	go func() {
		<-ctx.Done()
		log.Println("api: shutting down HTTP server")
		s.agg.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("api: shutdown error: %v", err)
		}
	}()

	log.Printf("api: listening on %s  (WS endpoint: /ws/stream)", s.cfg.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api: ListenAndServe: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Container discovery + streaming helpers
// ─────────────────────────────────────────────────────────────────────────────

// discoverAndStream lists running containers and launches stats + log streams
// for each one. New containers are picked up every 30 seconds.
// If Docker is unavailable (dc == nil) the function exits immediately.
func (s *Server) discoverAndStream(ctx context.Context) {
	if s.dc == nil {
		log.Println("api: Docker unavailable — container streaming disabled")
		return
	}

	// Track which container IDs we have already started streams for.
	streamed := map[string]struct{}{}

	s.startStreams(ctx, streamed)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.startStreams(ctx, streamed)
		}
	}
}

func (s *Server) startStreams(ctx context.Context, streamed map[string]struct{}) {
	// Broadcast the FULL container set (running + stopped) so the UI strip can
	// show exited containers too; live stats/log streams are started only for
	// the running ones further below.
	containers, err := s.dc.ListContainers(ctx, "")
	if err != nil {
		log.Printf("api: ListContainers: %v", err)
		return
	}

	// Enrich with inspect data: size, restart count, health, OOM, exit code
	for i := range containers {
		meta, err := s.dc.InspectContainer(ctx, containers[i].ID)
		if err == nil {
			containers[i].SizeRwBytes = meta.SizeRwBytes
			containers[i].SizeRootFsBytes = meta.SizeRootFsBytes
			containers[i].RestartCount = meta.RestartCount
			containers[i].OOMKilled = meta.OOMKilled
			containers[i].HealthStatus = meta.HealthStatus
			containers[i].ExitCode = meta.ExitCode
		}
	}

	// Broadcast container list to hub so clients know what's present (running + stopped).
	s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgContainerList, containers)
	s.lastContainerList = containers

	// Drop cached stats for containers that no longer exist so the /metrics
	// endpoint and memory stay bounded.
	s.statsMu.Lock()
	present := make(map[string]struct{}, len(containers))
	for _, c := range containers {
		present[c.ID] = struct{}{}
	}
	for id := range s.lastStats {
		if _, ok := present[id]; !ok {
			delete(s.lastStats, id)
		}
	}
	s.statsMu.Unlock()

	for _, c := range containers {
		if c.State != "running" {
			continue // exited containers show in the list but get no live stream
		}
		if _, ok := streamed[c.ID]; ok {
			continue // already streaming
		}
		streamed[c.ID] = struct{}{}

		// Container stats stream
		statsCh, err := s.dc.StreamContainerStats(ctx, c.ID, c.Name)
		if err != nil {
			log.Printf("api: StreamContainerStats(%s): %v", c.ID, err)
			delete(streamed, c.ID)
			continue
		}
		s.agg.AddStream(statsCh)

		// Container log stream
		logCh, err := s.dc.StreamContainerLogs(ctx, c.ID, collector.DefaultLogStreamOptions())
		if err != nil {
			log.Printf("api: StreamContainerLogs(%s): %v", c.ID, err)
			continue
		}
		go func(id string) {
			for entry := range logCh {
				s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgContainerLog, entry)
				e := entry // capture copy for goroutine
				s.db.QueueWrite(func() error { return s.db.SaveContainerLog(e) })
			}
		}(c.ID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// REST handlers
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/v1/host — returns the most recent host metrics snapshot.
func (s *Server) handleHost(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.hc.Latest())
}

// GET /api/v1/host/history?limit=300 — returns historical host metrics.
// GET /api/v1/host/history?range=1h — returns metrics within a trailing window
// (1m/5m/15m/1h/24h), downsampled to a chart-friendly point count. When both
// are supplied, `range` wins.
func (s *Server) handleHostHistory(w http.ResponseWriter, r *http.Request) {
	if rs := r.URL.Query().Get("range"); rs != "" {
		d, err := time.ParseDuration(rs)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid range %q", rs))
			return
		}
		history, err := s.db.GetHostMetricsHistoryRange(d, 600)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, history)
		return
	}

	limit := parseLimit(r, 300)
	history, err := s.db.GetHostMetricsHistory(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

// GET /api/v1/containers?state=running — lists containers filtered by state.
// Returns an empty array when Docker is unavailable.
func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeJSON(w, http.StatusOK, []collector.ContainerInfo{})
		return
	}
	state := r.URL.Query().Get("state") // "running", "exited", "" = all
	containers, err := prov.ListContainers(r.Context(), state)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, containers)
}

// GET /api/v1/containers/{id}/logs?limit=200 — returns stored log entries.
func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("container id is required"))
		return
	}
	limit := parseLimit(r, 200)
	logs, err := s.db.GetContainerLogs(id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// GET /api/v1/containers/{id}/stats — single stats snapshot for one container.
// Docker's non-streaming stats mode is used (stream=false).
func (s *Server) handleContainerStatsOneShot(w http.ResponseWriter, r *http.Request) {
	if s.dc == nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Docker unavailable"))
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("container id is required"))
		return
	}

	// Open a stream, read one frame, close immediately.
	statsCh, err := s.dc.StreamContainerStats(r.Context(), id, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	select {
	case snap, ok := <-statsCh:
		if !ok {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("stats channel closed"))
			return
		}
		writeJSON(w, http.StatusOK, snap)
	case <-r.Context().Done():
		writeError(w, http.StatusGatewayTimeout, r.Context().Err())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 Batch 2 handlers: top, inspect raw JSON, system df
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/v1/containers/{id}/top — process list for one container.
func (s *Server) handleContainerTop(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("container id is required"))
		return
	}
	procs, err := prov.TopProcesses(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, procs)
}

// GET /api/v1/containers/{id}/inspect — raw `docker inspect` JSON document.
func (s *Server) handleContainerInspect(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("container id is required"))
		return
	}
	raw, err := prov.InspectRaw(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(raw); err != nil {
		log.Printf("api: handleContainerInspect write: %v", err)
	}
}

// GET /api/v1/containers/{id}/cgroup — cgroup v2 per-container detail (Linux).
// Returns 501 when the host is non-Linux (collector.ErrNotSupported) so the UI
// hides the Cgroup tab; 404-style 500 when the container is not running.
func (s *Server) handleContainerCgroup(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("container id is required"))
		return
	}
	stats, err := prov.CgroupStats(r.Context(), id)
	if err != nil {
		if errors.Is(err, collector.ErrNotSupported) {
			writeError(w, http.StatusNotImplemented, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// GET /api/v1/system/df — normalised docker system disk-usage summary.
func (s *Server) handleSystemDf(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	usage, err := prov.SystemUsage(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, usage)
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 6 handlers: image vulnerability scanning + fleet security posture
// ─────────────────────────────────────────────────────────────────────────────

// buildScanOptions derives a Trivy ScanOptions from server config, applying
// defaults so a zero-valued Config still yields a usable scan.
func (s *Server) buildScanOptions() collector.ScanOptions {
	bin := s.cfg.TrivyBinary
	if bin == "" {
		bin = "trivy"
	}
	sev := s.cfg.ScanSeverities
	if sev == "" {
		sev = "CRITICAL,HIGH,MEDIUM,LOW"
	}
	d := s.cfg.ScanTimeout
	if d <= 0 {
		d = 10 * time.Minute
	}
	modes := s.cfg.ScanModes
	if modes == "" {
		modes = "vuln"
	}
	return collector.ScanOptions{Binary: bin, Severities: sev, Timeout: d, Modes: modes}
}

// buildSBOMOptions derives a Trivy SBOM export from the same binary/timeout
// config; format comes from the request query (cyclonedx default).
func (s *Server) buildSBOMOptions(format string) collector.SBOMOptions {
	bin := s.cfg.TrivyBinary
	if bin == "" {
		bin = "trivy"
	}
	d := s.cfg.ScanTimeout
	if d <= 0 {
		d = 10 * time.Minute
	}
	return collector.SBOMOptions{Binary: bin, Format: format, Timeout: d}
}

// scanSummary is the lean POST /images/scan response (counts only; the CVE list
// is fetched from /images/vulns so the scan reply stays small).
type scanSummary struct {
	Ref            string         `json:"ref"`
	ImageID        string         `json:"image_id"`
	Scanner        string         `json:"scanner"`
	ScannedAt      time.Time      `json:"scanned_at"`
	Counts         map[string]int `json:"counts"`
	Total          int            `json:"total"`
	SecretCount    int            `json:"secret_count"`
	MisconfigCount int            `json:"misconfig_count"`
	Host           string         `json:"host,omitempty"`
}

// POST /api/v1/images/scan?ref=<tag>&host=<id> — run Trivy on the host that owns
// the image, cache the result, and return the severity counts.
func (s *Server) handleImageScan(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, errors.New("ref is required"))
		return
	}
	res, err := prov.ScanImage(r.Context(), ref, s.buildScanOptions())
	if err != nil {
		if errors.Is(err, collector.ErrScannerNotAvailable) {
			writeError(w, http.StatusNotImplemented, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.db.QueueWrite(func() error {
		if err := s.db.SaveImageScan(res); err != nil {
			return err
		}
		return s.db.AppendScanHistory(res)
	})
	s.evaluateScan(res) // Phase 8: fire CVE alerts on new breaches

	total := 0
	for _, n := range res.Counts {
		total += n
	}
	writeJSON(w, http.StatusOK, scanSummary{
		Ref: res.Ref, ImageID: res.ImageID, Scanner: res.Scanner,
		ScannedAt: res.ScannedAt, Counts: res.Counts, Total: total,
		SecretCount: res.SecretCount, MisconfigCount: res.MisconfigCount,
		Host: r.URL.Query().Get("host"),
	})
}

// GET /api/v1/images/vulns?ref=<tag> — the cached CVE list for one image (from
// SQLite; no scan is triggered). Returns an empty list with scanned=false when
// the image has never been scanned, so the panel prompts for a scan.
func (s *Server) handleImageVulns(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, errors.New("ref is required"))
		return
	}
	res, found, err := s.db.GetImageScanByRef(ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		// Fall back to an image-ID match for digest-style refs.
		res, found, err = s.db.GetImageScan(ref)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			res = collector.ImageVulnScan{Ref: ref, Vulnerabilities: []collector.Vulnerability{}}
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// GET /api/v1/images/sbom?ref=<tag>&format=cyclonedx|spdx&host=<id> — produce a
// CycloneDX/SPDX bill-of-materials via Trivy on the host that owns the image and
// stream it back as a file download.
func (s *Server) handleImageSBOM(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, errors.New("ref is required"))
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	doc, name, err := prov.ScanSBOM(r.Context(), ref, s.buildSBOMOptions(format))
	if err != nil {
		if errors.Is(err, collector.ErrScannerNotAvailable) {
			writeError(w, http.StatusNotImplemented, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(doc); err != nil {
		log.Printf("api: handleImageSBOM write: %v", err)
	}
}

// GET /api/v1/images/history?ref=<tag> — counts-only trend points for one image,
// oldest-first, feeding the SecurityPanel sparkline. Never-scanned → empty list.
func (s *Server) handleImageHistory(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, errors.New("ref is required"))
		return
	}
	var imageID string
	if sc, ok, err := s.db.GetImageScanByRef(ref); err == nil && ok {
		imageID = sc.ImageID
	} else if sc, ok, err := s.db.GetImageScan(ref); err == nil && ok {
		imageID = sc.ImageID
	}
	if imageID == "" {
		writeJSON(w, http.StatusOK, []storage.ScanTrend{})
		return
	}
	hist, err := s.db.GetScanHistory(imageID, 60)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if hist == nil {
		hist = []storage.ScanTrend{}
	}
	writeJSON(w, http.StatusOK, hist)
}

// GET /api/v1/security/report?format=csv|json — export the current fleet image
// exposure. json == the overview verbatim; csv == one row per in-use image.
func (s *Server) handleSecurityReport(w http.ResponseWriter, r *http.Request) {
	ov, err := s.buildSecurityOverview(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		writeJSON(w, http.StatusOK, ov)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="security-report.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"image", "scanned", "critical", "high", "medium", "low", "total", "secrets", "misconfigs", "hosts"})
	for _, e := range ov.ImageExposure {
		_ = cw.Write([]string{
			e.Ref, strconv.FormatBool(e.Scanned),
			strconv.Itoa(e.Counts["CRITICAL"]), strconv.Itoa(e.Counts["HIGH"]),
			strconv.Itoa(e.Counts["MEDIUM"]), strconv.Itoa(e.Counts["LOW"]),
			strconv.Itoa(e.Total), strconv.Itoa(e.SecretCount), strconv.Itoa(e.MisconfigCount),
			strings.Join(e.Hosts, "|"),
		})
	}
}

// Fleet security response shapes.
type (
	HostSecurity struct {
		HostID     string                       `json:"host_id"`
		HostName   string                       `json:"host_name"`
		OS         string                       `json:"os,omitempty"`
		Offline    bool                         `json:"offline"`
		Containers []collector.ContainerSecurity `json:"containers"`
	}
	ImageExposure struct {
		Ref            string         `json:"ref"`
		Counts         map[string]int `json:"counts"`
		Total          int            `json:"total"`
		Scanned        bool           `json:"scanned"`
		ScannedAt      string         `json:"scanned_at,omitempty"`
		Hosts          []string       `json:"hosts"`
		SecretCount    int            `json:"secret_count"`
		MisconfigCount int            `json:"misconfig_count"`
	}
	SecurityOverview struct {
		GeneratedAt     time.Time                     `json:"generated_at"`
		Hosts           []HostSecurity                `json:"hosts"`
		ImageExposure   []ImageExposure               `json:"image_exposure"`
		RiskyContainers []collector.ContainerSecurity `json:"risky_containers"`
		AutoScan        bool                          `json:"auto_scan"`
		ScanInterval    string                        `json:"scan_interval,omitempty"`
	}
)

// GET /api/v1/security/overview — fleet-wide posture + per-image exposure.
func (s *Server) handleSecurityOverview(w http.ResponseWriter, r *http.Request) {
	overview, err := s.buildSecurityOverview(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

// buildSecurityOverview fans out concurrently to the local host and every online
// agent; offline or erroring hosts are reported with offline=true rather than
// failing the whole overview. Shared by the JSON endpoint and the report export.
func (s *Server) buildSecurityOverview(ctx context.Context) (SecurityOverview, error) {
	type target struct {
		id, name, os string
		prov         ResourceProvider
	}
	var targets []target
	var localProv ResourceProvider
	if s.dc != nil {
		localProv = s.dc
	}
	targets = append(targets, target{id: s.cfg.LocalHostID, name: s.cfg.LocalHostName, os: runtime.GOOS, prov: localProv})
	for _, h := range s.agents.List() {
		targets = append(targets, target{
			id: h.ID, name: h.Name, os: h.OS,
			prov: &agentProxy{reg: s.agents, host: h.ID},
		})
	}

	hosts := make([]HostSecurity, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			h := HostSecurity{HostID: t.id, HostName: t.name, OS: t.os, Containers: []collector.ContainerSecurity{}}
			hosts[i] = h
			if t.prov == nil {
				hosts[i].Offline = true
				return
			}
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			posture, err := t.prov.SecurityPosture(ctx)
			if err != nil {
				hosts[i].Offline = true
				return
			}
			for j := range posture {
				posture[j].HostID = t.id
				posture[j].HostName = t.name
			}
			hosts[i].Containers = posture
		}(i, t)
	}
	wg.Wait()

	// Cached scans feed per-image counts (no Trivy re-run here).
	scans, _ := s.db.ListImageScans()
	byRef := map[string]collector.ImageVulnScan{}
	byID := map[string]collector.ImageVulnScan{}
	for _, sc := range scans {
		if sc.Ref != "" {
			byRef[sc.Ref] = sc
		}
		if sc.ImageID != "" {
			byID[sc.ImageID] = sc
		}
	}

	type agg struct {
		hosts map[string]bool
		scan  *collector.ImageVulnScan
	}
	exposures := map[string]*agg{}
	var risky []collector.ContainerSecurity

	addExposure := func(imageName, hostLabel string) {
		if imageName == "" {
			return
		}
		a := exposures[imageName]
		if a == nil {
			a = &agg{hosts: map[string]bool{}}
			if sc, ok := byRef[imageName]; ok {
				svv := sc
					a.scan = &svv
			} else if sc, ok := byID[imageName]; ok {
				sc2 := sc
				a.scan = &sc2
			}
			exposures[imageName] = a
		}
		if hostLabel != "" {
			a.hosts[hostLabel] = true
		}
	}

	for _, h := range hosts {
		for _, c := range h.Containers {
			addExposure(c.Image, h.HostID)
			if c.Privileged || c.Root || c.HostNetwork || c.HostPid || len(c.CapAdd) > 0 {
				risky = append(risky, c)
			}
		}
	}

	overview := SecurityOverview{
		GeneratedAt:     time.Now().UTC(),
		Hosts:           hosts,
		ImageExposure:   make([]ImageExposure, 0, len(exposures)),
		RiskyContainers: risky,
		AutoScan:        s.cfg.AutoScan,
		ScanInterval:    s.cfg.ScanInterval.String(),
	}
	for ref, a := range exposures {
		ie := ImageExposure{Ref: ref, Hosts: sortedKeys(a.hosts)}
		if a.scan != nil {
			ie.Scanned = true
			ie.Counts = a.scan.Counts
			ie.ScannedAt = a.scan.ScannedAt.UTC().Format(time.RFC3339)
			total := 0
			for _, n := range a.scan.Counts {
				total += n
			}
			ie.Total = total
			ie.SecretCount = a.scan.SecretCount
			ie.MisconfigCount = a.scan.MisconfigCount
		}
		if ie.Counts == nil {
			ie.Counts = map[string]int{}
		}
		overview.ImageExposure = append(overview.ImageExposure, ie)
	}
	sort.Slice(overview.ImageExposure, func(i, j int) bool {
		if overview.ImageExposure[i].Total != overview.ImageExposure[j].Total {
			return overview.ImageExposure[i].Total > overview.ImageExposure[j].Total
		}
		return overview.ImageExposure[i].Ref < overview.ImageExposure[j].Ref
	})

	return overview, nil
}

// sortedKeys returns the keys of a set in ascending order.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// startScanScheduler periodically Trivy-scans the local host's in-use images and
// records each result plus a history point. Launched only when cfg.AutoScan is
// set. A missing scanner aborts the loop (it will not appear mid-process);
// per-image failures are logged and skipped so one bad image never stops the run.
func (s *Server) startScanScheduler(ctx context.Context) {
	if s.dc == nil {
		return
	}
	interval := s.cfg.ScanInterval
	if interval < 5*time.Minute {
		interval = 5 * time.Minute
	}
	opts := s.buildScanOptions()
	t := time.NewTicker(interval)
	defer t.Stop()

	// One pass shortly after boot, then on every tick.
	if scanner := s.scanInUseImages(ctx, opts); !scanner {
		return // scanner absent → do not keep ticking
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if scanner := s.scanInUseImages(ctx, opts); !scanner {
				return
			}
		}
	}
}

// scanInUseImages enumerates unique non-<none> images referenced by containers on
// the local daemon, scanning each. Returns false when the scanner is unavailable
// (caller stops the scheduler); true otherwise, even if individual scans fail.
func (s *Server) scanInUseImages(ctx context.Context, opts collector.ScanOptions) bool {
	containers, err := s.dc.ListContainers(ctx, "")
	if err != nil {
		log.Printf("autoscan: list containers: %v", err)
		return true
	}
	seen := map[string]bool{}
	for _, c := range containers {
		ref := c.Image
		if ref == "" || strings.Contains(ref, "<none>") || seen[ref] {
			continue
		}
		seen[ref] = true
		sctx, cancel := context.WithTimeout(ctx, opts.Timeout+30*time.Second)
		res, err := s.dc.ScanImage(sctx, ref, opts)
		cancel()
		if err != nil {
			if errors.Is(err, collector.ErrScannerNotAvailable) {
				log.Printf("autoscan: scanner not available — disabling scheduler")
				return false
			}
			log.Printf("autoscan: scan %s: %v", ref, err)
			continue
		}
		s.db.QueueWrite(func() error {
			if err := s.db.SaveImageScan(res); err != nil {
				return err
			}
			return s.db.AppendScanHistory(res)
		})
		s.evaluateScan(res) // Phase 8: fire CVE alerts on new breaches
		total := 0
		for _, n := range res.Counts {
			total += n
		}
		log.Printf("autoscan: %s → %d finding(s)", ref, total)
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 handlers: topology, volumes, images (read + guarded pull/prune)
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/v1/networks/topology — container<->network graph.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	topo, err := prov.NetworkTopology(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, topo)
}

// GET /api/v1/volumes?size=1 — list volumes; size=1 adds mountpoint du + usage.
func (s *Server) handleVolumes(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	withSize := r.URL.Query().Get("size") == "1"
	vols, err := prov.ListVolumes(r.Context(), withSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, vols)
}

// GET /api/v1/images — list local images.
func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	images, err := prov.ListImages(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, images)
}

// GET /api/v1/images/layers?ref=... — ordered layer diff IDs for one image.
func (s *Server) handleImageLayers(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ref is required"))
		return
	}
	layers, err := prov.ImageLayers(r.Context(), ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ref": ref, "layers": layers})
}

// POST /api/v1/images/pull?ref=... — guarded pull of a single image.
func (s *Server) handleImagePull(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ref is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	status, err := prov.PullImage(ctx, ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pulled", "ref": ref, "detail": status})
}

// POST /api/v1/images/prune — remove dangling images only.
func (s *Server) handleImagePrune(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	reclaimed, err := prov.PruneDanglingImages(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"space_reclaimed_bytes": reclaimed})
}

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket handler
// ─────────────────────────────────────────────────────────────────────────────

// GET /ws/stream — upgrades the connection to WebSocket and registers the
// client with the hub. The client immediately receives the latest host metrics
// snapshot so the UI is populated without waiting for the next 1-second tick.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("api: WebSocket upgrade: %v", err)
		return // Upgrade already wrote the HTTP error
	}

	client := s.hub.newClient(conn, s.ctx)

	// Send initial host metrics snapshot so the UI is not blank.
	initial := WSMessage{Type: MsgHostMetrics, Data: s.hc.Latest(), Host: s.cfg.LocalHostID}
	if b, err := json.Marshal(initial); err == nil {
		select {
		case client.send <- b:
		default:
		}
	}

	// Send cached container list immediately (don't wait for 30s tick).
	if len(s.lastContainerList) == 0 && s.dc != nil {
		// First client connected before discoverAndStream finished — fetch now.
		if ctrs, err := s.dc.ListContainers(r.Context(), ""); err == nil {
			s.lastContainerList = ctrs
		}
	}
	if len(s.lastContainerList) > 0 {
		cl := WSMessage{Type: MsgContainerList, Data: s.lastContainerList, Host: s.cfg.LocalHostID}
		if b, err := json.Marshal(cl); err == nil {
			select {
			case client.send <- b:
			default:
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Health / utility
// ─────────────────────────────────────────────────────────────────────────────

// GET /healthz — lightweight liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]interface{}{
		"status":     "ok",
		"ws_clients": s.hub.ClientCount(),
		"time":       time.Now().UTC().Format(time.RFC3339),
	}
	if s.dc != nil {
		resp["go_os"] = s.dc.OS
		resp["docker_endpoint"] = s.dc.Endpoint
	} else {
		resp["docker"] = "unavailable"
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: writeJSON encode: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func parseLimit(r *http.Request, defaultVal int) int {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultVal
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// Static file serving (embedded React SPA)
// ─────────────────────────────────────────────────────────────────────────────

// SetStaticFS configures the Server to serve frontend files from f.
// Call before Start(). Pass nil to disable static serving (API-only mode).
func (s *Server) SetStaticFS(f fs.FS) {
	s.staticFS = f
}

// handleStatic is the catch-all GET / handler for the embedded SPA.
//
// Strategy:
//  1. If staticFS is nil (non-embed build) → return 200 with a plain hint.
//  2. Serve the requested path directly if it exists (e.g. /assets/index-abc.js).
//  3. Fall back to index.html for client-side routing (React Router, etc.).
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if s.staticFS == nil {
		http.Error(w,
			"Frontend not embedded. Build with `-tags embed` after "+
				"`cd frontend && npm run build && cp -r dist cmd/server/dist`.",
			http.StatusServiceUnavailable)
		return
	}

	// Normalise path: strip leading slash for fs.FS (which uses unrooted paths)
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	// Try to open the requested resource.
	f, err := s.staticFS.Open(path)
	if err != nil {
		// 404: fall back to index.html for SPA routing
		f, err = s.staticFS.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found in embedded FS", http.StatusInternalServerError)
			return
		}
	}
	defer f.Close() //nolint:errcheck

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If stat is a directory (e.g. path was "assets") → redirect to index inside
	if stat.IsDir() {
		sub, err := s.staticFS.Open(path + "/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer sub.Close() //nolint:errcheck
		stat, _ = sub.Stat()
		f = sub // reuse f for ServeContent (it implements io.ReadSeeker via fs.File)
	}

	// Let Go's content-type sniffer work off the filename hint
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if path == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}

	http.ServeContent(w, r, stat.Name(), stat.ModTime(),
		f.(interface{ Read([]byte) (int, error); Seek(int64, int) (int64, error) }))
}
