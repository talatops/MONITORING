// Command server is the single-binary entry-point for the cross-platform
// monitoring backend (general.md §3 — "Single Core Backend").
//
// It wires together:
//
//	Module A — collector.HostCollector   (gopsutil, 1 s ticker)
//	Module B — collector.DockerClient    (Docker SDK, Unix Socket / Named Pipe)
//	Module C — collector.StreamContainerLogs
//	Module D — storage.DB               (SQLite, 24 h retention)
//	Module E — api.Server              (REST + WebSocket hub)
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/monitoring/backend/agent"
	"github.com/monitoring/backend/api"
	"github.com/monitoring/backend/collector"
	"github.com/monitoring/backend/storage"
)

func main() {
	// ── Flags ─────────────────────────────────────────────────────────────────
	cfg := api.DefaultConfig()

	mode := flag.String("mode", "server", "Run mode: server (hub + UI) or agent (remote collector)")
	addr := flag.String("addr", cfg.Addr, "HTTP listen address (e.g. :8080) [server]")
	dockerHost := flag.String("docker-host", os.Getenv("DOCKER_HOST"),
		"Docker daemon endpoint URI; empty → auto-detect from OS")
	dbPath := flag.String("db", cfg.DBPath, "Path to SQLite database file [server]")
	retention := flag.Duration("retention", cfg.Retention,
		"Metric/log retention window (e.g. 24h, 720h) [server]")
	pollInterval := flag.Duration("poll", cfg.PollInterval,
		"Host metric polling interval")

	// Security + identity (server and agent share the enroll/admin tokens).
	// Admin token is hardcoded to "changeme" as the out-of-the-box default so
	// localhost mutating actions work without extra config; override via the
	// MONITOR_ADMIN_TOKEN env var or the -admin-token flag.
	defaultAdminToken := os.Getenv("MONITOR_ADMIN_TOKEN")
	if defaultAdminToken == "" {
		defaultAdminToken = "changeme"
	}
	adminToken := flag.String("admin-token", defaultAdminToken,
		"Bearer token required on mutating endpoints; empty disables actions [server]")
	enrollToken := flag.String("enroll-token", os.Getenv("MONITOR_ENROLL_TOKEN"),
		"Shared secret agents present to connect; empty disables agent access")
	localHostID := flag.String("local-host-id", cfg.LocalHostID, "Host id tagging the hub's own metrics [server]")
	localHostName := flag.String("local-host-name", cfg.LocalHostName, "Display name for the local host [server]")

	// Image vulnerability scanning (Trivy) — server + agents share these.
	trivyBin := flag.String("trivy-bin", cfg.TrivyBinary,
		"Image scanner binary name/path (looked up on PATH); empty → 'trivy'")
	scanSeverities := flag.String("scan-severities", cfg.ScanSeverities,
		"Comma-separated Trivy severities to report (e.g. CRITICAL,HIGH)")
	scanTimeout := flag.Duration("scan-timeout", cfg.ScanTimeout,
		"Per-image Trivy scan deadline (e.g. 10m)")
	scanModes := flag.String("scan-modes", cfg.ScanModes,
		"Comma-separated Trivy scanner modes (e.g. vuln,secret,misconfig)")
	autoScan := flag.Bool("auto-scan", cfg.AutoScan,
		"Periodically scan the local host's in-use images (requires Trivy on PATH)")
	scanInterval := flag.Duration("scan-interval", cfg.ScanInterval,
		"Background scan interval when -auto-scan is set (min 5m, e.g. 24h)")

	// Alerting (Phase 8). SMTP credentials are flag/env only — the password is
	// never persisted to the database or exposed in the UI.
	alertInterval := flag.Duration("alert-interval", cfg.AlertInterval,
		"Alert rule evaluation interval (min 10s) [server]")
	smtpDefaultPort := cfg.SMTPPort
	if v, err := strconv.Atoi(os.Getenv("MONITOR_SMTP_PORT")); err == nil && v > 0 {
		smtpDefaultPort = v
	}
	smtpHost := flag.String("smtp-host", os.Getenv("MONITOR_SMTP_HOST"),
		"SMTP server host for email alerts; empty disables the email channel [server]")
	smtpPort := flag.Int("smtp-port", smtpDefaultPort,
		"SMTP server port (587 STARTTLS, 465 implicit TLS) [server]")
	smtpFrom := flag.String("smtp-from", os.Getenv("MONITOR_SMTP_FROM"),
		"From address for alert emails [server]")
	smtpUser := flag.String("smtp-user", os.Getenv("MONITOR_SMTP_USER"),
		"SMTP username; empty = no auth [server]")
	smtpPass := flag.String("smtp-pass", os.Getenv("MONITOR_SMTP_PASSWORD"),
		"SMTP password (env/flag only, never stored) [server]")

	// Agent-only flags.
	hubURL := flag.String("hub-url", "", "Hub WebSocket URL to connect to, e.g. wss://hub:8080/ws/agent [agent]")
	hostID := flag.String("host-id", "", "Stable id this agent reports to the hub [agent]")
	hostName := flag.String("name", "", "Human-readable host name shown in the UI [agent]")

	flag.Parse()

	// ── Context with graceful shutdown ────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("main: received signal %v — shutting down", sig)
		cancel()
	}()

	// ── Agent mode: connect to the hub and stream; no HTTP server or DB ───────
	if *mode == "agent" {
		if *hubURL == "" {
			log.Fatal("main: -mode=agent requires -hub-url")
		}
		if *hostID == "" {
			log.Fatal("main: -mode=agent requires -host-id")
		}
		name := *hostName
		if name == "" {
			name = *hostID
		}
		log.Printf("main: starting AGENT host-id=%s hub=%s", *hostID, *hubURL)
		if err := agent.Run(ctx, agent.Options{
			HubURL:       *hubURL,
			HostID:       *hostID,
			Name:         name,
			EnrollToken:  *enrollToken,
			DockerHost:   *dockerHost,
			PollInterval: *pollInterval,
		}); err != nil && ctx.Err() == nil {
			log.Fatalf("main: agent: %v", err)
		}
		log.Println("main: agent shutdown complete")
		return
	}

	// ── Module B: Docker SDK client ───────────────────────────────────────────
	// Docker is optional: if the daemon is unreachable the server still starts
	// and serves host metrics + the SPA; container panels show an empty state.
	var dc *collector.DockerClient
	dc, dockerErr := collector.NewDockerClient(*dockerHost)
	if dockerErr != nil {
		log.Printf("main: WARNING Docker unavailable (%v) — running in host-metrics-only mode", dockerErr)
		dc = nil
	} else {
		defer dc.Close()
		log.Printf("main: Docker SDK connected  endpoint=%s  os=%s", dc.Endpoint, dc.OS)
	}

	// ── Module A: Host metrics collector ──────────────────────────────────────
	hc := collector.NewHostCollector(*pollInterval)

	// ── Module D: SQLite storage ──────────────────────────────────────────────
	db, err := storage.Open(*dbPath, *retention)
	if err != nil {
		log.Fatalf("main: storage open: %v", err)
	}
	defer db.Close()
	log.Printf("main: SQLite ready  path=%s  retention=%s", *dbPath, *retention)
	db.StartWriter(ctx) // serialises all hot-path writes through one goroutine

	// ── Module E: Hub + HTTP/WS server ────────────────────────────────────────
	hub := api.NewHub()

	serverCfg := api.Config{
		Addr:          *addr,
		DockerHost:    *dockerHost,
		DBPath:        *dbPath,
		Retention:     *retention,
		PollInterval:  *pollInterval,
		AdminToken:    *adminToken,
		EnrollToken:   *enrollToken,
		LocalHostID:   *localHostID,
		LocalHostName: *localHostName,
		TrivyBinary:    *trivyBin,
		ScanSeverities: *scanSeverities,
		ScanTimeout:    *scanTimeout,
		ScanModes:      *scanModes,
		AutoScan:       *autoScan,
		ScanInterval:   *scanInterval,
		AlertInterval:  *alertInterval,
		SMTPHost:       *smtpHost,
		SMTPPort:       *smtpPort,
		SMTPFrom:       *smtpFrom,
		SMTPUser:       *smtpUser,
		SMTPPassword:   *smtpPass,
	}

	srv := api.New(serverCfg, hub, dc, hc, db)

	// Enable SPA static serving when built with `-tags embed`.
	// staticFS is nil in normal (API-only) builds, so this is safe to call always.
	srv.SetStaticFS(staticFS)

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("main: server: %v", err)
	}

	log.Println("main: shutdown complete")
}
