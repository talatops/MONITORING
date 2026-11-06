// Package storage provides a thin embedded-SQLite layer for persisting
// time-series host metrics and container logs with a configurable retention
// window (default 24 hours per general.md §Module D).
//
// Driver: modernc.org/sqlite — pure Go, no CGO, works on Linux and Windows.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver with database/sql

	"github.com/monitoring/backend/collector"
)

// DB wraps an *sql.DB with domain-specific helpers for the monitoring backend.
// All hot-path writes (container logs, host metrics) go through QueueWrite so
// they are serialised by a single background writer goroutine — this eliminates
// SQLITE_BUSY under high concurrent-write load.
type DB struct {
	handle    *sql.DB
	retention time.Duration
	writeCh   chan func() // buffered write queue
}

// Open creates (or opens) the SQLite database at dbPath, runs migrations, and
// returns a ready-to-use DB. Pass ":memory:" for an ephemeral test database.
func Open(dbPath string, retention time.Duration) (*DB, error) {
	if retention <= 0 {
		retention = 24 * time.Hour
	}

	// modernc.org/sqlite uses _pragma= syntax (NOT the mattn/go-sqlite3 style).
	// WAL + busy_timeout(10s) + txlock=immediate eliminates SQLITE_BUSY under
	// concurrent access from the single-writer goroutine + HTTP readers.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=txlock(immediate)", dbPath)
	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", dbPath, err)
	}

	// SQLite serialises writes at the file level; limit the pool to one
	// connection so the database/sql driver never hands two writers
	// different connections simultaneously.
	handle.SetMaxOpenConns(1)

	db := &DB{
		handle:    handle,
		retention: retention,
		writeCh:   make(chan func(), 4096), // large buffer absorbs log bursts
	}
	if err := db.migrate(); err != nil {
		handle.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the underlying database handle.
func (db *DB) Close() error {
	close(db.writeCh)
	return db.handle.Close()
}

// ─────────────────────────────────────────────────────────────────────────────
// Async write queue
// ─────────────────────────────────────────────────────────────────────────────

// StartWriter launches the single background goroutine that drains writeCh.
// Call once after Open(); it exits when ctx is cancelled.
func (db *DB) StartWriter(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case fn, ok := <-db.writeCh:
				if !ok {
					return // channel closed via Close()
				}
				fn() // error is already handled inside the closure
			}
		}
	}()
}

// QueueWrite enqueues fn for asynchronous execution by the writer goroutine.
// If the queue is full (4096 pending writes) the op is dropped with a warning
// rather than blocking the caller — safe for best-effort log persistence.
func (db *DB) QueueWrite(fn func() error) {
	select {
	case db.writeCh <- func() {
		if err := fn(); err != nil {
			log.Printf("storage: queued write: %v", err)
		}
	}:
	default:
		log.Println("storage: WARNING write queue full — dropping one write")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema
// ─────────────────────────────────────────────────────────────────────────────

const schema = `
CREATE TABLE IF NOT EXISTS host_metrics (
    ts            TEXT    NOT NULL,
    cpu_percent   REAL,
    mem_used      INTEGER,
    mem_total     INTEGER,
    mem_percent   REAL,
    disk_read_bps INTEGER,
    disk_write_bps INTEGER,
    net_recv_bps  INTEGER,
    net_sent_bps  INTEGER,
    num_cpu       INTEGER,
    go_os         TEXT
);

CREATE TABLE IF NOT EXISTS container_logs (
    ts           TEXT    NOT NULL,
    container_id TEXT    NOT NULL,
    stream       TEXT,
    line         TEXT
);

CREATE TABLE IF NOT EXISTS image_scans (
    image_id    TEXT    PRIMARY KEY,
    ref         TEXT,
    scanner     TEXT,
    scanned_at  TEXT,
    counts_json TEXT,
    vulns_json  TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    image_id        TEXT,
    ref             TEXT,
    scanned_at      TEXT,
    counts_json     TEXT,
    total           INTEGER,
    secret_count    INTEGER,
    misconfig_count INTEGER
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id   TEXT PRIMARY KEY,
    body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_channels (
    id   TEXT PRIMARY KEY,
    body TEXT NOT NULL
);

-- Generic key/value settings store (e.g. the SMTP config saved from the UI).
-- Values are opaque JSON strings; secrets within them are encrypted by the
-- caller before they reach storage.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT,
    rule_name   TEXT,
    type        TEXT,
    severity    TEXT,
    status      TEXT,
    resource    TEXT,
    metric      TEXT,
    value       REAL,
    threshold   REAL,
    summary     TEXT,
    detail      TEXT,
    started_at  TEXT,
    resolved_at TEXT,
    notified    TEXT,
    acked       INTEGER DEFAULT 0,
    acked_at    TEXT,
    ack_note    TEXT
);

CREATE INDEX IF NOT EXISTS idx_host_ts      ON host_metrics(ts);
CREATE INDEX IF NOT EXISTS idx_logs_cid_ts  ON container_logs(container_id, ts);
CREATE INDEX IF NOT EXISTS idx_history_img_ts ON scan_history(image_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status_ts ON alerts(status, started_at);
`

func (db *DB) migrate() error {
	_, err := db.handle.Exec(schema)
	if err != nil {
		return fmt.Errorf("storage: migrate: %w", err)
	}
	// Schema above only creates missing tables; it never adds columns to an
	// existing one. Alerts introduced ack columns after the fact, so backfill
	// them for databases created before that change (SQLite errors on a
	// duplicate column, which we ignore).
	for _, col := range []string{
		`ALTER TABLE alerts ADD COLUMN acked INTEGER DEFAULT 0`,
		`ALTER TABLE alerts ADD COLUMN acked_at TEXT`,
		`ALTER TABLE alerts ADD COLUMN ack_note TEXT`,
	} {
		if _, err := db.handle.Exec(col); err != nil &&
			!strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("storage: migrate alert column: %w", err)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Write operations
// ─────────────────────────────────────────────────────────────────────────────

// SaveHostMetrics appends one HostMetrics row to the time-series table.
func (db *DB) SaveHostMetrics(m collector.HostMetrics) error {
	_, err := db.handle.Exec(
		`INSERT INTO host_metrics
		 (ts, cpu_percent, mem_used, mem_total, mem_percent,
		  disk_read_bps, disk_write_bps, net_recv_bps, net_sent_bps, num_cpu, go_os)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.Timestamp.UTC().Format(time.RFC3339Nano),
		m.CPUPercent,
		m.MemUsedBytes,
		m.MemTotalBytes,
		m.MemPercent,
		m.DiskReadBPS,
		m.DiskWriteBPS,
		m.NetRecvBPS,
		m.NetSentBPS,
		m.NumCPU,
		m.GOOS,
	)
	if err != nil {
		return fmt.Errorf("storage: SaveHostMetrics: %w", err)
	}
	return nil
}

// SaveContainerLog appends one LogEntry row.
func (db *DB) SaveContainerLog(entry collector.LogEntry) error {
	_, err := db.handle.Exec(
		`INSERT INTO container_logs (ts, container_id, stream, line) VALUES (?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano),
		entry.ContainerID,
		entry.Stream,
		entry.Line,
	)
	if err != nil {
		return fmt.Errorf("storage: SaveContainerLog: %w", err)
	}
	return nil
}

// SaveImageScan upserts the latest Trivy result for an image, keyed by image ID
// so a re-scan replaces the prior row. Counts and vulnerabilities are stored as
// JSON blobs (the panel re-reads them whole; we never query CVEs by column).
func (db *DB) SaveImageScan(s collector.ImageVulnScan) error {
	counts, err := json.Marshal(s.Counts)
	if err != nil {
		return fmt.Errorf("storage: marshal counts: %w", err)
	}
	vulns, err := json.Marshal(s.Vulnerabilities)
	if err != nil {
		return fmt.Errorf("storage: marshal vulns: %w", err)
	}
	_, err = db.handle.Exec(
		`INSERT INTO image_scans (image_id, ref, scanner, scanned_at, counts_json, vulns_json)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(image_id) DO UPDATE SET
		   ref=excluded.ref, scanner=excluded.scanner, scanned_at=excluded.scanned_at,
		   counts_json=excluded.counts_json, vulns_json=excluded.vulns_json`,
		s.ImageID, s.Ref, s.Scanner,
		s.ScannedAt.UTC().Format(time.RFC3339Nano),
		string(counts), string(vulns),
	)
	if err != nil {
		return fmt.Errorf("storage: SaveImageScan: %w", err)
	}
	return nil
}

// scanRow decodes one image_scans row into an ImageVulnScan.
func scanRow(imageID, ref, scanner, scannedAt, countsJSON, vulnsJSON string) collector.ImageVulnScan {
	var s collector.ImageVulnScan
	_ = json.Unmarshal([]byte(countsJSON), &s.Counts)
	_ = json.Unmarshal([]byte(vulnsJSON), &s.Vulnerabilities)
	if s.Vulnerabilities == nil {
		s.Vulnerabilities = []collector.Vulnerability{}
	}
	s.ImageID, s.Ref, s.Scanner = imageID, ref, scanner
	if t, err := time.Parse(time.RFC3339Nano, scannedAt); err == nil {
		s.ScannedAt = t
	}
	return s
}

// GetImageScan returns the cached scan for an image ID, and whether it exists.
func (db *DB) GetImageScan(imageID string) (collector.ImageVulnScan, bool, error) {
	row := db.handle.QueryRow(
		`SELECT image_id, ref, scanner, scanned_at, counts_json, vulns_json
		 FROM image_scans WHERE image_id = ?`, imageID,
	)
	var id, ref, scanner, scannedAt, countsJSON, vulnsJSON string
	if err := row.Scan(&id, &ref, &scanner, &scannedAt, &countsJSON, &vulnsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return collector.ImageVulnScan{}, false, nil
		}
		return collector.ImageVulnScan{}, false, fmt.Errorf("storage: GetImageScan: %w", err)
	}
	return scanRow(id, ref, scanner, scannedAt, countsJSON, vulnsJSON), true, nil
}

// GetImageScanByRef returns the cached scan stored for an image reference/tag,
// and whether it exists. The vulns endpoint keys off the human tag the panel
// shows (the same value Trivy was run with), so a ref lookup avoids a resolve.
func (db *DB) GetImageScanByRef(ref string) (collector.ImageVulnScan, bool, error) {
	row := db.handle.QueryRow(
		`SELECT image_id, ref, scanner, scanned_at, counts_json, vulns_json
		 FROM image_scans WHERE ref = ?`, ref,
	)
	var id, r, scanner, scannedAt, countsJSON, vulnsJSON string
	if err := row.Scan(&id, &r, &scanner, &scannedAt, &countsJSON, &vulnsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return collector.ImageVulnScan{}, false, nil
		}
		return collector.ImageVulnScan{}, false, fmt.Errorf("storage: GetImageScanByRef: %w", err)
	}
	return scanRow(id, r, scanner, scannedAt, countsJSON, vulnsJSON), true, nil
}

// ListImageScans returns every cached scan (bounded by the number of images),
// used to enrich the fleet security overview without re-running Trivy.
func (db *DB) ListImageScans() ([]collector.ImageVulnScan, error) {
	rows, err := db.handle.Query(
		`SELECT image_id, ref, scanner, scanned_at, counts_json, vulns_json FROM image_scans`,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: ListImageScans: %w", err)
	}
	defer rows.Close()

	var out []collector.ImageVulnScan
	for rows.Next() {
		var id, ref, scanner, scannedAt, countsJSON, vulnsJSON string
		if err := rows.Scan(&id, &ref, &scanner, &scannedAt, &countsJSON, &vulnsJSON); err != nil {
			return nil, fmt.Errorf("storage: scan image row: %w", err)
		}
		out = append(out, scanRow(id, ref, scanner, scannedAt, countsJSON, vulnsJSON))
	}
	return out, rows.Err()
}

// ScanTrend is one lightweight history point: the severity counts (plus secret
// and misconfig totals) recorded for an image at a scan time. It powers the
// per-image CVE trend chart; the full finding detail stays in image_scans.
type ScanTrend struct {
	ScannedAt      string         `json:"scanned_at"`
	Counts         map[string]int `json:"counts"`
	Total          int            `json:"total"`
	SecretCount    int            `json:"secret_count"`
	MisconfigCount int            `json:"misconfig_count"`
}

// AppendScanHistory records a counts-only history row for one scan result. Called
// alongside SaveImageScan on every scan (on-demand or scheduled). Errors are the
// caller's to log; a failure here must not fail the scan response.
func (db *DB) AppendScanHistory(s collector.ImageVulnScan) error {
	counts, err := json.Marshal(s.Counts)
	if err != nil {
		return fmt.Errorf("storage: marshal history counts: %w", err)
	}
	total := 0
	for _, n := range s.Counts {
		total += n
	}
	_, err = db.handle.Exec(
		`INSERT INTO scan_history (image_id, ref, scanned_at, counts_json, total, secret_count, misconfig_count)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		s.ImageID, s.Ref, s.ScannedAt.UTC().Format(time.RFC3339Nano),
		string(counts), total, s.SecretCount, s.MisconfigCount,
	)
	if err != nil {
		return fmt.Errorf("storage: AppendScanHistory: %w", err)
	}
	return nil
}

// GetScanHistory returns up to `limit` most-recent trend points for an image ID,
// ordered oldest-first (ready to plot on a time axis).
func (db *DB) GetScanHistory(imageID string, limit int) ([]ScanTrend, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.handle.Query(
		`SELECT scanned_at, counts_json, total, secret_count, misconfig_count
		 FROM scan_history WHERE image_id = ? ORDER BY scanned_at DESC LIMIT ?`,
		imageID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: GetScanHistory: %w", err)
	}
	defer rows.Close()

	var out []ScanTrend
	for rows.Next() {
		var scannedAt, countsJSON string
		var t ScanTrend
		if err := rows.Scan(&scannedAt, &countsJSON, &t.Total, &t.SecretCount, &t.MisconfigCount); err != nil {
			return nil, fmt.Errorf("storage: scan history row: %w", err)
		}
		_ = json.Unmarshal([]byte(countsJSON), &t.Counts)
		if t.Counts == nil {
			t.Counts = map[string]int{}
		}
		t.ScannedAt = scannedAt
		out = append(out, t)
	}
	// Query returned newest-first; reverse to oldest-first for plotting.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// Read operations
// ─────────────────────────────────────────────────────────────────────────────

// GetContainerLogs returns up to `limit` most-recent log entries for
// containerID, ordered newest-first. Returns an empty slice when nothing found.
func (db *DB) GetContainerLogs(containerID string, limit int) ([]collector.LogEntry, error) {
	if limit <= 0 {
		limit = 200
	}

	rows, err := db.handle.Query(
		`SELECT container_id, stream, line
		 FROM container_logs
		 WHERE container_id = ?
		 ORDER BY ts DESC
		 LIMIT ?`,
		containerID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: GetContainerLogs: %w", err)
	}
	defer rows.Close()

	var result []collector.LogEntry
	for rows.Next() {
		var e collector.LogEntry
		if err := rows.Scan(&e.ContainerID, &e.Stream, &e.Line); err != nil {
			return nil, fmt.Errorf("storage: scan log row: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// GetHostMetricsHistory returns up to `limit` recent host metric snapshots
// ordered newest-first.
func (db *DB) GetHostMetricsHistory(limit int) ([]collector.HostMetrics, error) {
	if limit <= 0 {
		limit = 300
	}

	rows, err := db.handle.Query(
		`SELECT ts, cpu_percent, mem_used, mem_total, mem_percent,
		        disk_read_bps, disk_write_bps, net_recv_bps, net_sent_bps, num_cpu, go_os
		 FROM host_metrics
		 ORDER BY ts DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: GetHostMetricsHistory: %w", err)
	}
	defer rows.Close()

	var result []collector.HostMetrics
	for rows.Next() {
		var (
			m   collector.HostMetrics
			tsS string
		)
		if err := rows.Scan(
			&tsS,
			&m.CPUPercent,
			&m.MemUsedBytes,
			&m.MemTotalBytes,
			&m.MemPercent,
			&m.DiskReadBPS,
			&m.DiskWriteBPS,
			&m.NetRecvBPS,
			&m.NetSentBPS,
			&m.NumCPU,
			&m.GOOS,
		); err != nil {
			return nil, fmt.Errorf("storage: scan metric row: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, tsS); err == nil {
			m.Timestamp = t
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// GetHostMetricsHistoryRange returns host metric snapshots captured within the
// trailing `window` (e.g. time.Hour), ordered oldest-first for chart rendering.
// RFC3339Nano timestamps are lexicographically sortable in UTC, so the cutoff
// comparison works on the stored text column (same trick as Prune).
//
// To bound payload size for wide windows (e.g. 24 h at 1 s = ~86k rows), the
// result is evenly downsampled to at most `maxPoints` samples. Pass maxPoints
// <= 0 to disable downsampling.
func (db *DB) GetHostMetricsHistoryRange(window time.Duration, maxPoints int) ([]collector.HostMetrics, error) {
	cutoff := time.Now().UTC().Add(-window).Format(time.RFC3339Nano)

	rows, err := db.handle.Query(
		`SELECT ts, cpu_percent, mem_used, mem_total, mem_percent,
		        disk_read_bps, disk_write_bps, net_recv_bps, net_sent_bps, num_cpu, go_os
		 FROM host_metrics
		 WHERE ts >= ?
		 ORDER BY ts ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: GetHostMetricsHistoryRange: %w", err)
	}
	defer rows.Close()

	var result []collector.HostMetrics
	for rows.Next() {
		var (
			m   collector.HostMetrics
			tsS string
		)
		if err := rows.Scan(
			&tsS,
			&m.CPUPercent,
			&m.MemUsedBytes,
			&m.MemTotalBytes,
			&m.MemPercent,
			&m.DiskReadBPS,
			&m.DiskWriteBPS,
			&m.NetRecvBPS,
			&m.NetSentBPS,
			&m.NumCPU,
			&m.GOOS,
		); err != nil {
			return nil, fmt.Errorf("storage: scan metric row: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, tsS); err == nil {
			m.Timestamp = t
		}
		result = append(result, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Even downsample to maxPoints, always keeping the newest sample.
	if maxPoints > 0 && len(result) > maxPoints {
		step := float64(len(result)) / float64(maxPoints)
		sampled := make([]collector.HostMetrics, 0, maxPoints)
		for i := 0; i < maxPoints; i++ {
			sampled = append(sampled, result[int(float64(i)*step)])
		}
		sampled = append(sampled, result[len(result)-1])
		return sampled, nil
	}
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Retention
// ─────────────────────────────────────────────────────────────────────────────

// Prune deletes all rows older than the configured retention window.
// Run it periodically (e.g. every hour) to keep the database bounded.
func (db *DB) Prune() (int64, error) {
	cutoff := time.Now().UTC().Add(-db.retention).Format(time.RFC3339Nano)

	res1, err := db.handle.Exec(`DELETE FROM host_metrics WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("storage: prune host_metrics: %w", err)
	}
	res2, err := db.handle.Exec(`DELETE FROM container_logs WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("storage: prune container_logs: %w", err)
	}
	res3, err := db.handle.Exec(`DELETE FROM scan_history WHERE scanned_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("storage: prune scan_history: %w", err)
	}

	n1, _ := res1.RowsAffected()
	n2, _ := res2.RowsAffected()
	n3, _ := res3.RowsAffected()
	return n1 + n2 + n3, nil
}

// StartPruneTicker runs Prune() every `interval` until ctx is cancelled.
// A non-positive interval defaults to 1 hour.
func (db *DB) StartPruneTicker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := db.Prune(); err != nil {
					fmt.Printf("storage: prune error: %v\n", err)
				} else if n > 0 {
					fmt.Printf("storage: pruned %d stale row(s)\n", n)
				}
			}
		}
	}()
}
