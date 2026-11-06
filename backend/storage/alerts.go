package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/monitoring/backend/collector"
)

// Alert rules and channels are stored as JSON bodies keyed by id (they contain
// slices, so a blob avoids column churn). Alerts are a relational table so they
// can be queried by status and time. Writes here run synchronously — they are
// low-frequency (config changes, alert transitions), not the hot per-second path.

// ── Rules ──────────────────────────────────────────────────────────────────────

func (db *DB) UpsertAlertRule(r collector.AlertRule) error {
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("storage: marshal rule: %w", err)
	}
	_, err = db.handle.Exec(
		`INSERT INTO alert_rules (id, body) VALUES (?, ?)
		 ON CONFLICT(id) DO UPDATE SET body=excluded.body`,
		r.ID, string(body),
	)
	if err != nil {
		return fmt.Errorf("storage: UpsertAlertRule: %w", err)
	}
	return nil
}

func (db *DB) DeleteAlertRule(id string) error {
	if _, err := db.handle.Exec(`DELETE FROM alert_rules WHERE id = ?`, id); err != nil {
		return fmt.Errorf("storage: DeleteAlertRule: %w", err)
	}
	return nil
}

func (db *DB) ListAlertRules() ([]collector.AlertRule, error) {
	rows, err := db.handle.Query(`SELECT body FROM alert_rules`)
	if err != nil {
		return nil, fmt.Errorf("storage: ListAlertRules: %w", err)
	}
	defer rows.Close()
	var out []collector.AlertRule
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("storage: scan rule row: %w", err)
		}
		var r collector.AlertRule
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			continue // skip malformed rows
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, rows.Err()
}

// ── Channels ─────────────────────────────────────────────────────────────────

func (db *DB) UpsertAlertChannel(c collector.AlertChannel) error {
	body, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("storage: marshal channel: %w", err)
	}
	_, err = db.handle.Exec(
		`INSERT INTO alert_channels (id, body) VALUES (?, ?)
		 ON CONFLICT(id) DO UPDATE SET body=excluded.body`,
		c.ID, string(body),
	)
	if err != nil {
		return fmt.Errorf("storage: UpsertAlertChannel: %w", err)
	}
	return nil
}

func (db *DB) DeleteAlertChannel(id string) error {
	if _, err := db.handle.Exec(`DELETE FROM alert_channels WHERE id = ?`, id); err != nil {
		return fmt.Errorf("storage: DeleteAlertChannel: %w", err)
	}
	return nil
}

func (db *DB) ListAlertChannels() ([]collector.AlertChannel, error) {
	rows, err := db.handle.Query(`SELECT body FROM alert_channels`)
	if err != nil {
		return nil, fmt.Errorf("storage: ListAlertChannels: %w", err)
	}
	defer rows.Close()
	var out []collector.AlertChannel
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("storage: scan channel row: %w", err)
		}
		var c collector.AlertChannel
		if err := json.Unmarshal([]byte(body), &c); err != nil {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, rows.Err()
}

// ── Alerts ───────────────────────────────────────────────────────────────────

// SaveAlert upserts one alert row (used on fire and when re-saving with the
// notified result after dispatch).
func (db *DB) SaveAlert(a collector.Alert) error {
	resolved := ""
	if a.ResolvedAt != nil {
		resolved = a.ResolvedAt.UTC().Format(time.RFC3339Nano)
	}
	ackedInt := 0
	if a.Acked {
		ackedInt = 1
	}
	ackedAt := ""
	if a.AckedAt != nil {
		ackedAt = a.AckedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := db.handle.Exec(
		`INSERT INTO alerts
		 (id, rule_id, rule_name, type, severity, status, resource, metric,
		  value, threshold, summary, detail, started_at, resolved_at, notified,
		  acked, acked_at, ack_note)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   status=excluded.status, value=excluded.value, summary=excluded.summary,
		   detail=excluded.detail, resolved_at=excluded.resolved_at, notified=excluded.notified`,
		a.ID, a.RuleID, a.RuleName, a.Type, a.Severity, a.Status, a.Resource, a.Metric,
		a.Value, a.Threshold, a.Summary, a.Detail,
		a.StartedAt.UTC().Format(time.RFC3339Nano), resolved, a.Notified,
		ackedInt, ackedAt, a.AckNote,
	)
	if err != nil {
		return fmt.Errorf("storage: SaveAlert: %w", err)
	}
	return nil
}

// AckAlert records that a human acknowledged a firing alert, with an optional
// note. It only touches the ack columns, so it never disturbs the alert's
// firing/resolved lifecycle or its delivery log.
func (db *DB) AckAlert(id, note string, at time.Time) error {
	_, err := db.handle.Exec(
		`UPDATE alerts SET acked=1, acked_at=?, ack_note=? WHERE id=?`,
		at.UTC().Format(time.RFC3339Nano), note, id,
	)
	if err != nil {
		return fmt.Errorf("storage: AckAlert: %w", err)
	}
	return nil
}

// ResolveAlert marks a firing alert resolved at the given time.
func (db *DB) ResolveAlert(id string, at time.Time) error {
	_, err := db.handle.Exec(
		`UPDATE alerts SET status='resolved', resolved_at=? WHERE id=?`,
		at.UTC().Format(time.RFC3339Nano), id,
	)
	if err != nil {
		return fmt.Errorf("storage: ResolveAlert: %w", err)
	}
	return nil
}

func scanAlert(rows rowScanner) (collector.Alert, error) {
	var (
		a                                             collector.Alert
		metric, detail, started, resolved, notified   sql.NullString
		ackedAt                                       sql.NullString
		ackNote                                       sql.NullString
		ackedInt                                      int
	)
	err := rows.Scan(
		&a.ID, &a.RuleID, &a.RuleName, &a.Type, &a.Severity, &a.Status, &a.Resource, &metric,
		&a.Value, &a.Threshold, &a.Summary, &detail, &started, &resolved, &notified,
		&ackedInt, &ackedAt, &ackNote,
	)
	if err != nil {
		return a, err
	}
	a.Metric = metric.String
	a.Detail = detail.String
	a.Notified = notified.String
	a.Acked = ackedInt != 0
	a.AckNote = ackNote.String
	if started.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, started.String); perr == nil {
			a.StartedAt = t
		}
	}
	if resolved.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, resolved.String); perr == nil {
			a.ResolvedAt = &t
		}
	}
	if ackedAt.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, ackedAt.String); perr == nil {
			a.AckedAt = &t
		}
	}
	return a, nil
}

const alertCols = `id, rule_id, rule_name, type, severity, status, resource, metric,
	value, threshold, summary, detail, started_at, resolved_at, notified,
	acked, acked_at, ack_note`

// ListAlerts returns up to limit alerts, newest first. status "" = all,
// otherwise filtered (e.g. "firing", "resolved").
func (db *DB) ListAlerts(status string, limit int) ([]collector.Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT ` + alertCols + ` FROM alerts`
	args := []interface{}{}
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY started_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.handle.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: ListAlerts: %w", err)
	}
	defer rows.Close()
	var out []collector.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: scan alert row: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListActiveAlerts returns all currently-firing alerts, newest first.
func (db *DB) ListActiveAlerts() ([]collector.Alert, error) {
	return db.ListAlerts("firing", 500)
}

// rowScanner abstracts *sql.Rows for the shared scan helper.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// ── Generic settings (key/value) ─────────────────────────────────────────────

// GetSetting returns the stored value for key and whether it exists. A missing
// key yields ("", false, nil) rather than an error.
func (db *DB) GetSetting(key string) (string, bool, error) {
	var val string
	err := db.handle.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("storage: GetSetting %q: %w", key, err)
	}
	return val, true, nil
}

// SetSetting upserts the value for key (empty value is a valid, stored string).
func (db *DB) SetSetting(key, value string) error {
	_, err := db.handle.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("storage: SetSetting %q: %w", key, err)
	}
	return nil
}
