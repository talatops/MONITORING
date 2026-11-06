package api

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/monitoring/backend/collector"
)

// Re-export the alert domain models (defined in collector so storage can use
// them without importing api) under the api package's names.
type (
	AlertRule    = collector.AlertRule
	AlertChannel = collector.AlertChannel
	Alert        = collector.Alert
)

// newID returns a short, collision-resistant hex id prefixed by kind.
func newID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// defaultAlertRules are seeded (disabled) on first run so the Alerts tab is not
// empty. Users enable and tune them as needed.
func defaultAlertRules() []AlertRule {
	return []AlertRule{
		{ID: newID("rule"), Name: "CPU over 90%", Enabled: false, Type: "host", Metric: "cpu", Op: ">", Threshold: 90, ForSeconds: 300, Severity: "warning", CooldownSeconds: 900},
		{ID: newID("rule"), Name: "Memory over 90%", Enabled: false, Type: "host", Metric: "mem", Op: ">", Threshold: 90, ForSeconds: 300, Severity: "warning", CooldownSeconds: 900},
		{ID: newID("rule"), Name: "Disk over 90%", Enabled: false, Type: "host", Metric: "disk", Op: ">", Threshold: 90, ForSeconds: 300, Severity: "critical", CooldownSeconds: 1800},
		{ID: newID("rule"), Name: "Container exited", Enabled: false, Type: "container", EventKinds: []string{"exit", "oom"}, Severity: "critical", CooldownSeconds: 60},
		{ID: newID("rule"), Name: "Container unhealthy", Enabled: false, Type: "container", EventKinds: []string{"unhealthy"}, Severity: "warning", CooldownSeconds: 600},
		{ID: newID("rule"), Name: "Host / daemon offline", Enabled: false, Type: "offline", ForSeconds: 60, Severity: "critical", CooldownSeconds: 600},
		{ID: newID("rule"), Name: "New critical CVEs", Enabled: false, Type: "cve", MinSeverity: "CRITICAL", CountThreshold: 1, Severity: "critical", CooldownSeconds: 3600},
	}
}
