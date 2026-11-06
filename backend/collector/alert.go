package collector

import "time"

// Alert domain models. These live in collector (not api) because both the api
// layer and the storage layer need them, and storage must not import api
// (api already imports storage, so that would be a cycle).

// AlertRule is a user-configurable condition evaluated by the alert scheduler.
type AlertRule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Type            string   `json:"type"` // "host" | "container" | "cve" | "offline"
	Metric          string   `json:"metric,omitempty"`    // host: cpu|mem|disk|swap|load1
	Op              string   `json:"op,omitempty"`        // ">" | "<"
	Threshold       float64  `json:"threshold"`           // host threshold value
	ForSeconds      int      `json:"for_seconds"`         // sustained window before firing
	Severity        string   `json:"severity"`            // info | warning | critical
	EventKinds      []string `json:"event_kinds,omitempty"`     // container: exit | oom | unhealthy
	MinSeverity     string   `json:"min_severity,omitempty"`    // cve: CRITICAL | HIGH
	CountThreshold  int      `json:"count_threshold,omitempty"` // cve: fire when count >= this
	CooldownSeconds int      `json:"cooldown_seconds"`          // min gap before re-notifying
	ChannelIDs      []string `json:"channel_ids,omitempty"`     // empty = all enabled channels
}

// Alert is one firing/resolved instance of a rule against a resource.
type Alert struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"rule_id"`
	RuleName   string     `json:"rule_name"`
	Type       string     `json:"type"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"` // firing | resolved
	Resource   string     `json:"resource"`
	Metric     string     `json:"metric,omitempty"`
	Value      float64    `json:"value"`
	Threshold  float64    `json:"threshold"`
	Summary    string     `json:"summary"`
	Detail     string     `json:"detail,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Notified   string     `json:"notified,omitempty"` // JSON: per-channel delivery result
	Acked      bool       `json:"acked"`
	AckedAt    *time.Time `json:"acked_at,omitempty"`
	AckNote    string     `json:"ack_note,omitempty"`
}

// AlertChannel is a delivery target (webhook / slack / email). SMTP server
// credentials are configured via flags/env, never stored here.
type AlertChannel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"` // webhook | slack | email
	Enabled bool   `json:"enabled"`
	URL     string `json:"url,omitempty"` // webhook / slack endpoint
	To      string `json:"to,omitempty"`  // email recipient(s), comma-separated
}
