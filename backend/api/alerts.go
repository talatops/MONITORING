package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/monitoring/backend/collector"
)

// ─────────────────────────────────────────────────────────────────────────────
// Phase 8: alerting — background evaluator, dispatch, and REST handlers.
// ─────────────────────────────────────────────────────────────────────────────

// alertRuntime is the in-memory state for one (rule, resource) pair. It drives
// the sustained "for" window, cooldown, and fire/resolve transitions. It is not
// persisted: on restart alerts re-evaluate from current conditions (history in
// the DB is retained).
type alertRuntime struct {
	pendingSince time.Time // zero when the condition is not currently breached
	firing       bool
	alertID      string    // id of the current firing alert row
	lastNotified time.Time
	lastValue    float64
	lastAlert    Alert // most recent firing copy, reused to broadcast resolution
}

// state returns (creating if needed) the runtime for a key. All map access is
// guarded so the scheduler tick and scan-time CVE evaluation can run concurrently.
func (s *Server) state(key string) *alertRuntime {
	s.alertMu.Lock()
	defer s.alertMu.Unlock()
	st := s.alertState[key]
	if st == nil {
		st = &alertRuntime{}
		s.alertState[key] = st
	}
	return st
}

func (s *Server) loadRules() []AlertRule {
	rules, err := s.db.ListAlertRules()
	if err != nil {
		log.Printf("alerts: list rules: %v", err)
		return nil
	}
	return rules
}

func (s *Server) loadChannels() []AlertChannel {
	chans, err := s.db.ListAlertChannels()
	if err != nil {
		log.Printf("alerts: list channels: %v", err)
		return nil
	}
	return chans
}

// startAlertScheduler ticks the evaluator. It runs unconditionally; each tick
// is a no-op when there are no enabled rules.
func (s *Server) startAlertScheduler(ctx context.Context) {
	interval := s.cfg.AlertInterval
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runAlertTick(ctx)
		}
	}
}

func (s *Server) runAlertTick(ctx context.Context) {
	var enabled []AlertRule
	for _, r := range s.loadRules() {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	if len(enabled) == 0 {
		return
	}
	channels := s.loadChannels()
	now := time.Now().UTC()
	s.evaluateHostRules(enabled, channels, now)
	s.evaluateContainerRules(enabled, channels, ctx, now)
	s.evaluateOfflineRules(enabled, channels, ctx, now)
}

// ── Host thresholds ──────────────────────────────────────────────────────────

func metricValue(metric string, m collector.HostMetrics) (float64, bool) {
	switch metric {
	case "cpu":
		return m.CPUPercent, true
	case "mem":
		return m.MemPercent, true
	case "disk":
		return m.DiskUsedPct, true
	case "swap":
		return m.SwapPercent, true
	case "load1":
		return m.Load1, true
	default:
		return 0, false
	}
}

func isBreach(op string, val, thr float64) bool {
	if op == "<" {
		return val < thr
	}
	return val > thr
}

func (s *Server) evaluateHostRules(rules []AlertRule, channels []AlertChannel, now time.Time) {
	m := s.hc.Latest()
	for _, r := range rules {
		if r.Type != "host" {
			continue
		}
		val, ok := metricValue(r.Metric, m)
		if !ok {
			continue
		}
		key := r.ID + "|" + s.cfg.LocalHostID
		st := s.state(key)
		if isBreach(r.Op, val, r.Threshold) {
			if st.pendingSince.IsZero() {
				st.pendingSince = now
			}
			forDur := time.Duration(r.ForSeconds) * time.Second
			if !st.firing && now.Sub(st.pendingSince) >= forDur {
				op := r.Op
				if op == "" {
					op = ">"
				}
				summary := fmt.Sprintf("%s: %s %s %.1f (threshold %s %.1f)", r.Name, r.Metric, op, val, op, r.Threshold)
				s.fire(r, channels, st, s.cfg.LocalHostID, r.Metric, val, r.Threshold, summary, "")
			}
		} else {
			st.pendingSince = time.Time{}
			if st.firing {
				s.resolve(r, st, now)
			}
		}
	}
}

// ── Container exit / OOM ───────────────────────────────────────────────────────

func kindMatched(kinds []string, kind string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}

func (s *Server) evaluateContainerRules(rules []AlertRule, channels []AlertChannel, ctx context.Context, now time.Time) {
	if s.dc == nil {
		return
	}
	list, err := s.dc.ListContainers(ctx, "")
	if err != nil {
		log.Printf("alerts: list containers: %v", err)
		return
	}
	newStates := make(map[string]string, len(list))
	for _, c := range list {
		newStates[c.ID] = c.State
	}

	// Health is only known via inspect, so we pay that cost just when a rule
	// asks for it. Running containers only; exited ones are handled as exits.
	needHealth := false
	for _, r := range rules {
		if r.Type == "container" && kindMatched(r.EventKinds, "unhealthy") {
			needHealth = true
			break
		}
	}
	health := map[string]string{}
	if needHealth {
		for _, c := range list {
			if c.State != "running" {
				continue
			}
			if meta, err := s.dc.InspectContainer(ctx, c.ID); err == nil {
				health[c.ID] = meta.HealthStatus
			}
		}
	}

	for _, r := range rules {
		if r.Type != "container" {
			continue
		}
		for _, c := range list {
			key := r.ID + "|" + c.Name
			st := s.state(key)
			prev := s.lastContainerState[c.ID]
			if prev == "running" && (c.State == "exited" || c.State == "dead") && !st.firing {
				if kindMatched(r.EventKinds, "exit") || kindMatched(r.EventKinds, "oom") {
					s.fireContainerExit(r, channels, st, ctx, c)
				}
			} else if c.State == "running" && st.firing {
				s.resolve(r, st, now)
			}
		}
		// Unhealthy (healthcheck) transitions, tracked under a distinct key.
		if kindMatched(r.EventKinds, "unhealthy") {
			for _, c := range list {
				if c.State != "running" {
					continue
				}
				h := health[c.ID]
				if h == "" {
					continue // no healthcheck configured
				}
				ukey := r.ID + "|unhealthy|" + c.Name
				ust := s.state(ukey)
				if h == "unhealthy" && !ust.firing {
					s.fire(r, channels, ust, c.Name, "", 0, 0,
						fmt.Sprintf("%s: container %s is unhealthy", r.Name, c.Name), "")
				} else if h == "healthy" && ust.firing {
					s.resolve(r, ust, now)
				}
			}
		}
	}
	s.lastContainerState = newStates
}

// fireContainerExit inspects the container for OOM/exit-code context and fires
// a single exit/OOM alert.
func (s *Server) fireContainerExit(r AlertRule, channels []AlertChannel, st *alertRuntime, ctx context.Context, c collector.ContainerInfo) {
	oom := false
	detail := fmt.Sprintf("Container %s exited (state: %s)", c.Name, c.State)
	if meta, err := s.dc.InspectContainer(ctx, c.ID); err == nil {
		oom = meta.OOMKilled
		if oom {
			detail = fmt.Sprintf("Container %s was OOM-killed", c.Name)
		} else {
			detail = fmt.Sprintf("Container %s exited with code %d", c.Name, meta.ExitCode)
		}
	}
	kind := "exit"
	if oom {
		kind = "oom"
	}
	// Only notify when the rule actually enables this specific kind.
	if !kindMatched(r.EventKinds, kind) {
		return
	}
	s.fire(r, channels, st, c.Name, "", 0, 0, fmt.Sprintf("%s: container %s %s", r.Name, c.Name, kind), detail)
}

// ── Host / agent offline ──────────────────────────────────────────────────────

// evaluateOfflineRules fires when the local Docker daemon is unreachable or a
// previously-connected agent has dropped, after the rule's "for" grace window.
func (s *Server) evaluateOfflineRules(rules []AlertRule, channels []AlertChannel, ctx context.Context, now time.Time) {
	var off []AlertRule
	for _, r := range rules {
		if r.Type == "offline" {
			off = append(off, r)
		}
	}
	if len(off) == 0 {
		return
	}

	down := map[string]string{} // host id -> display name
	if err := s.dc.Ping(ctx); err != nil {
		down[s.cfg.LocalHostID] = displayName(s.cfg.LocalHostName)
	}
	for _, h := range s.agents.AllHosts() {
		if !h.Online {
			down[h.ID] = displayName(h.Name)
		}
	}

	for _, r := range off {
		for id, name := range down {
			key := r.ID + "|" + id
			st := s.state(key)
			if st.pendingSince.IsZero() {
				st.pendingSince = now
			}
			forDur := time.Duration(r.ForSeconds) * time.Second
			if !st.firing && now.Sub(st.pendingSince) >= forDur {
				s.fire(r, channels, st, id, "", 0, 0,
					fmt.Sprintf("%s: %s is offline", r.Name, name), "")
			}
		}
		// Resolve any host under this rule that is no longer down.
		prefix := r.ID + "|"
		var back []string
		s.alertMu.Lock()
		for key, st := range s.alertState {
			if !strings.HasPrefix(key, prefix) || !st.firing {
				continue
			}
			if _, stillDown := down[strings.TrimPrefix(key, prefix)]; !stillDown {
				back = append(back, key)
			}
		}
		s.alertMu.Unlock()
		for _, key := range back {
			s.resolve(r, s.state(key), now)
		}
	}
}

// displayName falls back to a generic label when a name is empty.
func displayName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "host"
	}
	return name
}

// ── CVE rules (evaluated at scan completion) ───────────────────────────────────

func (s *Server) evaluateScan(res collector.ImageVulnScan) {
	var rules []AlertRule
	for _, r := range s.loadRules() {
		if r.Enabled && r.Type == "cve" {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return
	}
	channels := s.loadChannels()
	now := time.Now().UTC()
	for _, r := range rules {
		sev := strings.ToUpper(r.MinSeverity)
		if sev == "" {
			sev = "CRITICAL"
		}
		count := res.Counts[sev]
		thr := r.CountThreshold
		if thr < 1 {
			thr = 1
		}
		key := r.ID + "|" + res.Ref
		st := s.state(key)
		if count >= thr && (!st.firing || float64(count) > st.lastValue) {
			summary := fmt.Sprintf("%s: %d %s finding(s) on %s", r.Name, count, sev, res.Ref)
			s.fire(r, channels, st, res.Ref, "", float64(count), float64(thr), summary, "")
		} else if count >= thr && st.firing {
			st.lastValue = float64(count) // keep the highest seen; no re-notify
		} else if count < thr && st.firing {
			s.resolve(r, st, now)
		}
	}
}

// ── Fire / resolve / dispatch ────────────────────────────────────────────────

func (s *Server) fire(r AlertRule, channels []AlertChannel, st *alertRuntime, resource, metric string, value, threshold float64, summary, detail string) {
	a := Alert{
		ID:        newID("alert"),
		RuleID:    r.ID,
		RuleName:  r.Name,
		Type:      r.Type,
		Severity:  r.Severity,
		Status:    "firing",
		Resource:  resource,
		Metric:    metric,
		Value:     value,
		Threshold: threshold,
		Summary:   summary,
		Detail:    detail,
		StartedAt: time.Now().UTC(),
	}
	st.firing = true
	st.alertID = a.ID
	st.lastNotified = a.StartedAt
	st.lastValue = value
	st.lastAlert = a

	alert := a // capture for the queued write
	s.db.QueueWrite(func() error { return s.db.SaveAlert(alert) })
	s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgAlert, a) // live toast
	s.dispatch(r, a, channels)
}

func (s *Server) resolve(r AlertRule, st *alertRuntime, now time.Time) {
	if st.alertID != "" {
		id := st.alertID
		at := now
		s.db.QueueWrite(func() error { return s.db.ResolveAlert(id, at) })
		resolved := st.lastAlert
		resolved.Status = "resolved"
		resolved.ResolvedAt = &now
		s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgAlert, resolved) // live toast
	}
	st.firing = false
	st.alertID = ""
	st.pendingSince = time.Time{}
	st.lastValue = 0
	st.lastAlert = Alert{}
}

// deliveryResult is the per-channel outcome recorded in Alert.Notified.
type deliveryResult struct {
	Status   string `json:"status"` // ok | error
	Attempts int    `json:"attempts"`
	Error    string `json:"error,omitempty"`
}

// sendWithRetry tries a channel up to len(delays) times with backoff, so a
// transient network blip doesn't drop a notification.
func (s *Server) sendWithRetry(c AlertChannel, a Alert) deliveryResult {
	delays := []time.Duration{0, 2 * time.Second, 5 * time.Second}
	var lastErr error
	for i, d := range delays {
		if d > 0 {
			time.Sleep(d)
		}
		if err := s.notifier.Send(c, a); err == nil {
			return deliveryResult{Status: "ok", Attempts: i + 1}
		}
		lastErr = err
		log.Printf("alerts: notify %s (%s) attempt %d: %v", c.Name, c.Kind, i+1, err)
	}
	msg := ""
	if lastErr != nil {
		msg = lastErr.Error()
	}
	return deliveryResult{Status: "error", Attempts: len(delays), Error: msg}
}

// dispatch sends the alert to the rule's target channels (all enabled when the
// rule specifies none) in a goroutine, then records per-channel results.
func (s *Server) dispatch(r AlertRule, a Alert, channels []AlertChannel) {
	want := map[string]bool{}
	for _, id := range r.ChannelIDs {
		want[id] = true
	}
	var targets []AlertChannel
	for _, c := range channels {
		if !c.Enabled {
			continue
		}
		if len(want) == 0 || want[c.ID] {
			targets = append(targets, c)
		}
	}
	if len(targets) == 0 {
		return
	}
	go func() {
		results := map[string]deliveryResult{}
		for _, c := range targets {
			results[c.Name] = s.sendWithRetry(c, a)
		}
		b, _ := json.Marshal(results)
		a.Notified = string(b)
		s.db.QueueWrite(func() error { return s.db.SaveAlert(a) })
		// Re-broadcast so an open UI can show delivery without polling.
		s.hub.BroadcastJSONWithHost(s.cfg.LocalHostID, MsgAlert, a)
	}()
}

// ── Seed ─────────────────────────────────────────────────────────────────────

// seedAlertDefaults inserts a set of disabled example rules on first run so the
// Alerts tab is not empty. Safe to call every start; a no-op once rules exist.
func (s *Server) seedAlertDefaults() {
	rules, err := s.db.ListAlertRules()
	if err != nil || len(rules) > 0 {
		return
	}
	for _, r := range defaultAlertRules() {
		rr := r
		if err := s.db.UpsertAlertRule(rr); err != nil {
			log.Printf("alerts: seed rule %q: %v", r.Name, err)
		}
	}
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func (s *Server) handleListAlertRules(w http.ResponseWriter, _ *http.Request) {
	rules, err := s.db.ListAlertRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if rules == nil {
		rules = []AlertRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleSaveAlertRule(w http.ResponseWriter, r *http.Request) {
	var rule AlertRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(rule.Name) == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	if rule.ID == "" {
		rule.ID = newID("rule")
	}
	if rule.Severity == "" {
		rule.Severity = "warning"
	}
	if err := s.db.UpsertAlertRule(rule); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleDeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	if err := s.db.DeleteAlertRule(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAlertChannels(w http.ResponseWriter, _ *http.Request) {
	chans, err := s.db.ListAlertChannels()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if chans == nil {
		chans = []AlertChannel{}
	}
	writeJSON(w, http.StatusOK, chans)
}

func (s *Server) handleSaveAlertChannel(w http.ResponseWriter, r *http.Request) {
	var ch AlertChannel
	if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(ch.Name) == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	switch ch.Kind {
	case "webhook", "slack":
		if ch.URL == "" {
			writeError(w, http.StatusBadRequest, errors.New("URL is required for webhook/slack channels"))
			return
		}
	case "email":
		if ch.To == "" {
			writeError(w, http.StatusBadRequest, errors.New("recipient is required for email channels"))
			return
		}
	default:
		writeError(w, http.StatusBadRequest, errors.New("kind must be webhook, slack, or email"))
		return
	}
	if ch.ID == "" {
		ch.ID = newID("chan")
	}
	if err := s.db.UpsertAlertChannel(ch); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

func (s *Server) handleDeleteAlertChannel(w http.ResponseWriter, r *http.Request) {
	if err := s.db.DeleteAlertChannel(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	alerts, err := s.db.ListAlerts(status, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleActiveAlerts(w http.ResponseWriter, _ *http.Request) {
	alerts, err := s.db.ListActiveAlerts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

// handleTestAlert sends a sample alert to one channel so the user can verify
// delivery without waiting for a real breach.
func (s *Server) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChannelID string `json:"channel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var ch *AlertChannel
	for _, c := range s.loadChannels() {
		if c.ID == body.ChannelID {
			cc := c
			ch = &cc
			break
		}
	}
	if ch == nil {
		writeError(w, http.StatusNotFound, errors.New("channel not found"))
		return
	}
	test := Alert{
		ID:        newID("alert"),
		RuleName:  "Test alert",
		Type:      "test",
		Severity:  "info",
		Status:    "firing",
		Resource:  s.cfg.LocalHostID,
		Summary:   "This is a test alert from System Monitor",
		StartedAt: time.Now().UTC(),
	}
	if err := s.notifier.Send(*ch, test); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── SMTP settings (UI-managed, encrypted at rest) ──────────────────────────────

// smtpPayload is the wire form for GET/POST /alerts/smtp. Password is accepted
// on write and never returned; HasPassword indicates whether a secret is stored.
type smtpPayload struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	From        string `json:"from"`
	User        string `json:"user"`
	Password    string `json:"password,omitempty"`
	HasPassword bool   `json:"has_password"`
	Source      string `json:"source,omitempty"`
}

func (s *Server) handleGetSMTP(w http.ResponseWriter, _ *http.Request) {
	st, err := s.loadSMTP()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, smtpPayload{
		Host: st.Host, Port: st.Port, From: st.From, User: st.User,
		HasPassword: st.HasPassword, Source: st.Source,
	})
}

func (s *Server) handleSaveSMTP(w http.ResponseWriter, r *http.Request) {
	var in smtpPayload
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if in.Port == 0 {
		in.Port = 587
	}
	if err := s.saveSMTP(SMTPSettings{
		Host: strings.TrimSpace(in.Host), Port: in.Port,
		From: strings.TrimSpace(in.From), User: strings.TrimSpace(in.User),
		Password: in.Password, // "" keeps existing; " " clears
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	st, _ := s.loadSMTP()
	writeJSON(w, http.StatusOK, smtpPayload{
		Host: st.Host, Port: st.Port, From: st.From, User: st.User,
		HasPassword: st.HasPassword, Source: st.Source,
	})
}

// handleTestSMTP sends a one-off test email to the address in the body, using
// the currently-effective SMTP settings (so it validates what's saved).
func (s *Server) handleTestSMTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.To) == "" {
		writeError(w, http.StatusBadRequest, errors.New("'to' recipient is required"))
		return
	}
	ch := AlertChannel{ID: "test", Name: "SMTP test", Kind: "email", Enabled: true, To: strings.TrimSpace(body.To)}
	test := Alert{
		ID: newID("alert"), RuleName: "Test alert", Type: "test", Severity: "info",
		Status: "firing", Resource: s.cfg.LocalHostID,
		Summary:   "This is a test email from System Monitor",
		StartedAt: time.Now().UTC(),
	}
	if err := s.notifier.Send(ch, test); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── Acknowledge / manual resolve ─────────────────────────────────────────────

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Note string `json:"note"`
	}
	// Body is optional (an ack with no note); ignore decode errors on empty/absent JSON.
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.db.AckAlert(id, strings.TrimSpace(body.Note), time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.db.ResolveAlert(id, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
