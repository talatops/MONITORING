package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/monitoring/backend/collector"
)

// Notifier delivers alerts to configured channels. It uses only the standard
// library (net/http for webhook/Slack, net/smtp for email) so the CGO-free
// static build is unaffected. SMTP credentials are resolved on every email send
// via smtpFn (UI-saved settings override flags/env), so a config change takes
// effect without restarting the server.
type Notifier struct {
	client   *http.Client
	fallback Config            // flag/env-derived, used when smtpFn is nil
	smtpFn   func() Config     // returns the effective (possibly DB-backed) config
}

func NewNotifier(fallback Config, smtpFn func() Config) *Notifier {
	return &Notifier{client: &http.Client{Timeout: 10 * time.Second}, fallback: fallback, smtpFn: smtpFn}
}

// smtp returns the current effective SMTP configuration.
func (n *Notifier) smtp() Config {
	if n.smtpFn == nil {
		return n.fallback
	}
	return n.smtpFn()
}

// Send delivers one alert to a single channel, returning an error on failure.
func (n *Notifier) Send(ch collector.AlertChannel, a collector.Alert) error {
	switch ch.Kind {
	case "webhook":
		return n.sendWebhook(ch.URL, a)
	case "slack":
		return n.sendSlack(ch.URL, a)
	case "email":
		return n.sendEmail(ch.To, a)
	default:
		return fmt.Errorf("unknown channel kind %q", ch.Kind)
	}
}

// alertText renders a compact human-readable one-liner for the alert.
func alertText(a collector.Alert) string {
	if a.Metric != "" && a.Threshold != 0 {
		return fmt.Sprintf("%s — %s: %s (%.1f %s %.1f)", a.Status, a.Severity, a.Summary, a.Value, cmpOp(a), a.Threshold)
	}
	return fmt.Sprintf("%s — %s: %s", a.Status, a.Severity, a.Summary)
}

// cmpOp returns the comparison operator for the alert, defaulting to ">".
func cmpOp(a collector.Alert) string {
	if a.Threshold != 0 && a.Value < a.Threshold {
		return "<"
	}
	return ">"
}

func (n *Notifier) postJSON(url string, payload interface{}) error {
	if url == "" {
		return fmt.Errorf("channel URL is empty")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendWebhook(url string, a collector.Alert) error {
	return n.postJSON(url, map[string]interface{}{
		"rule":       a.RuleName,
		"type":       a.Type,
		"severity":   a.Severity,
		"status":     a.Status,
		"resource":   a.Resource,
		"metric":     a.Metric,
		"value":      a.Value,
		"threshold":  a.Threshold,
		"summary":    a.Summary,
		"detail":     a.Detail,
		"started_at": a.StartedAt,
		"text":       alertText(a),
	})
}

func (n *Notifier) sendSlack(url string, a collector.Alert) error {
	return n.postJSON(url, map[string]string{"text": fmt.Sprintf("*%s*", alertText(a))})
}

func (n *Notifier) sendEmail(to string, a collector.Alert) error {
	cfg := n.smtp()
	if cfg.SMTPHost == "" {
		return fmt.Errorf("SMTP not configured (save it in the Alerts tab or set -smtp-host)")
	}
	if to == "" {
		return fmt.Errorf("email channel has no recipient")
	}
	subject := fmt.Sprintf("[monitoring %s] %s", strings.ToUpper(a.Status), a.Summary)
	msgBody := alertText(a)
	if a.Detail != "" {
		msgBody += "\n\n" + a.Detail
	}
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = "monitoring@localhost"
	}

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPHost)
	}
	recipients := strings.Split(to, ",")
	for i := range recipients {
		recipients[i] = strings.TrimSpace(recipients[i])
	}

	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		cfg.SMTPFrom, to, subject, msgBody))

	// Port 465 is implicit TLS; everything else uses STARTTLS via smtp.SendMail.
	if cfg.SMTPPort == 465 {
		return n.sendEmailTLS(cfg, addr, auth, recipients, msg)
	}
	return smtp.SendMail(addr, auth, cfg.SMTPFrom, recipients, msg)
}

func (n *Notifier) sendEmailTLS(cfg Config, addr string, auth smtp.Auth, recipients []string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer c.Quit()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(cfg.SMTPFrom); err != nil {
		return err
	}
	for _, rcpt := range recipients {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}
