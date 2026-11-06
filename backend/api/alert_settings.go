package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// ─────────────────────────────────────────────────────────────────────────────
// Phase 8+: SMTP settings saved from the UI. The password is encrypted at rest
// with AES-256-GCM using a per-installation key file that lives next to the
// SQLite database (never in the DB itself). The key file is created on first
// use with mode 0600. The browser can set the password but never reads it back.
// ─────────────────────────────────────────────────────────────────────────────

const smtpSettingKey = "smtp"

// storedSMTP is the DB-persisted row. PassEnc is base64(nonce||ciphertext||tag);
// the plaintext password is never stored.
type storedSMTP struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	From    string `json:"from"`
	User    string `json:"user"`
	PassEnc string `json:"pass_enc,omitempty"`
}

// SMTPSettings is the in-memory plaintext view. Password is populated only for
// internal send operations and on save; GET handlers return the redacted form.
type SMTPSettings struct {
	Host        string
	Port        int
	From        string
	User        string
	Password    string
	HasPassword bool
	Source      string // "db" when a UI-saved row exists, "env" when using flags/env
}

// keyFilePath is the per-install location of the AES key, alongside the DB.
func (s *Server) secretKeyPath() string {
	if s.cfg.DBPath == "" || s.cfg.DBPath == ":memory:" {
		return "monitor.secret"
	}
	return filepath.Join(filepath.Dir(s.cfg.DBPath), "monitor.secret")
}

// secretKey loads (or first-run creates) the 32-byte AES-GCM key. The key is
// read fresh each call — SMTP saves/tests are rare, so caching it would add
// locking without measurable benefit. If the file can't be written we still
// return an in-memory key so the current session works (with a warning).
func (s *Server) secretKey() ([]byte, error) {
	path := s.secretKeyPath()
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("gen key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		log.Printf("alerts: could not persist SMTP key file %s: %v (session-only)", path, err)
	}
	return key, nil
}

func (s *Server) encryptSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	key, err := s.secretKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func (s *Server) decryptSecret(b64 string) (string, error) {
	if b64 == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	key, err := s.secretKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// loadSMTP returns the effective SMTP settings: the UI-saved row when present,
// otherwise the flag/env-derived Config values.
func (s *Server) loadSMTP() (SMTPSettings, error) {
	raw, found, err := s.db.GetSetting(smtpSettingKey)
	if err != nil {
		return SMTPSettings{}, err
	}
	if !found || raw == "" {
		return SMTPSettings{
			Host:        s.cfg.SMTPHost,
			Port:        s.cfg.SMTPPort,
			From:        s.cfg.SMTPFrom,
			User:        s.cfg.SMTPUser,
			Password:    s.cfg.SMTPPassword,
			HasPassword: s.cfg.SMTPPassword != "",
			Source:      "env",
		}, nil
	}
	var st storedSMTP
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return SMTPSettings{}, err
	}
	pass := ""
	if st.PassEnc != "" {
		p, derr := s.decryptSecret(st.PassEnc)
		if derr != nil {
			log.Printf("alerts: decrypt SMTP password failed (key changed?): %v", derr)
		}
		pass = p
	}
	return SMTPSettings{
		Host:        st.Host,
		Port:        st.Port,
		From:        st.From,
		User:        st.User,
		Password:    pass,
		HasPassword: st.PassEnc != "",
		Source:      "db",
	}, nil
}

// saveSMTP persists SMTP settings. An empty Password keeps the previously
// stored secret; a password of the sentinel " " clears it.
func (s *Server) saveSMTP(in SMTPSettings) error {
	var existing storedSMTP
	if raw, found, _ := s.db.GetSetting(smtpSettingKey); found && raw != "" {
		_ = json.Unmarshal([]byte(raw), &existing)
	}
	passEnc := existing.PassEnc
	switch in.Password {
	case "":
		// keep existing secret
	case " ":
		passEnc = "" // explicit clear
	default:
		e, err := s.encryptSecret(in.Password)
		if err != nil {
			return err
		}
		passEnc = e
	}
	st := storedSMTP{Host: in.Host, Port: in.Port, From: in.From, User: in.User, PassEnc: passEnc}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.db.SetSetting(smtpSettingKey, string(b))
}

// smtpConfig returns the base Config with SMTP fields overridden by any
// UI-saved settings. Used by the Notifier so email always reflects the latest
// configuration without restarting the server.
func (s *Server) smtpConfig() Config {
	c := s.cfg
	st, err := s.loadSMTP()
	if err != nil || st.Source != "db" {
		return c
	}
	c.SMTPHost = st.Host
	c.SMTPPort = st.Port
	c.SMTPFrom = st.From
	c.SMTPUser = st.User
	c.SMTPPassword = st.Password
	return c
}
