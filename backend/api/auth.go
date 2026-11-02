package api

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

var (
	errActionsDisabled = errors.New("actions disabled (no admin token configured)")
	errUnauthorized    = errors.New("missing or invalid admin token")
)

// bearerToken extracts the token from an "Authorization: Bearer <t>" header.
func bearerToken(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
}

// requireAdmin gates every mutating endpoint. When no admin token is configured
// the actions are disabled outright (403); otherwise a matching bearer token is
// required (401). Constant-time compare avoids token timing leaks.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			writeError(w, http.StatusForbidden, errActionsDisabled)
			return
		}
		got := bearerToken(r)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AdminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		next(w, r)
	}
}
