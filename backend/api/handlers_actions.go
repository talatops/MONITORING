package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// actionTimeout bounds how long a local or remote mutating operation may run
// before the handler gives up. Remove/restart can take a moment on a busy host.
const actionTimeout = 30 * time.Second

// ─────────────────────────────────────────────────────────────────────────────
// Host listing
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/v1/hosts — the local host plus every currently connected agent.
// The local entry is always reported (even if Docker is down) so the UI always
// has a selectable host.
func (s *Server) handleHosts(w http.ResponseWriter, _ *http.Request) {
	out := make([]HostInfo, 0, 1+len(s.agents.List()))
	out = append(out, HostInfo{
		ID:     s.cfg.LocalHostID,
		Name:   s.cfg.LocalHostName,
		Kind:   "local",
		Online: true,
	})
	out = append(out, s.agents.List()...)
	writeJSON(w, http.StatusOK, out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent connection (hub side of the multi-host WebSocket)
// ─────────────────────────────────────────────────────────────────────────────

// GET /ws/agent — an agent connects here and keeps a single multiplexed socket
// for the life of the process. The enrollment token is checked on the HTTP
// upgrade request (Authorization: Bearer). The first frame must be a "register"
// declaring the agent's host id; afterwards the connection is added to the
// registry so REST handlers can proxy reads/actions to it and its event frames
// are relayed to browser clients.
func (s *Server) handleAgentStream(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EnrollToken == "" {
		writeError(w, http.StatusForbidden, errors.New("agent access disabled (no enroll token configured)"))
		return
	}
	got := bearerToken(r)
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.EnrollToken)) != 1 {
		writeError(w, http.StatusUnauthorized, errors.New("invalid enroll token"))
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("api: agent upgrade: %v", err)
		return
	}

	// Expect the register frame within a short window; agents send it right
	// after connecting. Clear the deadline once we have it.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	_, msg, err := conn.ReadMessage()
	if err != nil {
		conn.Close() //nolint:errcheck
		return
	}
	var reg AgentFrame
	if err := json.Unmarshal(msg, &reg); err != nil || reg.Type != "register" || reg.HostID == "" {
		conn.WriteMessage(websocket.CloseMessage, //nolint:errcheck
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "expected register frame"))
		conn.Close() //nolint:errcheck
		return
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	a := newAgentConn(reg.HostID, conn, s.hub)
	a.name = reg.Name
	a.os = reg.OS
	a.numCPU = reg.NumCPU

	s.agents.add(a)

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go a.writePump(ctx)
	a.readPump() // blocks until the socket dies
	s.agents.remove(a)
}

// ─────────────────────────────────────────────────────────────────────────────
// Action endpoints (all wrapped in requireAdmin at route registration)
// ─────────────────────────────────────────────────────────────────────────────

// boolQuery reports whether ?<key>= is present and truthy (1|true).
func boolQuery(r *http.Request, key string) bool {
	v := r.URL.Query().Get(key)
	return v == "1" || v == "true"
}

// POST /api/v1/containers/{id}/action?op=start|stop|restart|remove&force=&host=
func (s *Server) handleContainerAction(w http.ResponseWriter, r *http.Request) {
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
	op := r.URL.Query().Get("op")
	switch op {
	case "start", "stop", "restart", "remove":
	default:
		writeError(w, http.StatusBadRequest, errors.New("op must be start|stop|restart|remove"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), actionTimeout)
	defer cancel()
	if err := prov.ContainerAction(ctx, id, op, boolQuery(r, "force")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "id": id, "op": op})
}

// DELETE /api/v1/volumes/{name}?force=&host=
func (s *Server) handleVolumeDelete(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, errors.New("volume name is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), actionTimeout)
	defer cancel()
	if err := prov.RemoveVolume(ctx, name, boolQuery(r, "force")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "name": name})
}

// DELETE /api/v1/images?ref=&force=&host= — ref via query to survive tag slashes.
func (s *Server) handleImageDelete(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, errors.New("ref is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), actionTimeout)
	defer cancel()
	if err := prov.RemoveImage(ctx, ref, boolQuery(r, "force")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "ref": ref})
}

// POST /api/v1/images/pruneAll?host= — remove all unused images (not just dangling).
func (s *Server) handleImagePruneAll(w http.ResponseWriter, r *http.Request) {
	prov, err := s.providerFor(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	reclaimed, err := prov.PruneAllImages(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"space_reclaimed_bytes": reclaimed})
}
