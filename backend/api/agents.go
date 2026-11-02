package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	errAgentOffline = errors.New("agent offline")
	errAgentTimeout = errors.New("agent request timed out")
)

// AgentConn is the hub's handle to one connected agent. It owns the WebSocket,
// a write pump fed via `send`, and a pending-request table so REST handlers can
// issue synchronous RPC ("command" -> "response") to a remote host.
type AgentConn struct {
	hostID string
	name   string
	os     string
	numCPU int

	conn *websocket.Conn
	send chan []byte
	hub  *Hub

	mu      sync.Mutex
	pending map[string]chan AgentFrame
	closed  bool
	closeCh chan struct{}
	once    sync.Once
}

func newAgentConn(hostID string, conn *websocket.Conn, hub *Hub) *AgentConn {
	return &AgentConn{
		hostID:  hostID,
		conn:    conn,
		hub:     hub,
		send:    make(chan []byte, 256),
		pending: map[string]chan AgentFrame{},
		closeCh: make(chan struct{}),
	}
}

// writePump drains the send channel to the socket until ctx is cancelled or a
// write fails (which also unblocks request() via closeCh in shutdown()).
func (a *AgentConn) writePump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-a.send:
			a.conn.SetWriteDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
			if err := a.conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		}
	}
}

// readPump consumes agent frames: events are relayed to the browser hub, and
// responses are routed to their waiting request(). Returns on any read error.
func (a *AgentConn) readPump() {
	defer a.shutdown()
	a.conn.SetReadLimit(8 << 20) // 8 MiB for large inspect/topology payloads
	for {
		_, msg, err := a.conn.ReadMessage()
		if err != nil {
			return
		}
		var f AgentFrame
		if json.Unmarshal(msg, &f) != nil {
			continue
		}
		switch f.Type {
		case "event":
			if f.Event != nil {
				a.hub.BroadcastJSONWithHost(a.hostID, f.Event.Type, f.Event.Data)
			}
		case "response":
			a.deliver(f)
		}
	}
}

func (a *AgentConn) deliver(f AgentFrame) {
	a.mu.Lock()
	ch := a.pending[f.ReqID]
	delete(a.pending, f.ReqID)
	a.mu.Unlock()
	if ch != nil {
		select {
		case ch <- f:
		default:
		}
	}
}

// shutdown closes the socket and fails every in-flight request exactly once.
func (a *AgentConn) shutdown() {
	a.once.Do(func() {
		close(a.closeCh)
		a.mu.Lock()
		a.closed = true
		for id, ch := range a.pending {
			close(ch)
			delete(a.pending, id)
		}
		a.mu.Unlock()
		a.conn.Close() //nolint:errcheck
	})
}

// request issues a command and blocks for the matching response.
func (a *AgentConn) request(ctx context.Context, reqID, action string, args any, timeout time.Duration) (json.RawMessage, error) {
	payload, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}

	respCh := make(chan AgentFrame, 1)
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, errAgentOffline
	}
	a.pending[reqID] = respCh
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, reqID)
		a.mu.Unlock()
	}()

	frame, err := json.Marshal(AgentFrame{Type: "command", ReqID: reqID, Action: action, Args: payload})
	if err != nil {
		return nil, err
	}
	select {
	case a.send <- frame:
	case <-a.closeCh:
		return nil, errAgentOffline
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case f, ok := <-respCh:
		if !ok {
			return nil, errAgentOffline
		}
		if !f.OK {
			return nil, errors.New(f.Error)
		}
		return f.Data, nil
	case <-timer.C:
		return nil, errAgentTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.closeCh:
		return nil, errAgentOffline
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────────────────────────────────────

// AgentRegistry tracks connected agents by host id and provides the RPC entry
// point used by agentProxy. Safe for concurrent use.
type AgentRegistry struct {
	mu    sync.RWMutex
	conns map[string]*AgentConn
	seq   uint64
}

func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{conns: map[string]*AgentConn{}}
}

func (rg *AgentRegistry) add(a *AgentConn) {
	rg.mu.Lock()
	if old, ok := rg.conns[a.hostID]; ok && old != a {
		old.shutdown() // replace a stale conn for the same host id
	}
	rg.conns[a.hostID] = a
	rg.mu.Unlock()
	log.Printf("api: agent registered host=%s name=%s", a.hostID, a.name)
}

func (rg *AgentRegistry) remove(a *AgentConn) {
	rg.mu.Lock()
	// Only delete if the currently stored conn is this one: a reconnecting
	// agent may already have replaced us under the same host id, and we must
	// not evict the fresh conn.
	if cur, ok := rg.conns[a.hostID]; ok && cur == a {
		delete(rg.conns, a.hostID)
	}
	rg.mu.Unlock()
	log.Printf("api: agent disconnected host=%s", a.hostID)
}

func (rg *AgentRegistry) Online(hostID string) bool {
	rg.mu.RLock()
	_, ok := rg.conns[hostID]
	rg.mu.RUnlock()
	return ok
}

func (rg *AgentRegistry) List() []HostInfo {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	out := make([]HostInfo, 0, len(rg.conns))
	for id, a := range rg.conns {
		out = append(out, HostInfo{ID: id, Name: a.name, Kind: "agent", Online: true, OS: a.os, NumCPU: a.numCPU})
	}
	return out
}

// Request sends a command to the named host and waits for its response.
func (rg *AgentRegistry) Request(ctx context.Context, hostID, action string, args any, timeout time.Duration) (json.RawMessage, error) {
	rg.mu.RLock()
	a := rg.conns[hostID]
	rg.mu.RUnlock()
	if a == nil {
		return nil, fmt.Errorf("host %q is offline", hostID)
	}
	rg.mu.Lock()
	rg.seq++
	reqID := fmt.Sprintf("%d-%s", rg.seq, action)
	rg.mu.Unlock()
	return a.request(ctx, reqID, action, args, timeout)
}
