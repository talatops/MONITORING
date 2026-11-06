// Package api exposes the HTTP REST and WebSocket layers described in
// general.md §Module E. It bridges the collectors (host metrics, Docker
// stats, container logs) to connected browser clients through a fan-out Hub.
package api

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSMessage is the JSON envelope sent to every WebSocket client on each push.
// Clients filter on the Type field to route incoming data to the correct UI
// widget (gauges, log panel, container cards, …).
type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
	// Host identifies which monitored host produced this message. Empty is
	// treated as the hub's own (local) host by clients; relayed agent events
	// carry the agent's host id so the UI can filter by selected host.
	Host string `json:"host,omitempty"`
}

// Message type constants emitted by the hub.
const (
	MsgHostMetrics    = "host_metrics"
	MsgContainerStats = "container_stats"
	MsgContainerLog   = "container_log"
	MsgContainerList  = "container_list"
	MsgKernelEvent    = "kernel_event"
	MsgAlert          = "alert" // Phase 8: firing/resolved alert pushed live to the UI
)

// ─────────────────────────────────────────────────────────────────────────────
// Client
// ─────────────────────────────────────────────────────────────────────────────

// client wraps a single WebSocket connection owned by the Hub.
type client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	closed sync.Once
}

// close terminates the write pump and unregisters from the hub.
func (c *client) close() {
	c.closed.Do(func() {
		close(c.send)
		c.conn.Close() //nolint:errcheck
	})
}

// writePump pumps messages from the hub channel to the WebSocket connection.
// Runs in its own goroutine; exits when the send channel is closed or the
// connection encounters a write error.
func (c *client) writePump(ctx context.Context) {
	const (
		writeWait  = 10 * time.Second
		pongWait   = 60 * time.Second
		pingPeriod = (pongWait * 9) / 10
	)

	c.conn.SetReadDeadline(time.Now().Add(pongWait)) //nolint:errcheck
	c.conn.SetPongHandler(func(string) error {       //nolint:errcheck
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		select {
		case c.hub.unregister <- c:
		default:
			// Hub already exited — close directly.
			c.close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait)) //nolint:errcheck
			if !ok {
				// Hub closed the channel — graceful disconnect.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{}) //nolint:errcheck
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait)) //nolint:errcheck
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads incoming messages from the client (heartbeat / close frames).
// Runs in its own goroutine; signals the hub to unregister on exit.
func (c *client) readPump() {
	defer func() {
		select {
		case c.hub.unregister <- c:
		default:
			c.close()
		}
	}()

	c.conn.SetReadLimit(512) // clients don't send large payloads
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break // any read error (including close) exits the pump
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Hub
// ─────────────────────────────────────────────────────────────────────────────

// Hub is the central fan-out point for all real-time monitoring data.
// Collectors push typed messages via BroadcastJSON; every registered WebSocket
// client receives a marshalled copy.
//
// Hub is safe for concurrent use.
type Hub struct {
	mu         sync.RWMutex
	clients    map[*client]struct{}
	broadcast  chan []byte
	register   chan *client
	unregister chan *client
}

// NewHub returns an idle Hub. Call Run in a goroutine before broadcasting.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*client]struct{}),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *client, 64),
		unregister: make(chan *client, 64),
	}
}

// Run is the hub event loop. It exits when ctx is cancelled and disconnects
// all remaining clients.
func (h *Hub) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Shutdown: close every client send channel via sync.Once.
			h.mu.Lock()
			for c := range h.clients {
				delete(h.clients, c)
				c.close()
			}
			h.mu.Unlock()
			return

		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = struct{}{}
			h.mu.Unlock()

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				c.close() // sync.Once — safe even if readPump already closed it
			}
			h.mu.Unlock()

		case msg := <-h.broadcast:
			h.mu.RLock()
			slow := []*client{}
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					// Buffer full → mark for disconnect (handled after RUnlock).
					slow = append(slow, c)
				}
			}
			h.mu.RUnlock()

			// Disconnect slow clients without holding the read lock.
			for _, c := range slow {
				h.mu.Lock()
				if _, ok := h.clients[c]; ok {
					delete(h.clients, c)
					c.close() // sync.Once — safe
				}
				h.mu.Unlock()
			}
		}
	}
}

// BroadcastJSON marshals a WSMessage{Type, Data} and pushes it to all clients.
// Errors are logged but never propagated to callers (collectors should not
// block on WebSocket delivery).
func (h *Hub) BroadcastJSON(msgType string, data interface{}) {
	h.BroadcastJSONWithHost("", msgType, data)
}

// BroadcastJSONWithHost is BroadcastJSON with an explicit originating host id,
// used for the local host and for events relayed from remote agents.
func (h *Hub) BroadcastJSONWithHost(host, msgType string, data interface{}) {
	b, err := json.Marshal(WSMessage{Type: msgType, Data: data, Host: host})
	if err != nil {
		log.Printf("hub: marshal %s: %v", msgType, err)
		return
	}
	select {
	case h.broadcast <- b:
	default:
		// broadcast channel full — drop to avoid blocking collectors
	}
}

// ClientCount returns the current number of registered WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// newClient wraps a raw websocket.Conn and starts both pumps.
// Called by Server.handleWebSocket after a successful upgrade.
func (h *Hub) newClient(conn *websocket.Conn, ctx context.Context) *client {
	c := &client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}
	h.register <- c
	go c.writePump(ctx)
	go c.readPump()
	return c
}
