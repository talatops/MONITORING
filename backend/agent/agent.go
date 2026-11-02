// Package agent implements the remote monitoring agent described in Phase 4:
// a single process that talks to its LOCAL Docker daemon and host counters,
// pushes live events to the central hub over one WebSocket, and executes
// hub-issued read/action commands against the local collectors.
//
// It is built into the same `monitor` binary as the server and selected with
// `-mode=agent`. The agent holds no SQLite state (remote hosts are live-only).
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/gorilla/websocket"

	"github.com/monitoring/backend/api"
	"github.com/monitoring/backend/collector"
)

// Options configure one agent instance (populated from CLI flags in main).
type Options struct {
	HubURL       string // ws(s)://hub-host/ws/agent
	HostID       string // stable id reported in the register frame
	Name         string // display name
	EnrollToken  string // shared secret presented as Bearer on upgrade
	DockerHost   string // empty -> auto-detect local daemon
	PollInterval time.Duration
}

// Run connects to the hub and keeps a single logical session alive, reconnecting
// with exponential backoff until ctx is cancelled. It returns only when ctx is
// done (or the config is invalid).
func Run(ctx context.Context, opts Options) error {
	if opts.HostID == "" {
		return errors.New("agent: -host-id is required")
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = time.Second
	}

	// Local Docker client is optional: a host-metrics-only agent is valid.
	var dc *collector.DockerClient
	if c, err := collector.NewDockerClient(opts.DockerHost); err != nil {
		log.Printf("agent: WARNING Docker unavailable (%v) — host metrics only", err)
	} else {
		dc = c
		defer dc.Close()
		log.Printf("agent: Docker connected endpoint=%s os=%s", dc.Endpoint, dc.OS)
	}

	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		start := time.Now()
		err := runSession(ctx, opts, dc)
		if ctx.Err() != nil {
			return ctx.Err() // shutting down, not a real failure
		}
		// A long-lived session means the link was healthy: reset backoff so a
		// later blip reconnects quickly again.
		if time.Since(start) > 30*time.Second {
			backoff = 2 * time.Second
		}
		log.Printf("agent: session ended (%v) — reconnecting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// runSession owns one WebSocket connection and the collectors feeding it.
func runSession(ctx context.Context, opts Options, dc *collector.DockerClient) error {
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+opts.EnrollToken)

	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	conn, _, err := websocket.DefaultDialer.DialContext(dialCtx, opts.HubURL, hdr)
	if err != nil {
		return fmt.Errorf("agent: dial %s: %w", opts.HubURL, err)
	}
	defer conn.Close()

	// Per-connection context: cancelling it tears down collectors/streams when
	// the socket dies, so a reconnect starts from a clean slate.
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

	// All outbound frames (register, events, responses) funnel through one
	// channel consumed by a single writer, as gorilla forbids concurrent writes.
	send := make(chan []byte, 256)
	go writePump(conn, send, connCtx)

	// Register frame identifies this host to the hub.
	reg := api.AgentFrame{Type: "register", HostID: opts.HostID, Name: opts.Name, OS: runtime.GOOS}
	if b, err := json.Marshal(reg); err == nil {
		select {
		case send <- b:
		case <-connCtx.Done():
			return connCtx.Err()
		}
	}

	// Live host metrics, emitted as event frames.
	hc := collector.NewHostCollector(opts.PollInterval)
	hc.Start(connCtx)
	go func() {
		for m := range hc.Subscribe() {
			emit(send, connCtx, opts.HostID, api.MsgHostMetrics, m)
		}
	}()

	// Container stats fan out through a fresh aggregator each session.
	agg := collector.NewContainerStatsAggregator()
	defer agg.Close()
	go func() {
		for snap := range agg.Output() {
			emit(send, connCtx, opts.HostID, api.MsgContainerStats, snap)
		}
	}()

	if dc != nil {
		go discoverAndStream(connCtx, dc, agg, send, opts.HostID)
	}

	// Kernel/OOM events stream live, exactly like host metrics. The non-Linux
	// stub parks until connCtx ends, so this is safe on every agent host.
	go func() {
		kernelCh := make(chan collector.KernelEvent, 64)
		go collector.StreamKernelEvents(connCtx, kernelCh)
		for ev := range kernelCh {
			emit(send, connCtx, opts.HostID, api.MsgKernelEvent, ev)
		}
	}()

	// Command reader: blocks until the socket dies, then we reconnect.
	return readCommands(connCtx, conn, dc, send, opts.HostID)
}

// writePump serialises frames to the socket until ctx is cancelled or a write
// fails.
func writePump(conn *websocket.Conn, send <-chan []byte, ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-send:
			conn.SetWriteDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		}
	}
}

// emit marshals an event frame and does a context-aware send so a stalled
// connection never blocks a collector. Dropped frames are tolerable for live
// metrics (the next tick replaces them).
func emit(send chan<- []byte, ctx context.Context, hostID, msgType string, data any) {
	b, err := json.Marshal(api.AgentFrame{
		Type:   "event",
		HostID: hostID,
		Event:  &api.WSMessage{Type: msgType, Data: data},
	})
	if err != nil {
		return
	}
	select {
	case send <- b:
	case <-ctx.Done():
	}
}

// readCommands consumes hub->agent command frames and executes each against the
// local collectors in its own goroutine (so slow pulls don't stall the reader),
// returning when the socket errors or ctx is cancelled.
func readCommands(ctx context.Context, conn *websocket.Conn, dc *collector.DockerClient, send chan<- []byte, hostID string) error {
	conn.SetReadLimit(8 << 20) // 8 MiB for large inspect/topology/volume payloads
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var f api.AgentFrame
		if json.Unmarshal(msg, &f) != nil || f.Type != "command" {
			continue
		}
		go handleCommand(ctx, dc, f, send, hostID)
	}
}

func handleCommand(ctx context.Context, dc *collector.DockerClient, f api.AgentFrame, send chan<- []byte, hostID string) {
	data, err := executeCommand(ctx, dc, f.Action, f.Args)
	resp := api.AgentFrame{Type: "response", HostID: hostID, ReqID: f.ReqID}
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.OK = true
		resp.Data = data
	}
	b, merr := json.Marshal(resp)
	if merr != nil {
		return
	}
	select {
	case send <- b:
	case <-ctx.Done():
	}
}

var errNoDocker = errors.New("agent: Docker unavailable on this host")

// executeCommand maps a protocol action name to a local collector method and
// marshals its result for the response Data field. Action names come from the
// shared api.Act* constants so hub and agent can never drift.
func executeCommand(ctx context.Context, dc *collector.DockerClient, action string, args json.RawMessage) (json.RawMessage, error) {
	decode := func(v any) error { return json.Unmarshal(args, v) }

	// container.inspect returns raw inspect JSON (already encoded) and needs the
	// client too; handled first so it can pass the RawMessage straight through.
	if action == api.ActContainerInsp {
		var a api.ArgID
		if err := decode(&a); err != nil {
			return nil, err
		}
		if dc == nil {
			return nil, errNoDocker
		}
		return dc.InspectRaw(ctx, a.ID)
	}

	if dc == nil {
		return nil, errNoDocker
	}

	switch action {
	case api.ActContainersList:
		var a api.ArgState
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.ListContainers(ctx, a.State))
	case api.ActContainerInspectOne:
		var a api.ArgID
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.InspectContainer(ctx, a.ID))
	case api.ActContainerTop:
		var a api.ArgID
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.TopProcesses(ctx, a.ID))
	case api.ActCgroupStats:
		var a api.ArgID
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.CgroupStats(ctx, a.ID))
	case api.ActSystemDF:
		return marshal(dc.SystemUsage(ctx))
	case api.ActTopology:
		return marshal(dc.NetworkTopology(ctx))
	case api.ActVolumesList:
		var a api.ArgVolumesList
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.ListVolumes(ctx, a.WithSize))
	case api.ActImagesList:
		return marshal(dc.ListImages(ctx))
	case api.ActImageLayers:
		var a api.ArgRef
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.ImageLayers(ctx, a.Ref))
	case api.ActImagePull:
		var a api.ArgRef
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.PullImage(ctx, a.Ref))
	case api.ActImagePrune:
		return marshal(dc.PruneDanglingImages(ctx))
	case api.ActImagePruneAll:
		return marshal(dc.PruneAllImages(ctx))
	case api.ActImageDelete:
		var a api.ArgRefForce
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshalOK(dc.RemoveImage(ctx, a.Ref, a.Force))
	case api.ActContainerAct:
		var a api.ArgContainerAction
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshalOK(dc.ContainerAction(ctx, a.ID, a.Op, a.Force))
	case api.ActVolumeRemove:
		var a api.ArgVolumeRemove
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshalOK(dc.RemoveVolume(ctx, a.Name, a.Force))
	case api.ActImageScan:
		var a api.ArgImageScan
		if err := decode(&a); err != nil {
			return nil, err
		}
		return marshal(dc.ScanImage(ctx, a.Ref, a.Opts))
	case api.ActSecurityPosture:
		return marshal(dc.SecurityPosture(ctx))
	default:
		return nil, fmt.Errorf("agent: unknown action %q", action)
	}
}

// marshal encodes a (value, error) pair from a read method into the response
// Data field, propagating any error.
func marshal(v any, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	b, merr := json.Marshal(v)
	return b, merr
}

// marshalOK encodes an error-only action result: empty Data on success.
func marshalOK(err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// discoverAndStream mirrors the server's local streaming loop but emits events
// onto the hub connection instead of a WebSocket hub + SQLite. New containers
// are picked up every 30s; each gets a stats stream (fed to the aggregator) and
// a log stream.
func discoverAndStream(ctx context.Context, dc *collector.DockerClient, agg *collector.ContainerStatsAggregator, send chan<- []byte, hostID string) {
	streamed := map[string]struct{}{}
	tick(ctx, dc, agg, send, hostID, streamed)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick(ctx, dc, agg, send, hostID, streamed)
		}
	}
}

func tick(ctx context.Context, dc *collector.DockerClient, agg *collector.ContainerStatsAggregator, send chan<- []byte, hostID string, streamed map[string]struct{}) {
	containers, err := dc.ListContainers(ctx, "running")
	if err != nil {
		log.Printf("agent: ListContainers: %v", err)
		return
	}
	for i := range containers {
		if meta, err := dc.InspectContainer(ctx, containers[i].ID); err == nil {
			containers[i].SizeRwBytes = meta.SizeRwBytes
			containers[i].SizeRootFsBytes = meta.SizeRootFsBytes
			containers[i].RestartCount = meta.RestartCount
			containers[i].OOMKilled = meta.OOMKilled
			containers[i].HealthStatus = meta.HealthStatus
			containers[i].ExitCode = meta.ExitCode
		}
	}
	emit(send, ctx, hostID, api.MsgContainerList, containers)

	for _, c := range containers {
		if _, ok := streamed[c.ID]; ok {
			continue
		}
		streamed[c.ID] = struct{}{}

		statsCh, err := dc.StreamContainerStats(ctx, c.ID, c.Name)
		if err != nil {
			log.Printf("agent: StreamContainerStats(%s): %v", c.ID, err)
			delete(streamed, c.ID)
			continue
		}
		agg.AddStream(statsCh)

		logCh, err := dc.StreamContainerLogs(ctx, c.ID, collector.DefaultLogStreamOptions())
		if err != nil {
			log.Printf("agent: StreamContainerLogs(%s): %v", c.ID, err)
			continue
		}
		go func() {
			for entry := range logCh {
				emit(send, ctx, hostID, api.MsgContainerLog, entry)
			}
		}()
	}
}
