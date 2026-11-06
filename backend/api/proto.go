package api

import (
	"encoding/json"

	"github.com/monitoring/backend/collector"
)

// ─────────────────────────────────────────────────────────────────────────────
// Hub <-> agent wire protocol (JSON frames over a single WebSocket).
// The agent opens one connection and multiplexes three message kinds on it:
//   - "event"    agent -> hub : a relayed WSMessage for a monitored host
//   - "command"  hub -> agent : an RPC request (read or action)
//   - "response" agent -> hub : the reply to a command, matched by ReqID
// The initial "register" frame identifies the agent to the hub.
// ─────────────────────────────────────────────────────────────────────────────

// HostInfo describes a monitored host surfaced in the UI host selector.
type HostInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"` // "local" | "agent"
	Online bool   `json:"online"`
	OS     string `json:"os,omitempty"`
	NumCPU int    `json:"num_cpu,omitempty"`
}

// AgentFrame is the single envelope for every hub<->agent message.
type AgentFrame struct {
	Type   string          `json:"type"` // register|event|command|response
	HostID string          `json:"host_id,omitempty"`
	Name   string          `json:"name,omitempty"`
	OS     string          `json:"os,omitempty"`
	NumCPU int             `json:"num_cpu,omitempty"`
	Event  *WSMessage      `json:"event,omitempty"`
	ReqID  string          `json:"req_id,omitempty"`
	Action string          `json:"action,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	OK     bool            `json:"ok,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Action names understood by the agent command executor. Exported so the
// hub-side proxy (provider.go) and the agent executor (agent package) share one
// source of truth and can never drift.
const (
	ActContainersList      = "containers.list"
	ActContainerInspectOne = "container.inspectOne"
	ActContainerTop        = "container.top"
	ActContainerInsp       = "container.inspect"
	ActCgroupStats         = "container.cgroup"
	ActSystemDF            = "system.df"
	ActTopology            = "topology"
	ActVolumesList         = "volumes.list"
	ActImagesList          = "images.list"
	ActImageLayers         = "image.layers"
	ActImagePull           = "image.pull"
	ActImagePrune          = "image.prune"
	ActImagePruneAll       = "image.pruneAll"
	ActImageDelete         = "image.delete"
	ActContainerAct        = "container.action"
	ActVolumeRemove        = "volume.remove"
	ActImageScan           = "image.scan"
	ActImageSBOM           = "image.sbom"
	ActSecurityPosture     = "security.posture"
)

// Command argument payloads, shared verbatim by the hub-side proxy (marshal)
// and the agent-side executor (unmarshal) so the JSON keys can never drift.
type (
	ArgState struct {
		State string `json:"state"`
	}
	ArgID struct {
		ID string `json:"id"`
	}
	ArgRef struct {
		Ref string `json:"ref"`
	}
	ArgVolumesList struct {
		WithSize bool `json:"with_size"`
	}
	ArgRefForce struct {
		Ref   string `json:"ref"`
		Force bool   `json:"force"`
	}
	ArgContainerAction struct {
		ID    string `json:"id"`
		Op    string `json:"op"`
		Force bool   `json:"force"`
	}
	ArgVolumeRemove struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	ArgImageScan struct {
		Ref  string                `json:"ref"`
		Opts collector.ScanOptions `json:"opts"`
	}
	ArgImageSBOM struct {
		Ref  string                `json:"ref"`
		Opts collector.SBOMOptions `json:"opts"`
	}
)

// SBOMResult is the agent->hub payload for an SBOM export: the raw CycloneDX/
// SPDX document plus the suggested download filename.
type SBOMResult struct {
	Doc  json.RawMessage `json:"doc"`
	Name string          `json:"name"`
}
