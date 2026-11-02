package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/monitoring/backend/collector"
)

var errDockerUnavailable = errors.New("Docker unavailable")

// ResourceProvider is the read+action surface the REST handlers need. It is
// satisfied locally by *collector.DockerClient and remotely by agentProxy, so
// a handler can serve the local daemon or a remote agent unchanged.
type ResourceProvider interface {
	ListContainers(ctx context.Context, state string) ([]collector.ContainerInfo, error)
	InspectContainer(ctx context.Context, id string) (collector.ContainerInfo, error)
	TopProcesses(ctx context.Context, id string) (collector.ContainerProcess, error)
	InspectRaw(ctx context.Context, id string) (json.RawMessage, error)
	CgroupStats(ctx context.Context, id string) (collector.ContainerCgroupStats, error)
	SystemUsage(ctx context.Context) (collector.DiskUsageSummary, error)
	NetworkTopology(ctx context.Context) (collector.Topology, error)
	ListVolumes(ctx context.Context, withSize bool) ([]collector.VolumeInfo, error)
	ListImages(ctx context.Context) ([]collector.ImageInfo, error)
	ImageLayers(ctx context.Context, ref string) ([]string, error)
	PullImage(ctx context.Context, ref string) (string, error)
	PruneDanglingImages(ctx context.Context) (int64, error)
	PruneAllImages(ctx context.Context) (int64, error)
	RemoveImage(ctx context.Context, ref string, force bool) error
	ContainerAction(ctx context.Context, id, op string, force bool) error
	RemoveVolume(ctx context.Context, name string, force bool) error
	ScanImage(ctx context.Context, ref string, opts collector.ScanOptions) (collector.ImageVulnScan, error)
	SecurityPosture(ctx context.Context) ([]collector.ContainerSecurity, error)
}

var (
	_ ResourceProvider = (*collector.DockerClient)(nil)
	_ ResourceProvider = (*agentProxy)(nil)
)

const defaultRPCTimeout = 15 * time.Second

// defaultScanTimeout bounds a remote Trivy scan RPC. Image scans pull a DB and
// walk every layer, so they can run for minutes; keep it generous.
const defaultScanTimeout = 10 * time.Minute

// agentProxy turns ResourceProvider calls into hub->agent RPCs.
type agentProxy struct {
	reg  *AgentRegistry
	host string
}

// call performs an RPC and unmarshals the response into out (may be nil).
func (p *agentProxy) call(ctx context.Context, action string, args, out any, timeout time.Duration) error {
	data, err := p.reg.Request(ctx, p.host, action, args, timeout)
	if err != nil {
		return err
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (p *agentProxy) ListContainers(ctx context.Context, state string) ([]collector.ContainerInfo, error) {
	var out []collector.ContainerInfo
	err := p.call(ctx, ActContainersList, ArgState{State: state}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) InspectContainer(ctx context.Context, id string) (collector.ContainerInfo, error) {
	var out collector.ContainerInfo
	err := p.call(ctx, ActContainerInspectOne, ArgID{ID: id}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) TopProcesses(ctx context.Context, id string) (collector.ContainerProcess, error) {
	var out collector.ContainerProcess
	err := p.call(ctx, ActContainerTop, ArgID{ID: id}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) InspectRaw(ctx context.Context, id string) (json.RawMessage, error) {
	return p.reg.Request(ctx, p.host, ActContainerInsp, ArgID{ID: id}, defaultRPCTimeout)
}

func (p *agentProxy) CgroupStats(ctx context.Context, id string) (collector.ContainerCgroupStats, error) {
	var out collector.ContainerCgroupStats
	err := p.call(ctx, ActCgroupStats, ArgID{ID: id}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) SystemUsage(ctx context.Context) (collector.DiskUsageSummary, error) {
	var out collector.DiskUsageSummary
	err := p.call(ctx, ActSystemDF, struct{}{}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) NetworkTopology(ctx context.Context) (collector.Topology, error) {
	var out collector.Topology
	err := p.call(ctx, ActTopology, struct{}{}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) ListVolumes(ctx context.Context, withSize bool) ([]collector.VolumeInfo, error) {
	var out []collector.VolumeInfo
	err := p.call(ctx, ActVolumesList, ArgVolumesList{WithSize: withSize}, &out, 60*time.Second)
	return out, err
}

func (p *agentProxy) ListImages(ctx context.Context) ([]collector.ImageInfo, error) {
	var out []collector.ImageInfo
	err := p.call(ctx, ActImagesList, struct{}{}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) ImageLayers(ctx context.Context, ref string) ([]string, error) {
	var out []string
	err := p.call(ctx, ActImageLayers, ArgRef{Ref: ref}, &out, defaultRPCTimeout)
	return out, err
}

func (p *agentProxy) PullImage(ctx context.Context, ref string) (string, error) {
	var out string
	err := p.call(ctx, ActImagePull, ArgRef{Ref: ref}, &out, 10*time.Minute)
	return out, err
}

func (p *agentProxy) PruneDanglingImages(ctx context.Context) (int64, error) {
	var out int64
	err := p.call(ctx, ActImagePrune, struct{}{}, &out, 2*time.Minute)
	return out, err
}

func (p *agentProxy) PruneAllImages(ctx context.Context) (int64, error) {
	var out int64
	err := p.call(ctx, ActImagePruneAll, struct{}{}, &out, 2*time.Minute)
	return out, err
}

func (p *agentProxy) RemoveImage(ctx context.Context, ref string, force bool) error {
	return p.call(ctx, ActImageDelete, ArgRefForce{Ref: ref, Force: force}, nil, defaultRPCTimeout)
}

func (p *agentProxy) ContainerAction(ctx context.Context, id, op string, force bool) error {
	return p.call(ctx, ActContainerAct, ArgContainerAction{ID: id, Op: op, Force: force}, nil, defaultRPCTimeout)
}

func (p *agentProxy) RemoveVolume(ctx context.Context, name string, force bool) error {
	return p.call(ctx, ActVolumeRemove, ArgVolumeRemove{Name: name, Force: force}, nil, defaultRPCTimeout)
}

func (p *agentProxy) ScanImage(ctx context.Context, ref string, opts collector.ScanOptions) (collector.ImageVulnScan, error) {
	var out collector.ImageVulnScan
	err := p.call(ctx, ActImageScan, ArgImageScan{Ref: ref, Opts: opts}, &out, defaultScanTimeout)
	return out, err
}

func (p *agentProxy) SecurityPosture(ctx context.Context) ([]collector.ContainerSecurity, error) {
	var out []collector.ContainerSecurity
	err := p.call(ctx, ActSecurityPosture, struct{}{}, &out, defaultScanTimeout)
	return out, err
}

// providerFor resolves the target provider for a request from its ?host= query
// parameter: empty or the local id uses the hub's own Docker client, otherwise
// it proxies to the named online agent.
func (s *Server) providerFor(r *http.Request) (ResourceProvider, error) {
	host := r.URL.Query().Get("host")
	if host == "" || host == s.cfg.LocalHostID {
		if s.dc == nil {
			return nil, errDockerUnavailable
		}
		return s.dc, nil
	}
	if !s.agents.Online(host) {
		return nil, errors.New("host " + host + " is offline")
	}
	return &agentProxy{reg: s.agents, host: host}, nil
}
