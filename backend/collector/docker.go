// Package collector provides Docker Engine SDK integration for the
// cross-platform monitoring backend. It auto-detects the host OS at runtime
// and connects via the appropriate transport:
//
//	Linux:   unix:///var/run/docker.sock
//	Windows: npipe:////./pipe/docker_engine
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// DockerClient wraps the official Docker SDK client with metadata about the
// transport endpoint in use.
type DockerClient struct {
	CLI      *client.Client
	Endpoint string // resolved host string actually used
	OS       string // "linux" | "windows" | "darwin"
}

// NewDockerClient builds a platform-aware Docker SDK client.
//
// Transport selection rules (see §2 of general.md):
//   - Linux / macOS → unix:///var/run/docker.sock
//   - Windows       → npipe:////./pipe/docker_engine
//
// An optional dockerHost override (e.g. from DOCKER_HOST env var) always
// takes precedence.
func NewDockerClient(dockerHost string) (*DockerClient, error) {
	var opts []client.Opt

	// Version negotiation + default env-based options (respects DOCKER_HOST).
	opts = append(opts, client.FromEnv, client.WithAPIVersionNegotiation())

	if dockerHost != "" {
		opts = append(opts, client.WithHost(dockerHost))
	} else {
		host := DefaultEndpoint()
		opts = append(opts, client.WithHost(host))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("collector: failed to create Docker client: %w", err)
	}

	// Verify connectivity immediately so callers fail fast.
	ctx := context.Background()
	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("collector: Docker ping failed at %s: %w", cli.DaemonHost(), err)
	}

	return &DockerClient{
		CLI:      cli,
		Endpoint: cli.DaemonHost(),
		OS:       runtime.GOOS,
	}, nil
}

// Ping reports whether the Docker daemon is reachable. Used by offline alerts
// to detect a down local daemon (nil receiver = client never initialised).
func (dc *DockerClient) Ping(ctx context.Context) error {
	if dc == nil || dc.CLI == nil {
		return fmt.Errorf("collector: no docker client")
	}
	_, err := dc.CLI.Ping(ctx)
	return err
}

// DefaultEndpoint returns the platform-correct Docker socket URI per
// the compatibility rules in general.md §2.
func DefaultEndpoint() string {
	const (
		linuxSocket   = "unix:///var/run/docker.sock"
		windowsPipe   = "npipe:////./pipe/docker_engine"
		defaultSocket = linuxSocket // macOS uses the same Unix socket path
	)

	switch runtime.GOOS {
	case "windows":
		return windowsPipe
	case "darwin":
		// Docker Desktop for macOS exposes the socket at the Linux path.
		return defaultSocket
	default: // linux, freebsd, …
		return linuxSocket
	}
}

// ContainerInfo holds a normalised, UI-friendly subset of Docker's container
// metadata.
type ContainerInfo struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Image           string         `json:"image"`
	State           string         `json:"state"`
	Status          string         `json:"status"`
	Created         int64          `json:"created"` // Unix timestamp
	SizeRwBytes     int64          `json:"size_rw_bytes"`     // writable layer size
	SizeRootFsBytes int64          `json:"size_rootfs_bytes"` // total image + writable layer

	// ── Tier 2 additions ───────────────────────────────────────────────────
	RestartCount int              `json:"restart_count"`
	OOMKilled    bool             `json:"oom_killed"`
	HealthStatus string           `json:"health_status"` // "healthy" | "unhealthy" | "starting" | ""
	ExitCode     int              `json:"exit_code"`
	Ports        []ContainerPort  `json:"ports,omitempty"`
}

// ContainerPort represents a single port mapping.
type ContainerPort struct {
	IP          string `json:"ip"`
	PrivatePort uint16 `json:"private_port"`
	PublicPort  uint16 `json:"public_port"`
	Type        string `json:"type"` // "tcp" | "udp"
}

// ListContainers returns all containers whose State matches stateFilter.
// Pass "running" for only active containers, "" for every container regardless
// of state, or any Docker state string: "created", "exited", "paused", etc.
//
// Example usage:
//
//	containers, err := dc.ListContainers(context.Background(), "running")
func (dc *DockerClient) ListContainers(ctx context.Context, stateFilter string) ([]ContainerInfo, error) {
	filterMap := map[string][]string{}
	if stateFilter != "" {
		filterMap["status"] = []string{stateFilter}
	}

	// All=true is required to surface containers that are not running.
	// When stateFilter is "running" the status filter narrows the result set
	// further, so All can safely remain true.
	listOpts := container.ListOptions{
		All:     true,
		Filters: newContainerFilter(filterMap),
	}

	summaries, err := dc.CLI.ContainerList(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("collector: ContainerList failed: %w", err)
	}

	result := make([]ContainerInfo, 0, len(summaries))
	for _, s := range summaries {
		name := ""
		if len(s.Names) > 0 {
			// Docker prefixes container names with "/"; strip it.
			name = s.Names[0]
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}

		// Map ports from summary
		var ports []ContainerPort
		for _, p := range s.Ports {
			ports = append(ports, ContainerPort{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			})
		}

		result = append(result, ContainerInfo{
			ID:      s.ID[:12], // short ID
			Name:    name,
			Image:   s.Image,
			State:   string(s.State),
			Status:  s.Status,
			Created: s.Created,
			Ports:   ports,
		})
	}

	return result, nil
}

// Close releases the underlying HTTP/pipe connection.
func (dc *DockerClient) Close() error {
	return dc.CLI.Close()
}

// GetContainerSize returns the writable layer size and total filesystem size
// for a container. This calls Docker inspect with size=true, which is more
// expensive than a normal inspect, so use sparingly.
func (dc *DockerClient) GetContainerSize(ctx context.Context, containerID string) (sizeRw, sizeRootFs int64, err error) {
	resp, _, err := dc.CLI.ContainerInspectWithRaw(ctx, containerID, true)
	if err != nil {
		return 0, 0, fmt.Errorf("collector: ContainerInspectWithRaw(%s): %w", containerID, err)
	}
	if resp.ContainerJSONBase == nil {
		return 0, 0, nil
	}
	if resp.SizeRw != nil {
		sizeRw = *resp.SizeRw
	}
	if resp.SizeRootFs != nil {
		sizeRootFs = *resp.SizeRootFs
	}
	return sizeRw, sizeRootFs, nil
}

// InspectContainer returns enriched metadata for a container including
// restart count, OOM status, health, exit code, and filesystem size.
func (dc *DockerClient) InspectContainer(ctx context.Context, containerID string) (ContainerInfo, error) {
	resp, _, err := dc.CLI.ContainerInspectWithRaw(ctx, containerID, true)
	if err != nil {
		return ContainerInfo{}, fmt.Errorf("collector: InspectContainer(%s): %w", containerID, err)
	}

	info := ContainerInfo{
		ID: containerID,
	}

	if resp.ContainerJSONBase != nil {
		info.Name = strings.TrimPrefix(resp.Name, "/")
		info.RestartCount = resp.RestartCount
		if resp.SizeRw != nil {
			info.SizeRwBytes = *resp.SizeRw
		}
		if resp.SizeRootFs != nil {
			info.SizeRootFsBytes = *resp.SizeRootFs
		}
		if resp.State != nil {
			info.State = string(resp.State.Status)
			info.OOMKilled = resp.State.OOMKilled
			info.ExitCode = resp.State.ExitCode
			if resp.State.Health != nil {
				info.HealthStatus = string(resp.State.Health.Status)
			}
		}
	}

	return info, nil
}

// ── Phase 2 Batch 2: inspect raw JSON, top processes, system df ──────────────

// InspectRaw returns the untouched `docker inspect` JSON document for a
// container so the UI can render the full config without modelling every field.
func (dc *DockerClient) InspectRaw(ctx context.Context, containerID string) (json.RawMessage, error) {
	_, raw, err := dc.CLI.ContainerInspectWithRaw(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("collector: InspectRaw(%s): %w", containerID, err)
	}
	return json.RawMessage(raw), nil
}

// ContainerProcess mirrors the `docker top` response: column titles plus one
// row of strings per running process.
type ContainerProcess struct {
	Titles    []string   `json:"titles"`
	Processes [][]string `json:"processes"`
}

// TopProcesses returns the process list for a container. It fails for stopped
// containers, which the caller surfaces as an error message.
func (dc *DockerClient) TopProcesses(ctx context.Context, containerID string) (ContainerProcess, error) {
	resp, err := dc.CLI.ContainerTop(ctx, containerID, []string{"aux"})
	if err != nil {
		return ContainerProcess{}, fmt.Errorf("collector: ContainerTop(%s): %w", containerID, err)
	}
	return ContainerProcess{Titles: resp.Titles, Processes: resp.Processes}, nil
}

// DiskUsageSummary is a normalised, UI-friendly view of `docker system df`.
type DiskUsageSummary struct {
	ImagesCount               int   `json:"images_count"`
	ImagesTotalBytes          int64 `json:"images_total_bytes"`
	ContainersCount           int   `json:"containers_count"`
	ContainersRwBytes         int64 `json:"containers_rw_bytes"`
	VolumesCount              int   `json:"volumes_count"`
	VolumesTotalBytes         int64 `json:"volumes_total_bytes"`
	BuildCacheCount           int   `json:"build_cache_count"`
	BuildCacheTotalBytes      int64 `json:"build_cache_total_bytes"`
	BuildCacheReclaimableBytes int64 `json:"build_cache_reclaimable_bytes"`
}

// SystemUsage aggregates disk usage across images, containers, volumes and the
// build cache. Volume/container byte totals are best-effort: the daemon only
// populates them when it reports sizes, but counts and image/build-cache sizes
// are always accurate.
func (dc *DockerClient) SystemUsage(ctx context.Context) (DiskUsageSummary, error) {
	du, err := dc.CLI.DiskUsage(ctx, types.DiskUsageOptions{})
	if err != nil {
		return DiskUsageSummary{}, fmt.Errorf("collector: DiskUsage: %w", err)
	}

	var s DiskUsageSummary
	s.ImagesCount = len(du.Images)
	for _, img := range du.Images {
		s.ImagesTotalBytes += img.Size
	}
	s.ContainersCount = len(du.Containers)
	for _, c := range du.Containers {
		s.ContainersRwBytes += c.SizeRw
	}
	s.VolumesCount = len(du.Volumes)
	// Volume byte totals are not exposed by this SDK version's volume.Volume
	// type (the daemon only reports size with an opt-in flag the DiskUsage
	// client does not set here), so only the volume count is reported.
	s.BuildCacheCount = len(du.BuildCache)
	for _, bc := range du.BuildCache {
		if bc == nil {
			continue
		}
		s.BuildCacheTotalBytes += bc.Size
		if !bc.InUse && !bc.Shared {
			s.BuildCacheReclaimableBytes += bc.Size
		}
	}
	return s, nil
}
