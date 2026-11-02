package collector

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
)

// ─────────────────────────────────────────────────────────────────────────────
// Network topology
// ─────────────────────────────────────────────────────────────────────────────

// TopologyNode is a graph vertex: either a container or a Docker network.
type TopologyNode struct {
	ID     string `json:"id"`
	Type   string `json:"type"` // "container" | "network"
	Label  string `json:"label"`
	State  string `json:"state,omitempty"`
	Driver string `json:"driver,omitempty"`
}

// TopologyEdge connects a container node to the network node it is attached to.
type TopologyEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// Topology is a bipartite container<->network graph — the connections the
// Docker API actually exposes (shared networks), not live traffic flows.
type Topology struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}

// NetworkTopology builds the container/network graph. Empty built-in networks
// are omitted so the map stays readable.
func (dc *DockerClient) NetworkTopology(ctx context.Context) (Topology, error) {
	nets, err := dc.CLI.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return Topology{}, fmt.Errorf("collector: NetworkList: %w", err)
	}

	var topo Topology
	nodeSeen := map[string]bool{}
	edgeSeen := map[string]bool{}

	for _, n := range nets {
		insp, err := dc.CLI.NetworkInspect(ctx, n.ID, network.InspectOptions{})
		if err != nil {
			continue // best-effort: skip networks we cannot inspect
		}
		if len(insp.Containers) == 0 {
			continue // drop unused bridge/host/none noise
		}

		netID := "n:" + n.Name
		nodeSeen[netID] = true
		topo.Nodes = append(topo.Nodes, TopologyNode{
			ID: netID, Type: "network", Label: n.Name, Driver: n.Driver,
		})

		for _, ep := range insp.Containers {
			name := ep.Name
			if name == "" {
				name = truncate(ep.EndpointID, 12)
			}
			cID := "c:" + name
			if !nodeSeen[cID] {
				nodeSeen[cID] = true
				topo.Nodes = append(topo.Nodes, TopologyNode{
					ID: cID, Type: "container", Label: name,
				})
			}
			key := cID + "->" + netID
			if !edgeSeen[key] {
				edgeSeen[key] = true
				topo.Edges = append(topo.Edges, TopologyEdge{Source: cID, Target: netID})
			}
		}
	}
	return topo, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Volumes
// ─────────────────────────────────────────────────────────────────────────────

// VolumeInfo mirrors a Docker volume plus optional best-effort size and usage.
type VolumeInfo struct {
	Name         string            `json:"name"`
	Driver       string            `json:"driver"`
	Mountpoint   string            `json:"mountpoint"`
	Scope        string            `json:"scope"`
	Labels       map[string]string `json:"labels,omitempty"`
	SizeBytes    int64             `json:"size_bytes"`
	SizeComputed bool              `json:"size_computed"`
	UsedBy       []string          `json:"used_by,omitempty"`
}

// ListVolumes returns all volumes. When withSize is true it also walks each
// mountpoint to sum bytes and inspects every container to find usage — both
// are comparatively expensive, so they stay opt-in.
func (dc *DockerClient) ListVolumes(ctx context.Context, withSize bool) ([]VolumeInfo, error) {
	resp, err := dc.CLI.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("collector: VolumeList: %w", err)
	}

	var users map[string][]string
	if withSize {
		users = dc.volumeUsers(ctx)
	}

	out := make([]VolumeInfo, 0, len(resp.Volumes))
	for _, v := range resp.Volumes {
		if v == nil {
			continue
		}
		info := VolumeInfo{
			Name:       v.Name,
			Driver:     v.Driver,
			Mountpoint: v.Mountpoint,
			Scope:      v.Scope,
			Labels:     v.Labels,
			UsedBy:     users[v.Name],
		}
		if withSize && v.Mountpoint != "" {
			if size, ok := dirSize(v.Mountpoint); ok {
				info.SizeBytes = size
				info.SizeComputed = true
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// volumeUsers maps volume name -> container names that mount it (best-effort).
func (dc *DockerClient) volumeUsers(ctx context.Context) map[string][]string {
	m := map[string][]string{}
	summaries, err := dc.CLI.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return m
	}
	for _, s := range summaries {
		insp, _, err := dc.CLI.ContainerInspectWithRaw(ctx, s.ID, false)
		if err != nil || insp.ContainerJSONBase == nil {
			continue
		}
		name := strings.TrimPrefix(insp.Name, "/")
		for _, mt := range insp.Mounts {
			if string(mt.Type) == "volume" && mt.Name != "" {
				m[mt.Name] = append(m[mt.Name], name)
			}
		}
	}
	return m
}

// dirSize sums regular-file bytes under root. Returns ok=false when the tree
// is unreadable (e.g. permissions or missing mountpoint).
func dirSize(root string) (int64, bool) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // tolerate individual entry errors, keep walking
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // do not follow links
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, false
	}
	return total, true
}

// ─────────────────────────────────────────────────────────────────────────────
// Images
// ─────────────────────────────────────────────────────────────────────────────

// ImageInfo mirrors a Docker image summary for the UI table.
type ImageInfo struct {
	ID               string   `json:"id"`
	RepoTags         []string `json:"repo_tags"`
	Created          int64    `json:"created"`
	SizeBytes        int64    `json:"size_bytes"`
	VirtualSizeBytes int64    `json:"virtual_size_bytes"`
}

// ListImages returns all local images (including untagged/dangling).
func (dc *DockerClient) ListImages(ctx context.Context) ([]ImageInfo, error) {
	sums, err := dc.CLI.ImageList(ctx, image.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("collector: ImageList: %w", err)
	}
	out := make([]ImageInfo, 0, len(sums))
	for _, s := range sums {
		out = append(out, ImageInfo{
			ID:               s.ID,
			RepoTags:         s.RepoTags,
			Created:          s.Created,
			SizeBytes:        s.Size,
			VirtualSizeBytes: s.VirtualSize,
		})
	}
	return out, nil
}

// ImageLayers returns the ordered root filesystem layer diff IDs for an image.
func (dc *DockerClient) ImageLayers(ctx context.Context, ref string) ([]string, error) {
	insp, _, err := dc.CLI.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("collector: ImageInspectWithRaw(%s): %w", ref, err)
	}
	layers := make([]string, 0, len(insp.RootFS.Layers))
	for _, l := range insp.RootFS.Layers {
		layers = append(layers, l)
	}
	return layers, nil
}

// PullImage pulls ref and blocks until complete (the pull only proceeds while
// the response stream is drained). Returns the last status line from the stream.
func (dc *DockerClient) PullImage(ctx context.Context, ref string) (string, error) {
	rc, err := dc.CLI.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return "", fmt.Errorf("collector: ImagePull(%s): %w", ref, err)
	}
	defer rc.Close() //nolint:errcheck

	body, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("collector: ImagePull drain: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	return lines[len(lines)-1], nil
}

// PruneDanglingImages removes only untagged/dangling images and returns the
// number of bytes reclaimed.
func (dc *DockerClient) PruneDanglingImages(ctx context.Context) (int64, error) {
	rep, err := dc.CLI.ImagesPrune(ctx, filters.NewArgs(filters.Arg("dangling", "true")))
	if err != nil {
		return 0, fmt.Errorf("collector: ImagesPrune: %w", err)
	}
	return int64(rep.SpaceReclaimed), nil
}

// truncate returns the first n runes of s (or s if shorter).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
