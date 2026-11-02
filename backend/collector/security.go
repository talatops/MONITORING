package collector

import (
	"context"
	"strings"
)

// SecurityPosture returns the live security posture of every container on this
// host. It lists all containers (any state) and inspects each one's HostConfig
// for privileged/capability/namespace settings; a container whose inspect fails
// is skipped (best-effort, mirroring volumeUsers). HostID/HostName are left
// empty here — the API layer stamps them per provider when aggregating the fleet.
func (dc *DockerClient) SecurityPosture(ctx context.Context) ([]ContainerSecurity, error) {
	containers, err := dc.ListContainers(ctx, "")
	if err != nil {
		return nil, err
	}

	out := make([]ContainerSecurity, 0, len(containers))
	for _, c := range containers {
		resp, _, err := dc.CLI.ContainerInspectWithRaw(ctx, c.ID, false)
		if err != nil || resp.ContainerJSONBase == nil {
			continue // tolerate per-container inspect failures
		}

		cs := ContainerSecurity{
			ContainerID:  c.ID,
			Name:         c.Name,
			Image:        c.Image,
			ExposedPorts: c.Ports,
		}
		if hc := resp.HostConfig; hc != nil {
			cs.Privileged = hc.Privileged
			cs.HostNetwork = string(hc.NetworkMode) == "host"
			cs.HostPid = string(hc.PidMode) == "host"
			cs.ReadonlyRootfs = hc.ReadonlyRootfs
			// CapAdd is a slice of a named string type across SDK versions;
			// element-wise string() conversion compiles regardless.
			for _, c := range hc.CapAdd {
				if s := strings.ToUpper(string(c)); s != "" {
					cs.CapAdd = append(cs.CapAdd, s)
				}
			}
		}
		if resp.Config != nil {
			cs.User = resp.Config.User
			cs.Root = isRootUser(resp.Config.User)
		}
		out = append(out, cs)
	}
	return out, nil
}

// isRootUser reports whether a container User string resolves to uid 0. Docker
// leaves it empty when the image's USER is root, and accepts "root", "0", or
// "0:0" (uid:gid) forms.
func isRootUser(user string) bool {
	switch {
	case user == "",
		user == "0",
		user == "root",
		strings.HasPrefix(user, "0:"),
		strings.HasPrefix(user, "root:"):
		return true
	default:
		return false
	}
}
