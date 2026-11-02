//go:build !linux

package collector

import "context"

// CgroupStats is only meaningful on Linux (cgroup v2). On other platforms it
// returns ErrNotSupported so the API layer can answer 501 and the UI hides the
// Cgroup tab.
func (dc *DockerClient) CgroupStats(_ context.Context, _ string) (ContainerCgroupStats, error) {
	return ContainerCgroupStats{}, ErrNotSupported
}
