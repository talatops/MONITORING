package collector

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
)

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: control actions (lifecycle + deletes). Every method here is invoked
// only behind the admin-token middleware (local) or an authenticated command
// relay (remote agent), so the destructive operations are guarded upstream.
// ─────────────────────────────────────────────────────────────────────────────

// ContainerAction performs a lifecycle op: "start" | "stop" | "restart" | "remove".
// force only applies to "remove" (and also drops the container's anonymous volumes).
func (dc *DockerClient) ContainerAction(ctx context.Context, id, op string, force bool) error {
	var err error
	switch op {
	case "start":
		err = dc.CLI.ContainerStart(ctx, id, container.StartOptions{})
	case "stop":
		err = dc.CLI.ContainerStop(ctx, id, container.StopOptions{})
	case "restart":
		err = dc.CLI.ContainerRestart(ctx, id, container.StopOptions{})
	case "remove":
		err = dc.CLI.ContainerRemove(ctx, id, container.RemoveOptions{Force: force, RemoveVolumes: true})
	default:
		return fmt.Errorf("collector: ContainerAction(%s): unknown op %q", id, op)
	}
	if err != nil {
		return fmt.Errorf("collector: ContainerAction(%s,%s): %w", id, op, err)
	}
	return nil
}

// RemoveVolume deletes a named volume; force detaches it from running containers.
func (dc *DockerClient) RemoveVolume(ctx context.Context, name string, force bool) error {
	if err := dc.CLI.VolumeRemove(ctx, name, force); err != nil {
		return fmt.Errorf("collector: VolumeRemove(%s): %w", name, err)
	}
	return nil
}

// RemoveImage deletes a specific image (by ref or ID); force removes it even
// when tagged/used.
func (dc *DockerClient) RemoveImage(ctx context.Context, ref string, force bool) error {
	if _, err := dc.CLI.ImageRemove(ctx, ref, image.RemoveOptions{Force: force, PruneChildren: true}); err != nil {
		return fmt.Errorf("collector: ImageRemove(%s): %w", ref, err)
	}
	return nil
}

// PruneAllImages removes ALL unused images (not just dangling) and returns the
// number of bytes reclaimed.
func (dc *DockerClient) PruneAllImages(ctx context.Context) (int64, error) {
	rep, err := dc.CLI.ImagesPrune(ctx, filters.NewArgs(filters.Arg("all", "true")))
	if err != nil {
		return 0, fmt.Errorf("collector: ImagesPrune(all): %w", err)
	}
	return int64(rep.SpaceReclaimed), nil
}
