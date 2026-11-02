package collector

import "time"

// KernelEvent is a single classified kernel-log line surfaced in the live
// "Kernel Events" panel (Phase 5). Category and Severity are derived by
// classifying the raw message; ContainerID is a best-effort correlation when the
// message names a Docker container/cgroup. JSON tags are snake_case for the
// WS wire format.
type KernelEvent struct {
	Ts          time.Time `json:"ts"`
	Category    string    `json:"category"` // oom_kill|ext4_error|thermal|segfault|hung_task|soft_lockup|fs_readonly|other
	Severity    string    `json:"severity"` // crit|warn|info
	Message     string    `json:"message"`
	Source      string    `json:"source"` // journald|kmsg|dmesg
	ContainerID string    `json:"container_id,omitempty"`
}
