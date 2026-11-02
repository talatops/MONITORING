//go:build linux

package collector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cgroupRoot is the unified (v2) hierarchy mount point. Verified at resolve
// time by the `0::/` line in /proc/<pid>/cgroup.
const cgroupRoot = "/sys/fs/cgroup"

// errCgroupV1 signals the host is not running the unified v2 hierarchy, which
// is out of scope for this phase.
var errCgroupV1 = errors.New("collector: cgroup v1 detected (only v2 unified is supported)")

// CgroupStats reads per-container cgroup v2 accounting files. The container's
// cgroup directory is resolved via its init-process PID (works for both the
// systemd and cgroupfs drivers), so only running containers report data.
func (dc *DockerClient) CgroupStats(ctx context.Context, containerID string) (ContainerCgroupStats, error) {
	var out ContainerCgroupStats

	resp, _, err := dc.CLI.ContainerInspectWithRaw(ctx, containerID, false)
	if err != nil {
		return out, fmt.Errorf("collector: CgroupStats inspect(%s): %w", containerID, err)
	}
	if resp.State == nil || resp.State.Pid <= 0 {
		return out, fmt.Errorf("collector: CgroupStats(%s): container is not running", containerID)
	}

	rel, err := unifiedCgroupPath(resp.State.Pid)
	if err != nil {
		return out, err
	}
	dir := filepath.Join(cgroupRoot, rel)
	// Defence in depth: the resolved path must stay under the cgroup root even
	// though `rel` originates from the kernel's own /proc/<pid>/cgroup listing.
	if dir != cgroupRoot && !strings.HasPrefix(dir, cgroupRoot+string(os.PathSeparator)) {
		return out, fmt.Errorf("collector: CgroupStats(%s): cgroup path %q escapes %s", containerID, dir, cgroupRoot)
	}
	out.CgroupPath = dir

	// ── CPU usage + throttling (cpu.stat) ──
	if kv, ok := readKVFile(filepath.Join(dir, "cpu.stat")); ok {
		out.CPU.UsageUsec = kv["usage_usec"]
		out.CPU.NrPeriods = kv["nr_periods"]
		out.CPU.NrThrottled = kv["nr_throttled"]
		out.CPU.ThrottledUsec = kv["throttled_usec"]
		if out.CPU.NrPeriods > 0 {
			out.ThrottledPct = float64(out.CPU.NrThrottled) / float64(out.CPU.NrPeriods) * 100
		}
	}

	// cpu.max: "<quota|max> <period>"
	if fields := readFields(filepath.Join(dir, "cpu.max")); len(fields) == 2 {
		var quota, period uint64
		if fields[0] != "max" {
			quota, _ = strconv.ParseUint(fields[0], 10, 64)
		}
		period, _ = strconv.ParseUint(fields[1], 10, 64)
		if quota > 0 && period > 0 {
			out.CoresAllowed = float64(quota) / float64(period)
		} else if fields[0] == "max" {
			out.CoresAllowed = 0 // unlimited
		}
	}

	// ── Memory + swap ──
	out.Memory.Current = readUint(filepath.Join(dir, "memory.current"))
	out.Memory.Limit = readMemValue(filepath.Join(dir, "memory.max"))
	out.Memory.SwapCurrent = readUint(filepath.Join(dir, "memory.swap.current"))
	out.Memory.SwapLimit = readMemValue(filepath.Join(dir, "memory.swap.max"))
	if kv, ok := readKVFile(filepath.Join(dir, "memory.stat")); ok {
		out.Memory.Anon = kv["anon"]
		out.Memory.File = kv["file"]
		out.Memory.Slab = kv["slab"]
		out.Memory.Sock = kv["sock"]
	}

	// ── PSI pressure ──
	out.PSI.CPU = readPSI(filepath.Join(dir, "cpu.pressure"))
	out.PSI.Memory = readPSI(filepath.Join(dir, "memory.pressure"))
	out.PSI.IO = readPSI(filepath.Join(dir, "io.pressure"))

	// ── Block IO (summed across devices) ──
	out.IO = readIOStat(filepath.Join(dir, "io.stat"))

	// ── CPU affinity ──
	out.AllowedCPUs = strings.TrimSpace(readString(filepath.Join(dir, "cpuset.cpus.effective")))

	// ── NUMA distribution ──
	out.NUMA = readNuma(filepath.Join(dir, "memory.numa_stat"))

	return out, nil
}

// unifiedCgroupPath returns the container's cgroup path relative to the v2
// root, read from the `0::<path>` line in /proc/<pid>/cgroup. It errors if the
// host uses the v1 hierarchy (no `0::` line) — v1 is out of scope.
func unifiedCgroupPath(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("collector: read /proc/%d/cgroup: %w", pid, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		// Format: "<hier-id>::<controllers-path>"; the unified entry is "0::/…".
		id, rest, ok := strings.Cut(line, "::")
		if !ok || id != "0" {
			continue
		}
		if rest == "" {
			rest = "/"
		}
		return rest, nil
	}
	return "", errCgroupV1
}

// readKVFile parses whitespace "key value" accounting files (cpu.stat,
// memory.stat). Returns ok=false when the file is missing.
func readKVFile(path string) (map[string]uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	kv := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			kv[fields[0]] = v
		}
	}
	return kv, true
}

func readUint(path string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(readString(path)), 10, 64)
	return v
}

// readMemValue parses a memory limit file, treating the literal "max"
// (unlimited) as 0.
func readMemValue(path string) uint64 {
	s := strings.TrimSpace(readString(path))
	if s == "" || s == "max" {
		return 0
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func readString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func readFields(path string) []string {
	return strings.Fields(readString(path))
}

// readPSI parses a cgroup v2 pressure file. We take only the "some" line:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=0
func readPSI(path string) PSIPressure {
	var p PSIPressure
	for _, line := range strings.Split(readString(path), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "some" {
			continue
		}
		for _, kv := range fields[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch k {
			case "avg10":
				p.SomeAvg10, _ = strconv.ParseFloat(v, 64)
			case "avg60":
				p.SomeAvg60, _ = strconv.ParseFloat(v, 64)
			case "avg300":
				p.SomeAvg300, _ = strconv.ParseFloat(v, 64)
			case "total":
				p.TotalUsec, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		break
	}
	return p
}

// readIOStat sums rbytes/wbytes/rios/wios across every "..." device line in
// io.stat.
func readIOStat(path string) CgroupIO {
	var io CgroupIO
	for _, line := range strings.Split(readString(path), "\n") {
		for _, kv := range strings.Fields(line) {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			switch k {
			case "rbytes":
				io.RBytes += n
			case "wbytes":
				io.WBytes += n
			case "rios":
				io.RIops += n
			case "wios":
				io.WIops += n
			}
		}
	}
	return io
}

// readNuma collapses memory.numa_stat per-node bytes into node -> (anon+file).
// Lines look like: "anon N0=1024 N1=2048".
func readNuma(path string) map[string]uint64 {
	numa := map[string]uint64{}
	for _, line := range strings.Split(readString(path), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kind := fields[0]
		if kind != "anon" && kind != "file" {
			continue
		}
		for _, kv := range fields[1:] {
			node, v, ok := strings.Cut(kv, "=")
			if !ok || !strings.HasPrefix(node, "N") {
				continue
			}
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				numa[node] += n
			}
		}
	}
	if len(numa) == 0 {
		return nil
	}
	return numa
}
