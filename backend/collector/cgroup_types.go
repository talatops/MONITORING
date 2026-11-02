package collector

// ─────────────────────────────────────────────────────────────────────────────
// cgroup v2 per-container detail (Phase 5). The type surface lives in this
// untagged file so the Linux reader (cgroup.go) and the non-Linux stub
// (cgroup_other.go) both compile, and the multi-host agent/hub can serialise
// the struct regardless of the build target. JSON tags are snake_case for the
// REST/WS wire format.
// ─────────────────────────────────────────────────────────────────────────────

// PSIPressure is the "some" pressure-stall information for one resource
// (cpu | memory | io). Percentages are the avg over 10/60/300 s; TotalUsec is
// the cumulative stalled microseconds.
type PSIPressure struct {
	SomeAvg10  float64 `json:"some_avg10"`
	SomeAvg60  float64 `json:"some_avg60"`
	SomeAvg300 float64 `json:"some_avg300"`
	TotalUsec  uint64  `json:"total_usec"`
}

// CgroupMemory is memory + swap usage for a container cgroup. Limit fields are
// 0 when the limit is "max" (unlimited).
type CgroupMemory struct {
	Current     uint64 `json:"current"`
	Limit       uint64 `json:"limit"`
	SwapCurrent uint64 `json:"swap_current"`
	SwapLimit   uint64 `json:"swap_limit"`
	Anon        uint64 `json:"anon"`
	File        uint64 `json:"file"`
	Slab        uint64 `json:"slab"`
	Sock        uint64 `json:"sock"`
}

// CgroupIO is the summed block IO across all devices in io.stat.
type CgroupIO struct {
	RBytes uint64 `json:"rbytes"`
	WBytes uint64 `json:"wbytes"`
	RIops  uint64 `json:"riops"`
	WIops  uint64 `json:"wiops"`
}

// CgroupCPU is CPU usage and throttling counters from cpu.stat.
type CgroupCPU struct {
	UsageUsec     uint64 `json:"usage_usec"`
	NrPeriods     uint64 `json:"nr_periods"`
	NrThrottled   uint64 `json:"nr_throttled"`
	ThrottledUsec uint64 `json:"throttled_usec"`
}

// PSISet bundles the three per-resource pressure readings.
type PSISet struct {
	CPU    PSIPressure `json:"cpu"`
	Memory PSIPressure `json:"memory"`
	IO     PSIPressure `json:"io"`
}

// ContainerCgroupStats is the full cgroup-v2 snapshot for one running
// container. It is only ever populated on Linux; other platforms get an empty
// value alongside ErrNotSupported from the provider/handler layer.
type ContainerCgroupStats struct {
	CgroupPath   string       `json:"cgroup_path"`
	CPU          CgroupCPU    `json:"cpu"`
	ThrottledPct float64      `json:"throttled_pct"` // nr_throttled / nr_periods * 100
	CoresAllowed float64      `json:"cores_allowed"` // cpu.max quota / period
	AllowedCPUs  string       `json:"allowed_cpus"`  // cpuset.cpus.effective
	Memory       CgroupMemory `json:"memory"`
	PSI          PSISet       `json:"psi"`
	IO           CgroupIO     `json:"io"`
	NUMA         map[string]uint64 `json:"numa,omitempty"` // node -> anon+file bytes
}
