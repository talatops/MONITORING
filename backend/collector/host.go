package collector

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// HostMetrics is a point-in-time snapshot of host hardware utilisation.
// JSON tags follow snake_case for the REST/WS wire format.
type HostMetrics struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemUsedBytes  uint64    `json:"mem_used_bytes"`
	MemTotalBytes uint64    `json:"mem_total_bytes"`
	MemPercent    float64   `json:"mem_percent"`
	DiskReadBPS   uint64    `json:"disk_read_bps"`  // bytes per second
	DiskWriteBPS  uint64    `json:"disk_write_bps"` // bytes per second
	NetRecvBPS    uint64    `json:"net_recv_bps"`   // bytes per second
	NetSentBPS    uint64    `json:"net_sent_bps"`   // bytes per second
	NumCPU        int       `json:"num_cpu"`
	GOOS          string    `json:"go_os"` // linux | windows | darwin
	CPUPerCore    []float64 `json:"cpu_per_core,omitempty"` // per-logical-core usage %

	// ── Tier 1 additions ────────────────────────────────────────────────────────
	Load1          float64 `json:"load_1"`           // 1-minute load average
	Load5          float64 `json:"load_5"`           // 5-minute load average
	Load15         float64 `json:"load_15"`          // 15-minute load average
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapPercent    float64 `json:"swap_percent"`
	DiskTotalBytes uint64  `json:"disk_total_bytes"`  // root filesystem total
	DiskUsedBytes  uint64  `json:"disk_used_bytes"`   // root filesystem used
	DiskFreeBytes  uint64  `json:"disk_free_bytes"`   // root filesystem free
	DiskUsedPct    float64 `json:"disk_used_percent"` // root filesystem used %
	UptimeSeconds  uint64  `json:"uptime_seconds"`    // host uptime in seconds
}

// HostCollector polls OS hardware counters on a fixed interval and fans out
// snapshots to any number of subscriber channels.
//
// Disk and network IO counters are cumulative; the collector stores the
// previous values and computes per-second deltas automatically.
//
// Usage:
//
//	hc := collector.NewHostCollector(time.Second)
//	ch := hc.Subscribe()
//	hc.Start(ctx)
//	for m := range ch { … }
type HostCollector struct {
	interval time.Duration

	latest HostMetrics
	mu     sync.RWMutex

	subs  []chan HostMetrics
	subMu sync.Mutex

	// cumulative counters for delta computation
	prevDiskRead  uint64
	prevDiskWrite uint64
	prevNetRecv   uint64
	prevNetSent   uint64
	prevTime      time.Time
}

// NewHostCollector returns a collector that polls every `interval`.
// A non-positive interval defaults to 1 second (per general.md §Module A).
func NewHostCollector(interval time.Duration) *HostCollector {
	if interval <= 0 {
		interval = time.Second
	}
	return &HostCollector{interval: interval}
}

// Start launches the background polling goroutine. It shuts down cleanly when
// ctx is cancelled and closes every subscriber channel.
func (hc *HostCollector) Start(ctx context.Context) {
	go hc.run(ctx)
}

// Latest returns the most recent snapshot (zero-value if polling has not
// completed its first cycle yet). Safe for concurrent use.
func (hc *HostCollector) Latest() HostMetrics {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.latest
}

// Subscribe returns a receive-only channel fed with every future snapshot.
// The channel has a small buffer (8) to tolerate short consumer stalls; new
// snapshots are dropped if the buffer is full so the collector never blocks.
// The caller must NOT close the returned channel — it is owned by the collector.
func (hc *HostCollector) Subscribe() <-chan HostMetrics {
	ch := make(chan HostMetrics, 8)
	hc.subMu.Lock()
	hc.subs = append(hc.subs, ch)
	hc.subMu.Unlock()
	return ch
}

// Unsubscribe removes a previously-subscribed channel and closes it.
// Pass the receive-side channel obtained from Subscribe.
func (hc *HostCollector) Unsubscribe(ch <-chan HostMetrics) {
	hc.subMu.Lock()
	defer hc.subMu.Unlock()
	for i, sub := range hc.subs {
		if (<-chan HostMetrics)(sub) == ch {
			hc.subs = append(hc.subs[:i], hc.subs[i+1:]...)
			close(sub)
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal implementation
// ─────────────────────────────────────────────────────────────────────────────

func (hc *HostCollector) run(ctx context.Context) {
	hc.seed()

	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			hc.closeSubs()
			return
		case <-ticker.C:
			m := hc.poll()
			hc.mu.Lock()
			hc.latest = m
			hc.mu.Unlock()
			hc.broadcast(m)
		}
	}
}

// seed captures the initial cumulative IO counters before the first poll cycle.
func (hc *HostCollector) seed() {
	hc.prevTime = time.Now()
	hc.prevDiskRead, hc.prevDiskWrite = totalDiskIO()
	hc.prevNetRecv, hc.prevNetSent = totalNetIO()
}

func (hc *HostCollector) poll() HostMetrics {
	now := time.Now()
	elapsed := now.Sub(hc.prevTime).Seconds()
	if elapsed <= 0 {
		elapsed = 1 // guard against zero-division on the very first tick
	}

	// ── CPU ─────────────────────────────────────────────────────────────────
	// cpu.Percent(0, true) returns one entry per logical core, measured since
	// the previous call (non-blocking). The aggregate is the mean of the cores,
	// so a single sampling call feeds both the overall % and the per-core bars.
	var cpuPct float64
	var cpuPerCore []float64
	if perCore, err := cpu.Percent(0, true); err == nil && len(perCore) > 0 {
		cpuPerCore = perCore
		var sum float64
		for _, v := range perCore {
			sum += v
		}
		cpuPct = sum / float64(len(perCore))
	}

	// ── Memory ──────────────────────────────────────────────────────────────
	var memUsed, memTotal uint64
	var memPct float64
	if vm, err := mem.VirtualMemory(); err == nil {
		memUsed = vm.Used
		memTotal = vm.Total
		memPct = vm.UsedPercent
	}

	// ── Disk I/O (delta → bytes/second) ────────────────────────────────────
	curDiskRead, curDiskWrite := totalDiskIO()
	var diskReadBPS, diskWriteBPS uint64
	if curDiskRead >= hc.prevDiskRead {
		diskReadBPS = uint64(float64(curDiskRead-hc.prevDiskRead) / elapsed)
	}
	if curDiskWrite >= hc.prevDiskWrite {
		diskWriteBPS = uint64(float64(curDiskWrite-hc.prevDiskWrite) / elapsed)
	}

	// ── Network I/O (delta → bytes/second) ──────────────────────────────────
	curNetRecv, curNetSent := totalNetIO()
	var netRecvBPS, netSentBPS uint64
	if curNetRecv >= hc.prevNetRecv {
		netRecvBPS = uint64(float64(curNetRecv-hc.prevNetRecv) / elapsed)
	}
	if curNetSent >= hc.prevNetSent {
		netSentBPS = uint64(float64(curNetSent-hc.prevNetSent) / elapsed)
	}

	// Advance previous-counter window.
	hc.prevDiskRead = curDiskRead
	hc.prevDiskWrite = curDiskWrite
	hc.prevNetRecv = curNetRecv
	hc.prevNetSent = curNetSent
	hc.prevTime = now

	// ── Load Average ───────────────────────────────────────────────────────
	var load1, load5, load15 float64
	if avg, err := load.Avg(); err == nil {
		load1 = avg.Load1
		load5 = avg.Load5
		load15 = avg.Load15
	}

	// ── Swap Memory ────────────────────────────────────────────────────────
	var swapUsed, swapTotal uint64
	var swapPct float64
	if sw, err := mem.SwapMemory(); err == nil {
		swapUsed = sw.Used
		swapTotal = sw.Total
		swapPct = sw.UsedPercent
	}

	// ── Disk Space (root filesystem) ───────────────────────────────────────
	var diskTotal, diskUsed, diskFree uint64
	var diskUsedPct float64
	diskPart := "/"
	if runtime.GOOS == "windows" {
		diskPart = "C:\\"
	}
	if du, err := disk.Usage(diskPart); err == nil {
		diskTotal = du.Total
		diskUsed = du.Used
		diskFree = du.Free
		diskUsedPct = du.UsedPercent
	}

	// ── Host Uptime ────────────────────────────────────────────────────────
	var uptime uint64
	if u, err := host.Uptime(); err == nil {
		uptime = u
	}

	return HostMetrics{
		Timestamp:     now,
		CPUPercent:    cpuPct,
		MemUsedBytes:  memUsed,
		MemTotalBytes: memTotal,
		MemPercent:    memPct,
		DiskReadBPS:   diskReadBPS,
		DiskWriteBPS:  diskWriteBPS,
		NetRecvBPS:    netRecvBPS,
		NetSentBPS:    netSentBPS,
		NumCPU:        runtime.NumCPU(),
		GOOS:          runtime.GOOS,
		CPUPerCore:    cpuPerCore,

		Load1:          load1,
		Load5:          load5,
		Load15:         load15,
		SwapUsedBytes:  swapUsed,
		SwapTotalBytes: swapTotal,
		SwapPercent:    swapPct,
		DiskTotalBytes: diskTotal,
		DiskUsedBytes:  diskUsed,
		DiskFreeBytes:  diskFree,
		DiskUsedPct:    diskUsedPct,
		UptimeSeconds:  uptime,
	}
}

func (hc *HostCollector) broadcast(m HostMetrics) {
	hc.subMu.Lock()
	defer hc.subMu.Unlock()
	for _, ch := range hc.subs {
		select {
		case ch <- m:
		default: // non-blocking: drop if subscriber is stalled
		}
	}
}

func (hc *HostCollector) closeSubs() {
	hc.subMu.Lock()
	defer hc.subMu.Unlock()
	for _, ch := range hc.subs {
		close(ch)
	}
	hc.subs = nil
}

// totalDiskIO sums ReadBytes / WriteBytes across all mounted disk devices.
func totalDiskIO() (read, write uint64) {
	stats, err := disk.IOCounters()
	if err != nil {
		return
	}
	for _, s := range stats {
		read += s.ReadBytes
		write += s.WriteBytes
	}
	return
}

// totalNetIO sums BytesRecv / BytesSent across all physical network interfaces,
// excluding the loopback interface.
func totalNetIO() (recv, sent uint64) {
	stats, err := net.IOCounters(true) // true = per-interface
	if err != nil {
		return
	}
	for _, s := range stats {
		if s.Name == "lo" {
			continue
		}
		recv += s.BytesRecv
		sent += s.BytesSent
	}
	return
}
