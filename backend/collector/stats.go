package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// ContainerStatsSnapshot holds normalised per-container resource metrics
// extracted from the Docker Engine /stats endpoint.
type ContainerStatsSnapshot struct {
	ContainerID   string  `json:"container_id"`
	Name          string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemUsedBytes  uint64  `json:"mem_used_bytes"`
	MemLimitBytes uint64  `json:"mem_limit_bytes"`
	MemPercent    float64 `json:"mem_percent"`
	NetRxBytes    uint64  `json:"net_rx_bytes"` // cumulative since container start
	NetTxBytes    uint64  `json:"net_tx_bytes"`
	BlockRead     uint64  `json:"block_read"`   // cumulative bytes read from block devices
	BlockWrite    uint64  `json:"block_write"`

	// ── Tier 1 additions ───────────────────────────────────────────────────────
	PidsCurrent       uint64  `json:"pids_current"`        // number of processes in container
	MemCacheBytes     uint64  `json:"mem_cache_bytes"`     // page cache used
	MemRSSBytes       uint64  `json:"mem_rss_bytes"`       // resident set size
	MemSwapBytes      uint64  `json:"mem_swap_bytes"`      // swap used
	CPUThrottledPeriods uint64 `json:"cpu_throttled_periods"` // periods container was throttled
	CPUThrottledTime    uint64 `json:"cpu_throttled_ns"`      // total ns throttled
	NetRxPackets      uint64  `json:"net_rx_packets"`
	NetTxPackets      uint64  `json:"net_tx_packets"`

	// Per-interface network breakdown (eth0, eth1, …)
	NetInterfaces []NetInterfaceStats `json:"net_interfaces,omitempty"`
}

// NetInterfaceStats holds per-interface network counters.
type NetInterfaceStats struct {
	Ifname    string `json:"ifname"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal JSON structs that mirror the Docker Engine /stats wire format.
// Defined locally so we are not coupled to any specific SDK version type name.
// ─────────────────────────────────────────────────────────────────────────────

type dockerStatsRaw struct {
	ID          string            `json:"id"`
	CPUStats    dockerCPUStats    `json:"cpu_stats"`
	PreCPUStats dockerCPUStats    `json:"precpu_stats"`
	MemoryStats dockerMemStats    `json:"memory_stats"`
	Networks    map[string]dockerNetStat `json:"networks"`
	BlkioStats  dockerBlkioStats  `json:"blkio_stats"`
	PidsStats   dockerPidsStats   `json:"pids_stats"`
}

type dockerCPUStats struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemCPUUsage  uint64 `json:"system_cpu_usage"`
	OnlineCPUs      uint32 `json:"online_cpus"`
	ThrottlingData  struct {
		Periods          uint64 `json:"periods"`
		ThrottledPeriods uint64 `json:"throttled_periods"`
		ThrottledTime    uint64 `json:"throttled_time"`
	} `json:"throttling_data"`
}

type dockerMemStats struct {
	Usage uint64 `json:"usage"`
	Limit uint64 `json:"limit"`
	Stats struct {
		Cache uint64 `json:"cache"`
		RSS   uint64 `json:"rss"`
	} `json:"stats"`
	Swap uint64 `json:"swap"`
}

type dockerNetStat struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
}

type dockerBlkioStats struct {
	IoServiceBytesRecursive []struct {
		Op    string `json:"op"`
		Value uint64 `json:"value"`
	} `json:"io_service_bytes_recursive"`
}

type dockerPidsStats struct {
	Current uint64 `json:"current"`
}

// ─────────────────────────────────────────────────────────────────────────────

// StreamContainerStats opens a Docker Engine stats stream for containerID and
// returns a receive-only channel of ContainerStatsSnapshot values.
//
// stream=true keeps the connection open and emits a new snapshot every ~1 s
// (controlled by the Docker daemon). The caller cancels ctx to stop streaming.
//
// CPU% is calculated per general.md §Module B:
//
//	CPU% = (Δcontainer_cpu / Δsystem_cpu) × online_cpus × 100
func (dc *DockerClient) StreamContainerStats(
	ctx context.Context,
	containerID string,
	name string,
) (<-chan ContainerStatsSnapshot, error) {
	if containerID == "" {
		return nil, fmt.Errorf("collector: containerID must not be empty")
	}

	resp, err := dc.CLI.ContainerStats(ctx, containerID, true /* stream */)
	if err != nil {
		return nil, fmt.Errorf("collector: ContainerStats(%s) failed: %w", containerID, err)
	}

	ch := make(chan ContainerStatsSnapshot, 16)

	go func() {
		defer close(ch)
		defer resp.Body.Close() //nolint:errcheck

		dec := json.NewDecoder(resp.Body)
		for {
			// Check for cancellation without blocking on decode.
			select {
			case <-ctx.Done():
				return
			default:
			}

			var raw dockerStatsRaw
			if err := dec.Decode(&raw); err != nil {
				return // stream ended or decode error
			}

			snap := computeStats(containerID, name, raw)

			select {
			case ch <- snap:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

// computeStats converts a raw Docker stats frame into a ContainerStatsSnapshot,
// applying the CPU% formula from general.md.
func computeStats(id, name string, raw dockerStatsRaw) ContainerStatsSnapshot {
	// ── CPU% ────────────────────────────────────────────────────────────────
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage) -
		float64(raw.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(raw.CPUStats.SystemCPUUsage) -
		float64(raw.PreCPUStats.SystemCPUUsage)

	var cpuPct float64
	if sysDelta > 0 && cpuDelta > 0 {
		cpuPct = (cpuDelta / sysDelta) * float64(raw.CPUStats.OnlineCPUs) * 100.0
	}

	// ── Memory ──────────────────────────────────────────────────────────────
	var memPct float64
	if raw.MemoryStats.Limit > 0 {
		memPct = float64(raw.MemoryStats.Usage) / float64(raw.MemoryStats.Limit) * 100.0
	}

	// ── Network ─────────────────────────────────────────────────────────────
	var netRx, netTx, netRxPkts, netTxPkts uint64
	var ifaces []NetInterfaceStats
	for ifName, ns := range raw.Networks {
		netRx += ns.RxBytes
		netTx += ns.TxBytes
		netRxPkts += ns.RxPackets
		netTxPkts += ns.TxPackets
		ifaces = append(ifaces, NetInterfaceStats{
			Ifname:    ifName,
			RxBytes:   ns.RxBytes,
			TxBytes:   ns.TxBytes,
			RxPackets: ns.RxPackets,
			TxPackets: ns.TxPackets,
		})
	}

	// ── Block I/O ───────────────────────────────────────────────────────────
	var blkRead, blkWrite uint64
	for _, bi := range raw.BlkioStats.IoServiceBytesRecursive {
		switch bi.Op {
		case "read":
			blkRead += bi.Value
		case "write":
			blkWrite += bi.Value
		}
	}

	return ContainerStatsSnapshot{
		ContainerID:   id,
		Name:          name,
		CPUPercent:    cpuPct,
		MemUsedBytes:  raw.MemoryStats.Usage,
		MemLimitBytes: raw.MemoryStats.Limit,
		MemPercent:    memPct,
		NetRxBytes:    netRx,
		NetTxBytes:    netTx,
		BlockRead:     blkRead,
		BlockWrite:    blkWrite,

		PidsCurrent:         raw.PidsStats.Current,
		MemCacheBytes:       raw.MemoryStats.Stats.Cache,
		MemRSSBytes:         raw.MemoryStats.Stats.RSS,
		MemSwapBytes:        raw.MemoryStats.Swap,
		CPUThrottledPeriods: raw.CPUStats.ThrottlingData.ThrottledPeriods,
		CPUThrottledTime:    raw.CPUStats.ThrottlingData.ThrottledTime,
		NetRxPackets:        netRxPkts,
		NetTxPackets:        netTxPkts,
		NetInterfaces:       ifaces,
	}
}

// ContainerStatsAggregator fans out stats from multiple container streams into
// a single channel, making it easy for the WebSocket hub to subscribe to one
// source regardless of how many containers are being monitored.
type ContainerStatsAggregator struct {
	mu     sync.Mutex
	inputs []<-chan ContainerStatsSnapshot
	output chan ContainerStatsSnapshot
	done   chan struct{}
}

// NewContainerStatsAggregator returns a ready-to-use aggregator.
func NewContainerStatsAggregator() *ContainerStatsAggregator {
	return &ContainerStatsAggregator{
		output: make(chan ContainerStatsSnapshot, 64),
		done:   make(chan struct{}),
	}
}

// AddStream registers a new container stats channel. Each input is read in its
// own goroutine and forwarded to the aggregator's Output channel.
func (a *ContainerStatsAggregator) AddStream(ch <-chan ContainerStatsSnapshot) {
	a.mu.Lock()
	a.inputs = append(a.inputs, ch)
	a.mu.Unlock()

	go func() {
		for {
			select {
			case <-a.done:
				return
			case snap, ok := <-ch:
				if !ok {
					return // input channel closed
				}
				select {
				case a.output <- snap:
				case <-a.done:
					return
				}
			}
		}
	}()
}

// Output returns the merged stats channel. It is closed when Close is called.
func (a *ContainerStatsAggregator) Output() <-chan ContainerStatsSnapshot {
	return a.output
}

// Close shuts down all forwarding goroutines and closes the output channel.
func (a *ContainerStatsAggregator) Close() {
	close(a.done)
	close(a.output)
}
