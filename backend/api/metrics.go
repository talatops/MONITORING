package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/monitoring/backend/collector"
)

// This file implements a Prometheus text-exposition endpoint (GET /metrics).
// It is hand-rolled to avoid pulling in prometheus/client_golang, keeping the
// CGO-free static build dependency-lean. Output follows the exposition format
// version 0.0.4: `# HELP`/`# TYPE` once per metric family, then one sample line
// per series.

// escLabel sanitizes a label value per the Prometheus text format: backslash,
// newline and double-quote must be escaped.
func escLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// renderLabels formats a label set like {host="local",name="web"}; returns ""
// when there are no labels.
func renderLabels(pairs [][2]string) string {
	if len(pairs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `%s="%s"`, p[0], escLabel(p[1]))
	}
	sb.WriteByte('}')
	return sb.String()
}

// header writes the HELP/TYPE lines that introduce a metric family.
func header(b *strings.Builder, name, help, typ string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

// sample writes a single `name{labels} value` line. Floats use the 'f' format
// so large byte counters stay in plain decimal (no scientific notation, which
// some scrapers parse inconsistently).
func sample(b *strings.Builder, name string, labels [][2]string, value float64) {
	b.WriteString(name)
	b.WriteString(renderLabels(labels))
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(value, 'f', -1, 64))
	b.WriteByte('\n')
}

// gauge emits a one-off gauge family (header + single sample).
func gauge(b *strings.Builder, name, help string, value float64, labels [][2]string) {
	header(b, name, help, "gauge")
	sample(b, name, labels, value)
}

// handleMetrics serves the Prometheus text-exposition snapshot. It is a read
// endpoint and is left open (like the other GETs); Prometheus can be configured
// to scrape it directly.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	host := s.hc.Latest()
	hostID := s.cfg.LocalHostID
	hostLabels := [][2]string{{"host", hostID}}

	// Container counts (running vs total) from the cached list.
	var running, total int
	for _, c := range s.lastContainerList {
		total++
		if c.State == "running" {
			running++
		}
	}

	// Latest live snapshot per container, sorted by name for stable output.
	s.statsMu.Lock()
	stats := make([]collector.ContainerStatsSnapshot, 0, len(s.lastStats))
	for _, snap := range s.lastStats {
		stats = append(stats, snap)
	}
	s.statsMu.Unlock()
	sort.Slice(stats, func(i, j int) bool { return stats[i].Name < stats[j].Name })

	// Security totals are best-effort: if the overview can't be built we still
	// serve the rest of the metrics with zeroed scan series.
	var ov SecurityOverview
	if o, err := s.buildSecurityOverview(r.Context()); err == nil {
		ov = o
	}

	var b strings.Builder

	gauge(&b, "monitoring_up", "Always 1 when the monitoring server is reachable.", 1, hostLabels)

	// ── Host metrics ──────────────────────────────────────────────────────────
	gauge(&b, "monitoring_host_cpu_percent", "Host CPU utilisation percentage.", host.CPUPercent, hostLabels)
	gauge(&b, "monitoring_host_num_cpu", "Number of logical CPU cores on the host.", float64(host.NumCPU), hostLabels)
	gauge(&b, "monitoring_host_memory_used_bytes", "Host memory in use, bytes.", float64(host.MemUsedBytes), hostLabels)
	gauge(&b, "monitoring_host_memory_total_bytes", "Host memory total, bytes.", float64(host.MemTotalBytes), hostLabels)
	gauge(&b, "monitoring_host_memory_percent", "Host memory utilisation percentage.", host.MemPercent, hostLabels)
	gauge(&b, "monitoring_host_swap_used_bytes", "Host swap in use, bytes.", float64(host.SwapUsedBytes), hostLabels)
	gauge(&b, "monitoring_host_swap_total_bytes", "Host swap total, bytes.", float64(host.SwapTotalBytes), hostLabels)
	gauge(&b, "monitoring_host_disk_used_bytes", "Host root filesystem used, bytes.", float64(host.DiskUsedBytes), hostLabels)
	gauge(&b, "monitoring_host_disk_total_bytes", "Host root filesystem total, bytes.", float64(host.DiskTotalBytes), hostLabels)
	gauge(&b, "monitoring_host_disk_free_bytes", "Host root filesystem free, bytes.", float64(host.DiskFreeBytes), hostLabels)
	gauge(&b, "monitoring_host_disk_used_percent", "Host root filesystem used percentage.", host.DiskUsedPct, hostLabels)
	gauge(&b, "monitoring_host_disk_read_bytes_per_second", "Host disk read throughput, bytes/sec.", float64(host.DiskReadBPS), hostLabels)
	gauge(&b, "monitoring_host_disk_write_bytes_per_second", "Host disk write throughput, bytes/sec.", float64(host.DiskWriteBPS), hostLabels)
	gauge(&b, "monitoring_host_net_recv_bytes_per_second", "Host network receive throughput, bytes/sec.", float64(host.NetRecvBPS), hostLabels)
	gauge(&b, "monitoring_host_net_sent_bytes_per_second", "Host network transmit throughput, bytes/sec.", float64(host.NetSentBPS), hostLabels)
	gauge(&b, "monitoring_host_uptime_seconds", "Host uptime in seconds.", float64(host.UptimeSeconds), hostLabels)

	header(&b, "monitoring_host_load_average", "Host load average over the given window.", "gauge")
	sample(&b, "monitoring_host_load_average", append(hostLabels, [2]string{"window", "1"}), host.Load1)
	sample(&b, "monitoring_host_load_average", append(hostLabels, [2]string{"window", "5"}), host.Load5)
	sample(&b, "monitoring_host_load_average", append(hostLabels, [2]string{"window", "15"}), host.Load15)

	// ── Fleet counts ───────────────────────────────────────────────────────────
	gauge(&b, "monitoring_containers_total", "Total containers known to the server.", float64(total), hostLabels)
	gauge(&b, "monitoring_containers_running", "Containers currently running.", float64(running), hostLabels)

	// ── Per-container metrics ─────────────────────────────────────────────────
	// Each family emits its header once, then one sample per live container.
	fam := func(name, help, typ string) { header(&b, name, help, typ) }

	fam("monitoring_container_cpu_percent", "Container CPU utilisation percentage.", "gauge")
	for _, st := range stats {
		sample(&b, "monitoring_container_cpu_percent", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, st.CPUPercent)
	}
	fam("monitoring_container_memory_used_bytes", "Container memory in use, bytes.", "gauge")
	for _, st := range stats {
		sample(&b, "monitoring_container_memory_used_bytes", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, float64(st.MemUsedBytes))
	}
	fam("monitoring_container_memory_limit_bytes", "Container memory limit, bytes.", "gauge")
	for _, st := range stats {
		sample(&b, "monitoring_container_memory_limit_bytes", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, float64(st.MemLimitBytes))
	}
	fam("monitoring_container_memory_percent", "Container memory utilisation percentage.", "gauge")
	for _, st := range stats {
		sample(&b, "monitoring_container_memory_percent", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, st.MemPercent)
	}
	fam("monitoring_container_network_received_bytes", "Container bytes received since start.", "counter")
	for _, st := range stats {
		sample(&b, "monitoring_container_network_received_bytes", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, float64(st.NetRxBytes))
	}
	fam("monitoring_container_network_transmitted_bytes", "Container bytes transmitted since start.", "counter")
	for _, st := range stats {
		sample(&b, "monitoring_container_network_transmitted_bytes", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, float64(st.NetTxBytes))
	}
	fam("monitoring_container_block_read_bytes", "Container block-device bytes read since start.", "counter")
	for _, st := range stats {
		sample(&b, "monitoring_container_block_read_bytes", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, float64(st.BlockRead))
	}
	fam("monitoring_container_block_written_bytes", "Container block-device bytes written since start.", "counter")
	for _, st := range stats {
		sample(&b, "monitoring_container_block_written_bytes", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, float64(st.BlockWrite))
	}
	fam("monitoring_container_processes", "Number of processes running in the container.", "gauge")
	for _, st := range stats {
		sample(&b, "monitoring_container_processes", [][2]string{{"host", hostID}, {"id", st.ContainerID}, {"name", st.Name}}, float64(st.PidsCurrent))
	}

	// ── Security / scan totals ────────────────────────────────────────────────
	var scanned, images int
	sevTotals := map[string]int{}
	var secrets, misconfigs int
	for _, exp := range ov.ImageExposure {
		images++
		if exp.Scanned {
			scanned++
		}
		for sev, n := range exp.Counts {
			sevTotals[strings.ToLower(sev)] += n
		}
		secrets += exp.SecretCount
		misconfigs += exp.MisconfigCount
	}

	gauge(&b, "monitoring_scan_images_total", "In-use images considered by the scanner.", float64(images), hostLabels)
	gauge(&b, "monitoring_scan_images_scanned", "In-use images with a cached scan result.", float64(scanned), hostLabels)
	gauge(&b, "monitoring_scan_secrets_total", "Total secrets found across scanned images.", float64(secrets), hostLabels)
	gauge(&b, "monitoring_scan_misconfigurations_total", "Total misconfigurations found across scanned images.", float64(misconfigs), hostLabels)
	gauge(&b, "monitoring_risky_containers", "Containers flagged as risky (privileged/root/caps).", float64(len(ov.RiskyContainers)), hostLabels)

	header(&b, "monitoring_scan_findings", "Vulnerability findings by severity across scanned images.", "gauge")
	sevs := make([]string, 0, len(sevTotals))
	for sev := range sevTotals {
		sevs = append(sevs, sev)
	}
	sort.Strings(sevs)
	for _, sev := range sevs {
		sample(&b, "monitoring_scan_findings", append(hostLabels, [2]string{"severity", sev}), float64(sevTotals[sev]))
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
