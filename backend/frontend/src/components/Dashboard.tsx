import { useEffect, useMemo, useState } from "react";
import type { WSStatus } from "../types";
import HostGauges from "./HostGauges";
import ContainerList from "./ContainerList";
import LogPanel from "./LogPanel";
import SystemDfPanel from "./SystemDfPanel";
import NetworkTopology from "./NetworkTopology";
import VolumePanel from "./VolumePanel";
import ImagePanel from "./ImagePanel";
import KernelEventsPanel from "./KernelEventsPanel";
import SecurityPanel from "./SecurityPanel";
import { emptyBucket, type MonitorState } from "../hooks/useMonitorWebSocket";
import { useHostHistoryRange } from "../hooks/useHostHistoryRange";
import { useHosts } from "../hooks/useResources";
import { RANGES } from "../lib/constants";
import { exportHostCSV } from "../lib/csv";

// ── WS status indicator ─────────────────────────────────────────────────────────

function StatusDot({ status }: { status: WSStatus }) {
  const cfg: Record<WSStatus, { cls: string; label: string }> = {
    connecting: { cls: "bg-amber-400 animate-pulse", label: "Connecting…" },
    open:       { cls: "bg-emerald-400",              label: "Live" },
    closed:     { cls: "bg-slate-500",                label: "Disconnected" },
    error:      { cls: "bg-red-500 animate-pulse",    label: "Reconnecting…" },
  };
  const { cls, label } = cfg[status];
  return (
    <span className="flex items-center gap-1.5 text-xs text-slate-400">
      <span className={`h-2 w-2 rounded-full ${cls}`} />
      {label}
    </span>
  );
}

// ── Main dashboard ──────────────────────────────────────────────────────────────

export default function Dashboard({ state }: { state: MonitorState }) {
  const { status, byHost } = state;

  const { data: hostsData } = useHosts();
  const hosts = useMemo(() => hostsData ?? [], [hostsData]);
  const localHostId = useMemo(
    () => hosts.find((h) => h.kind === "local")?.id ?? "local",
    [hosts],
  );

  const [selectedHost, setSelectedHost] = useState("");
  // Default to the local hub once the host list is known.
  useEffect(() => {
    if (selectedHost === "" && hosts.length > 0) setSelectedHost(localHostId);
  }, [selectedHost, hosts, localHostId]);

  const activeHost = selectedHost || localHostId;
  const isRemote = activeHost !== localHostId;
  const bucket = byHost[activeHost] ?? emptyBucket;
  const { latestHost, hostHistory, containers, containerStats, logs, kernelEvents } = bucket;

  const [range, setRange] = useState("live");
  const [view, setView] = useState<"overview" | "topology" | "volumes" | "images" | "security">("overview");
  // DB-backed history is a local-only feature; remote hosts are live-only.
  const { data: rangeData, loading: rangeLoading } = useHostHistoryRange(isRemote ? "live" : range);
  const chartHistory = range === "live" || isRemote ? hostHistory : rangeData;

  const alertCount = containers.reduce((n, c) => {
    const s = containerStats[c.id];
    return n + (s && (s.cpu_percent > 90 || s.mem_percent > 85) ? 1 : 0);
  }, 0);

  const selectedHostInfo = hosts.find((h) => h.id === activeHost);

  return (
    <div className="flex min-h-screen flex-col bg-surface text-slate-100">
      {/* Header bar */}
      <header className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-2 border-b border-surface-border bg-surface/80 px-5 py-3 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <h1 className="text-base font-bold tracking-tight text-slate-100">
            System Monitor
          </h1>
          {latestHost && (
            <span className="badge-gray badge">
              {latestHost.go_os} · {latestHost.num_cpu} cores
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {hosts.length > 1 && (
            <select
              value={activeHost}
              onChange={(e) => setSelectedHost(e.target.value)}
              className="rounded border border-surface-border bg-surface px-2 py-1 text-xs text-slate-200 outline-none focus:border-sky-500"
              title="Select monitored host"
            >
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.name}
                  {h.kind === "local" ? " (local)" : h.online ? "" : " (offline)"}
                </option>
              ))}
            </select>
          )}
          <StatusDot status={status} />
        </div>
      </header>

      <main className="flex flex-1 flex-col gap-5 p-5">

        {/* View tabs */}
        <div className="flex flex-wrap items-center gap-1 self-start rounded-lg border border-surface-border bg-surface p-1">
          {([
            ["overview", "Overview"],
            ["topology", "Network"],
            ["volumes", "Volumes"],
            ["images", "Images"],
            ["security", "Security"],
          ] as const).map(([value, label]) => (
            <button
              key={value}
              onClick={() => setView(value)}
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
                view === value
                  ? "bg-slate-700 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {isRemote && (
          <p className="text-[11px] text-slate-500">
            {selectedHostInfo?.name ?? activeHost} is a remote agent — live data only
            (no stored history or CSV export).
          </p>
        )}

        {view === "overview" && (
          <>
        {/* Time-range selector + alert summary (local host only for range/CSV) */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          {!isRemote && (
            <div className="flex flex-wrap items-center gap-1 rounded-lg border border-surface-border bg-surface p-1">
              {RANGES.map((r) => (
                <button
                  key={r.value}
                  onClick={() => setRange(r.value)}
                  className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                    range === r.value
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {r.label}
                </button>
              ))}
            </div>
          )}
          {alertCount > 0 && (
            <span className="badge-red badge animate-pulse">
              {alertCount} container{alertCount > 1 ? "s" : ""} in alert
            </span>
          )}
          {!isRemote && (
            <button
              onClick={() => exportHostCSV(chartHistory, `host-metrics-${range}.csv`)}
              disabled={chartHistory.length === 0}
              className="rounded border border-surface-border bg-surface px-2.5 py-1 text-xs text-slate-300 transition-colors hover:border-sky-500 disabled:cursor-not-allowed disabled:opacity-40"
              title="Download the visible host metrics as CSV"
            >
              Download CSV
            </button>
          )}
        </div>
        {!isRemote && range !== "live" && rangeLoading && (
          <p className="text-xs text-slate-500">Loading {range} history…</p>
        )}

        {/* Row 1 — host gauges */}
        <HostGauges history={chartHistory} latest={latestHost} />

        {/* Row 2 — containers */}
        <section>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-slate-400">
            Containers
          </h2>
          <ContainerList containers={containers} stats={containerStats} logs={logs} host={activeHost} hostOS={latestHost?.go_os} />
        </section>

        {/* Row 2b — kernel/OOM event mining (Linux hosts only) */}
        {latestHost?.go_os === "linux" && (
          <KernelEventsPanel events={kernelEvents} containers={containers} />
        )}

        {/* Row 3 — docker disk usage */}
        <SystemDfPanel host={activeHost} />

        {/* Row 4 — logs */}
        <LogPanel logs={logs} containers={containers} />
          </>
        )}

        {view === "topology" && <NetworkTopology host={activeHost} />}
        {view === "volumes" && <VolumePanel host={activeHost} />}
        {view === "images" && <ImagePanel host={activeHost} />}
        {view === "security" && <SecurityPanel />}

      </main>

      {/* Footer */}
      <footer className="border-t border-surface-border px-5 py-2 text-center text-xs text-slate-600">
        Cross-platform monitoring · Linux Unix Socket · Windows Named Pipe
      </footer>
    </div>
  );
}
