import { useEffect, useMemo, useState } from "react";
import type { ContainerCgroupStats, ContainerInfo, ContainerStatsSnapshot, LogEntry } from "../types";
import { useContainerTop, useContainerInspect, useContainerCgroup } from "../hooks/useContainerExtras";
import { containerAction } from "../hooks/useResources";
import { ActionError, ensureAdminToken, invalidateAdminToken } from "../lib/api";

// ── Formatting helpers (kept local to avoid a circular import with ContainerList) ──

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

function fmtUptime(created: number): string {
  const secs = Math.floor(Date.now() / 1000 - created);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}

function stateBadgeClass(state: string): string {
  switch (state.toLowerCase()) {
    case "running": return "badge-green";
    case "exited":
    case "dead":    return "badge-red";
    case "paused":
    case "created": return "badge-yellow";
    default:        return "badge-gray";
  }
}

function StatBar({
  label,
  pct,
  sub,
  color = "bg-emerald-500",
}: {
  label: string;
  pct: number;
  sub: string;
  color?: string;
}) {
  const clamped = Math.min(100, Math.max(0, pct));
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-400">{label}</span>
        <span className="text-slate-300 tabular-nums">{sub}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700">
        <div
          className={`h-full rounded-full transition-all duration-500 ${color}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  );
}

type Tab = "overview" | "processes" | "inspect" | "logs" | "cgroup";

// ── cgroup v2 detail panel ────────────────────────────────────────────────────

function kvLabel(v: number): string {
  return Number.isInteger(v) ? `${v}` : v.toFixed(1);
}

function PSIRow({ label, p }: { label: string; p: ContainerCgroupStats["psi"]["cpu"] }) {
  // PSI "some" averages are percentages of time at least one task stalled.
  const hot = p.some_avg10 > 10;
  return (
    <div className="flex items-center justify-between text-[11px]">
      <span className="text-slate-400">{label} pressure</span>
      <span className={`tabular-nums ${hot ? "text-red-400" : "text-slate-300"}`}>
        some {p.some_avg10.toFixed(2)} / {p.some_avg60.toFixed(2)} / {p.some_avg300.toFixed(2)}%
      </span>
    </div>
  );
}

function CgroupPanel({ stats }: { stats: ContainerCgroupStats }) {
  const m = stats.memory;
  const memPct = m.limit > 0 ? (m.current / m.limit) * 100 : 0;
  const swapPct = m.swap_limit > 0 ? (m.swap_current / m.swap_limit) * 100 : 0;
  const numaEntries = Object.entries(stats.numa ?? {});
  return (
    <div className="flex flex-col gap-4">
      <p className="truncate font-mono text-[10px] text-slate-600">{stats.cgroup_path}</p>

      {/* CPU throttling */}
      <div className="flex flex-col gap-1">
        <h4 className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">CPU</h4>
        <div className="flex flex-wrap gap-1.5 text-[10px]">
          <span className={stats.throttled_pct > 1 ? "badge-yellow badge" : "badge-gray badge"}>
            Throttled {kvLabel(stats.throttled_pct)}%
          </span>
          <span className="badge-gray badge">{stats.cpu.nr_throttled}/{stats.cpu.nr_periods} periods</span>
          <span className="badge-gray badge">
            Cores {stats.cores_allowed > 0 ? kvLabel(stats.cores_allowed) : "unlimited"}
          </span>
          {stats.allowed_cpus && <span className="badge-gray badge">cpuset {stats.allowed_cpus}</span>}
        </div>
      </div>

      {/* Memory + swap bars */}
      <div className="flex flex-col gap-2">
        <h4 className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Memory</h4>
        <StatBar
          label="Used"
          pct={memPct}
          sub={m.limit > 0 ? `${fmtBytes(m.current)} / ${fmtBytes(m.limit)}` : `${fmtBytes(m.current)} (unlimited)`}
          color={memPct >= 90 ? "bg-red-500" : memPct >= 75 ? "bg-amber-500" : "bg-sky-500"}
        />
        {(m.swap_limit > 0 || m.swap_current > 0) && (
          <StatBar
            label="Swap"
            pct={swapPct}
            sub={m.swap_limit > 0 ? `${fmtBytes(m.swap_current)} / ${fmtBytes(m.swap_limit)}` : `${fmtBytes(m.swap_current)}`}
            color="bg-violet-500"
          />
        )}
        <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-slate-500">
          <span>anon {fmtBytes(m.anon)}</span>
          <span>file {fmtBytes(m.file)}</span>
          <span>slab {fmtBytes(m.slab)}</span>
          <span>sock {fmtBytes(m.sock)}</span>
        </div>
      </div>

      {/* PSI */}
      <div className="flex flex-col gap-1">
        <h4 className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Pressure (PSI)</h4>
        <PSIRow label="CPU" p={stats.psi.cpu} />
        <PSIRow label="Memory" p={stats.psi.memory} />
        <PSIRow label="IO" p={stats.psi.io} />
      </div>

      {/* IO totals */}
      <div className="flex flex-col gap-1">
        <h4 className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">IO</h4>
        <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-slate-400">
          <span>R {fmtBytes(stats.io.rbytes)} ({stats.io.riops} ops)</span>
          <span>W {fmtBytes(stats.io.wbytes)} ({stats.io.wiops} ops)</span>
        </div>
      </div>

      {/* NUMA */}
      {numaEntries.length > 0 && (
        <div className="flex flex-col gap-1">
          <h4 className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">NUMA</h4>
          <div className="flex flex-wrap gap-1.5 text-[10px] text-slate-400">
            {numaEntries.map(([node, bytes]) => (
              <span key={node} className="badge-gray badge">{node} {fmtBytes(bytes)}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function ContainerDetailModal({
  container,
  stats,
  logs,
  host,
  hostOS,
  onClose,
}: {
  container: ContainerInfo;
  stats?: ContainerStatsSnapshot;
  logs: LogEntry[];
  host?: string;
  hostOS?: string;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>("overview");
  const [busy, setBusy] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  // Close on Escape; listener is removed on unmount so nothing leaks.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Hooks are always called; `enabled` gates the actual fetch to the active tab
  // so we only hit /top, /inspect and /cgroup when the user opens those tabs.
  const isLinux = hostOS == null || hostOS.toLowerCase() === "linux";
  const cgroupEnabled = tab === "cgroup" && container.state === "running" && isLinux;
  const top = useContainerTop(container.id, tab === "processes", host);
  const inspect = useContainerInspect(container.id, tab === "inspect", host);
  const cgroup = useContainerCgroup(container.id, cgroupEnabled, host);

  const tabs: Tab[] = ["overview", "processes", "inspect", "logs"];
  if (container.state === "running" && isLinux) tabs.push("cgroup");

  const containerLogs = useMemo(
    () => logs.filter((e) => e.container_id === container.id).slice(-500).reverse(),
    [logs, container.id],
  );

  const cpu = stats?.cpu_percent ?? 0;
  const mem = stats?.mem_percent ?? 0;
  const isAlert = cpu > 90 || mem > 85;

  function healthBadge(): string | null {
    if (!container.health_status) return null;
    switch (container.health_status) {
      case "healthy": return "badge-green";
      case "unhealthy": return "badge-red";
      case "starting": return "badge-yellow";
      default: return null;
    }
  }
  const hBadge = healthBadge();

  async function runAction(op: "start" | "stop" | "restart" | "remove") {
    if (busy) return;
    const force =
      op === "remove" &&
      window.confirm(`Remove container "${container.name || container.id}"?\n\nOK force-removes it (and its anonymous volumes); Cancel to abort.`);
    if (op === "remove" && !force) return;
    if (!ensureAdminToken()) return;
    setBusy(op);
    setActionMsg(null);
    try {
      await containerAction(container.id, op, force, host);
      setActionMsg(`${op.charAt(0).toUpperCase()}${op.slice(1)} sent`);
      if (op === "remove") onClose();
    } catch (e) {
      if (e instanceof ActionError && (e.status === 401 || e.status === 403)) invalidateAdminToken();
      setActionMsg(`${op} failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      {/* Panel */}
      <div className="card relative z-10 flex max-h-[85vh] w-full max-w-2xl flex-col gap-4 overflow-hidden">
        {/* Header */}
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate text-base font-semibold text-slate-100">
              {container.name || container.id}
            </p>
            <p className="truncate text-xs text-slate-400">{container.image}</p>
            <p className="mt-0.5 truncate text-[10px] text-slate-600">{container.id}</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex flex-col items-end gap-1">
              <span className={stateBadgeClass(container.state)}>{container.state}</span>
              {isAlert && <span className="badge-red badge text-[10px] animate-pulse">ALERT</span>}
              {hBadge && <span className={`${hBadge} badge text-[10px]`}>{container.health_status}</span>}
              {container.oom_killed && <span className="badge-red badge text-[10px]">OOM Killed</span>}
            </div>
            <button
              onClick={onClose}
              className="rounded p-1 text-slate-400 transition-colors hover:bg-slate-700/60 hover:text-slate-100"
              aria-label="Close"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="M18 6 6 18M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-surface-border text-xs">
          {tabs.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`-mb-px border-b-2 px-3 py-1.5 font-medium capitalize transition-colors ${
                tab === t
                  ? "border-sky-500 text-slate-100"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Scrollable tab body */}
        <div className="scroll-thin flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto">
          {tab === "overview" && (
            <>
              {/* Live stats bars */}
              <div className="flex flex-col gap-2">
                <StatBar
                  label="CPU"
                  pct={cpu}
                  sub={`${cpu.toFixed(1)}%`}
                  color={cpu >= 90 ? "bg-red-500" : cpu >= 75 ? "bg-amber-500" : "bg-emerald-500"}
                />
                <StatBar
                  label="Memory"
                  pct={mem}
                  sub={stats ? `${fmtBytes(stats.mem_used_bytes)} / ${fmtBytes(stats.mem_limit_bytes)}` : "—"}
                  color={mem >= 85 ? "bg-red-500" : mem >= 70 ? "bg-amber-500" : "bg-sky-500"}
                />
              </div>

              {/* Detail badges */}
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                {stats && (
                  <>
                    <span className="badge-gray badge">
                      Net ↓{fmtBytes(stats.net_rx_bytes)} ↑{fmtBytes(stats.net_tx_bytes)}
                    </span>
                    <span className="badge-gray badge">
                      Disk R:{fmtBytes(stats.block_read)} W:{fmtBytes(stats.block_write)}
                    </span>
                    {stats.pids_current > 0 && (
                      <span className="badge-gray badge">PIDs {stats.pids_current}</span>
                    )}
                    {stats.cpu_throttled_periods > 0 && (
                      <span className="badge-yellow badge">Throttle {stats.cpu_throttled_periods}</span>
                    )}
                  </>
                )}
                <span className="badge-gray badge">Up {fmtUptime(container.created)}</span>
                {container.size_rw_bytes > 0 && (
                  <span className="badge-gray badge">FS {fmtBytes(container.size_rw_bytes)}</span>
                )}
                {container.restart_count > 0 && (
                  <span className="badge-yellow badge">Restarted {container.restart_count}x</span>
                )}
                {container.exit_code !== 0 && container.state === "exited" && (
                  <span className="badge-red badge">Exit {container.exit_code}</span>
                )}
              </div>

              {/* Port mappings */}
              {container.ports && container.ports.length > 0 && (
                <div className="flex flex-col gap-1">
                  <h4 className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Ports</h4>
                  <div className="flex flex-wrap gap-1.5 text-[10px] text-slate-400">
                    {container.ports.map((p, i) => (
                      <span key={i} className="badge-gray badge">
                        {p.public_port ? `${p.public_port}\u2192${p.private_port}/${p.type}` : `${p.private_port}/${p.type}`}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Memory + network breakdown */}
              {stats && (stats.mem_cache_bytes > 0 || stats.mem_rss_bytes > 0 || stats.mem_swap_bytes > 0 || (stats.net_interfaces && stats.net_interfaces.length > 0)) && (
                <div className="flex flex-col gap-2">
                  <h4 className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Details</h4>
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-slate-500">
                    {stats.mem_rss_bytes > 0 && <span>RSS {fmtBytes(stats.mem_rss_bytes)}</span>}
                    {stats.mem_cache_bytes > 0 && <span>Cache {fmtBytes(stats.mem_cache_bytes)}</span>}
                    {stats.mem_swap_bytes > 0 && <span className="text-amber-500">Swap {fmtBytes(stats.mem_swap_bytes)}</span>}
                    {container.size_rootfs_bytes > 0 && <span>Image {fmtBytes(container.size_rootfs_bytes)}</span>}
                  </div>
                  {stats.net_interfaces && stats.net_interfaces.length > 0 && (
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-slate-400">
                      {stats.net_interfaces.map((iface) => (
                        <span key={iface.ifname}>
                          {iface.ifname}: ↓{fmtBytes(iface.rx_bytes)} ↑{fmtBytes(iface.tx_bytes)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {tab === "processes" && (
            <div className="flex flex-col gap-2">
              {top.loading && <p className="text-xs text-slate-500">Loading processes…</p>}
              {top.error && (
                <p className="text-xs text-red-400">
                  {container.state !== "running"
                    ? "Processes are only available for running containers."
                    : `Could not load processes: ${top.error}`}
                </p>
              )}
              {top.data && top.data.processes.length > 0 && (
                <div className="scroll-thin overflow-x-auto">
                  <table className="w-full border-collapse text-left text-[11px]">
                    <thead>
                      <tr className="text-slate-500">
                        {top.data.titles.map((t) => (
                          <th key={t} className="whitespace-nowrap px-2 py-1 font-medium">{t}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="font-mono text-slate-300">
                      {top.data.processes.map((row, i) => (
                        <tr key={i} className="border-t border-slate-800/40">
                          {top.data!.titles.map((_, col) => (
                            <td key={col} className="whitespace-nowrap px-2 py-0.5">{row[col]}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {top.data && top.data.processes.length === 0 && (
                <p className="text-xs text-slate-500">No processes reported.</p>
              )}
            </div>
          )}

          {tab === "inspect" && (
            <div className="flex flex-col gap-2">
              {inspect.loading && <p className="text-xs text-slate-500">Loading inspect…</p>}
              {inspect.error && <p className="text-xs text-red-400">Could not load inspect: {inspect.error}</p>}
              {inspect.data != null && (
                <pre className="scroll-thin max-h-[60vh] overflow-auto rounded bg-slate-950/60 p-3 font-mono text-[11px] leading-relaxed text-slate-300">
                  {JSON.stringify(inspect.data, null, 2)}
                </pre>
              )}
            </div>
          )}

          {tab === "logs" && (
            <div className="flex flex-col">
              {containerLogs.length === 0 ? (
                <p className="px-1 py-6 text-center text-xs text-slate-600">
                  No log lines buffered for this container yet.
                </p>
              ) : (
                <div className="flex flex-col">
                  {containerLogs.map((entry, i) => (
                    <div
                      key={i}
                      className="flex gap-2 border-b border-slate-800/40 px-1 py-0.5 font-mono text-[11px]"
                    >
                      <span
                        className={`w-9 shrink-0 text-center text-[10px] uppercase ${
                          entry.stream === "stderr" ? "text-red-400" : "text-slate-500"
                        }`}
                      >
                        {entry.stream === "stderr" ? "ERR" : "OUT"}
                      </span>
                      <span
                        className={`flex-1 whitespace-pre-wrap break-all ${
                          entry.stream === "stderr" ? "text-red-400" : "text-slate-300"
                        }`}
                      >
                        {entry.line}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === "cgroup" && (
            <div className="flex flex-col gap-3">
              {cgroup.loading && <p className="text-xs text-slate-500">Reading cgroup v2 detail…</p>}
              {cgroup.error && (
                <p className="text-xs text-slate-500">
                  cgroup detail unavailable (Linux + root only).
                </p>
              )}
              {cgroup.data && <CgroupPanel stats={cgroup.data} />}
            </div>
          )}
        </div>

        {/* Action footer (admin token required server-side) */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-surface-border pt-3">
          {actionMsg && <span className="text-[11px] text-slate-400">{actionMsg}</span>}
          <div className="ml-auto flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => runAction("start")}
              disabled={busy !== null}
              className="rounded border border-emerald-500/40 bg-emerald-950/40 px-2 py-1 text-[11px] text-emerald-200 hover:bg-emerald-900/40 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy === "start" ? "Starting…" : "Start"}
            </button>
            <button
              type="button"
              onClick={() => runAction("stop")}
              disabled={busy !== null}
              className="rounded border border-amber-500/40 bg-amber-950/40 px-2 py-1 text-[11px] text-amber-200 hover:bg-amber-900/40 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy === "stop" ? "Stopping…" : "Stop"}
            </button>
            <button
              type="button"
              onClick={() => runAction("restart")}
              disabled={busy !== null}
              className="rounded border border-sky-500/40 bg-sky-950/40 px-2 py-1 text-[11px] text-sky-200 hover:bg-sky-900/40 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy === "restart" ? "Restarting…" : "Restart"}
            </button>
            <button
              type="button"
              onClick={() => runAction("remove")}
              disabled={busy !== null}
              className="rounded border border-red-500/40 bg-red-950/40 px-2 py-1 text-[11px] text-red-200 hover:bg-red-900/40 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy === "remove" ? "Removing…" : "Remove"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
