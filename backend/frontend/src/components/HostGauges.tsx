import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { HostMetrics, HostMetricsPoint } from "../types";

// ── Formatting helpers ─────────────────────────────────────────────────────────

/** bytes/s → human-readable string (KB/s, MB/s, …) */
function fmtBps(bps: number): string {
  if (bps < 1024) return `${bps} B/s`;
  if (bps < 1024 ** 2) return `${(bps / 1024).toFixed(1)} KB/s`;
  if (bps < 1024 ** 3) return `${(bps / 1024 ** 2).toFixed(1)} MB/s`;
  return `${(bps / 1024 ** 3).toFixed(2)} GB/s`;
}

/** bytes → human-readable string */
function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

/** seconds → human uptime */
function fmtUptime(s: number): string {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

/** Unix ms → HH:MM:SS label for XAxis */
function fmtTime(ts: number): string {
  const d = new Date(ts);
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");
}

// ── Mini chart ─────────────────────────────────────────────────────────────────

interface MiniChartProps {
  data: HostMetricsPoint[];
  accessor: keyof HostMetricsPoint;
  stroke: string;
  fillOpacity?: number;
  yMax?: number;
  yDomain?: [number | "auto", number | "auto"];
  valueFormatter?: (v: number) => string;
}

function MiniChart({
  data,
  accessor,
  stroke,
  fillOpacity = 0.18,
  yDomain = [0, "auto"],
  valueFormatter = (v) => String(v),
}: MiniChartProps) {
  return (
    <ResponsiveContainer width="100%" height={110}>
      <AreaChart data={data} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
        <defs>
          <linearGradient id={`grad-${accessor}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={stroke} stopOpacity={0.6} />
            <stop offset="100%" stopColor={stroke} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
        <XAxis
          dataKey="ts"
          tickFormatter={fmtTime}
          stroke="#475569"
          fontSize={10}
          minTickGap={50}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          domain={yDomain}
          stroke="#475569"
          fontSize={10}
          tickFormatter={valueFormatter}
          axisLine={false}
          tickLine={false}
          width={50}
        />
        <Tooltip
          contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8, fontSize: 12 }}
          labelStyle={{ color: "#94a3b8" }}
          labelFormatter={fmtTime}
          formatter={(v: number) => [valueFormatter(v), accessor]}
        />
        <Area
          type="monotone"
          dataKey={accessor}
          stroke={stroke}
          strokeWidth={1.5}
          fill={`url(#grad-${accessor})`}
          fillOpacity={fillOpacity}
          isAnimationActive={false}
          dot={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ── KPI badge ──────────────────────────────────────────────────────────────────

function KPI({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-slate-400 uppercase tracking-wider">{label}</span>
      <span className="text-xl font-bold text-slate-100 tabular-nums">{value}</span>
      {sub && <span className="text-xs text-slate-500">{sub}</span>}
    </div>
  );
}

// ── Section wrapper ─────────────────────────────────────────────────────────────

function ChartCard({
  title,
  latest,
  children,
}: {
  title: string;
  latest: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="card flex flex-col gap-2">
      <div className="flex items-start justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-400">{title}</h3>
        <div className="text-right">{latest}</div>
      </div>
      {children}
    </div>
  );
}

// ── Main component ──────────────────────────────────────────────────────────────

export default function HostGauges({
  history,
  latest,
}: {
  history: HostMetricsPoint[];
  latest: HostMetrics | null;
}) {
  const cpuPct = latest?.cpu_percent ?? 0;
  const memPct = latest?.mem_percent ?? 0;
  const diskR = latest?.disk_read_bps ?? 0;
  const diskW = latest?.disk_write_bps ?? 0;
  const netR = latest?.net_recv_bps ?? 0;
  const netS = latest?.net_sent_bps ?? 0;

  return (
    <>
    <section className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">

      {/* CPU */}
      <ChartCard
        title="CPU"
        latest={
          <div className="flex flex-col items-end">
            <span className={`text-2xl font-bold tabular-nums ${cpuPct > 90 ? "text-red-400" : cpuPct > 75 ? "text-amber-400" : "text-emerald-400"}`}>
              {cpuPct.toFixed(1)}%
            </span>
            {latest && <span className="text-xs text-slate-500">{latest.num_cpu} cores · {latest.go_os}</span>}
          </div>
        }
      >
        <MiniChart data={history} accessor="cpu" stroke="#34d399" yDomain={[0, 100]} valueFormatter={(v) => `${v}%`} />
      </ChartCard>

      {/* Memory */}
      <ChartCard
        title="Memory"
        latest={
          <div className="flex flex-col items-end">
            <span className={`text-2xl font-bold tabular-nums ${memPct > 85 ? "text-red-400" : memPct > 70 ? "text-amber-400" : "text-sky-400"}`}>
              {memPct.toFixed(1)}%
            </span>
            {latest && (
              <span className="text-xs text-slate-500">
                {fmtBytes(latest.mem_used_bytes)} / {fmtBytes(latest.mem_total_bytes)}
              </span>
            )}
          </div>
        }
      >
        <MiniChart data={history} accessor="mem" stroke="#38bdf8" yDomain={[0, 100]} valueFormatter={(v) => `${v}%`} />
      </ChartCard>

      {/* Disk I/O */}
      <ChartCard
        title="Disk I/O"
        latest={
          <div className="flex gap-3">
            <KPI label="R" value={fmtBps(diskR)} />
            <KPI label="W" value={fmtBps(diskW)} />
          </div>
        }
      >
        <div className="flex flex-col gap-1">
          <MiniChart data={history} accessor="diskRead" stroke="#a78bfa" valueFormatter={fmtBps} />
          <MiniChart data={history} accessor="diskWrite" stroke="#f472b6" valueFormatter={fmtBps} />
        </div>
      </ChartCard>

      {/* Network */}
      <ChartCard
        title="Network"
        latest={
          <div className="flex gap-3">
            <KPI label="RX" value={fmtBps(netR)} />
            <KPI label="TX" value={fmtBps(netS)} />
          </div>
        }
      >
        <div className="flex flex-col gap-1">
          <MiniChart data={history} accessor="netRecv" stroke="#fbbf24" valueFormatter={fmtBps} />
          <MiniChart data={history} accessor="netSent" stroke="#fb923c" valueFormatter={fmtBps} />
        </div>
      </ChartCard>

    </section>

    {/* Row 2 — Host info strip */}
    {latest && (
      <section className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Load Average */}
        <div className="card flex flex-col gap-1">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-400">Load Average</h3>
          <div className="flex gap-4 text-lg font-bold tabular-nums text-slate-100">
            <span>{latest.load_1.toFixed(2)}</span>
            <span className="text-slate-400">{latest.load_5.toFixed(2)}</span>
            <span className="text-slate-500">{latest.load_15.toFixed(2)}</span>
          </div>
          <span className="text-[10px] text-slate-500">1 / 5 / 15 min</span>
        </div>
  
        {/* Swap */}
        <div className="card flex flex-col gap-1">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-400">Swap</h3>
          <span className={`text-lg font-bold tabular-nums ${latest.swap_percent > 80 ? "text-red-400" : latest.swap_percent > 50 ? "text-amber-400" : "text-slate-100"}`}>
            {latest.swap_percent > 0 ? `${latest.swap_percent.toFixed(1)}%` : "None"}
          </span>
          {latest.swap_total_bytes > 0 && (
            <span className="text-xs text-slate-500">{fmtBytes(latest.swap_used_bytes)} / {fmtBytes(latest.swap_total_bytes)}</span>
          )}
        </div>
  
        {/* Disk Space */}
        <div className="card flex flex-col gap-1">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-400">Disk Space</h3>
          <span className={`text-lg font-bold tabular-nums ${latest.disk_used_percent > 90 ? "text-red-400" : latest.disk_used_percent > 75 ? "text-amber-400" : "text-slate-100"}`}>
            {latest.disk_used_percent.toFixed(1)}%
          </span>
          <span className="text-xs text-slate-500">
            {fmtBytes(latest.disk_used_bytes)} / {fmtBytes(latest.disk_total_bytes)} ({fmtBytes(latest.disk_free_bytes)} free)
          </span>
        </div>
  
        {/* Uptime */}
        <div className="card flex flex-col gap-1">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-400">Uptime</h3>
          <span className="text-lg font-bold tabular-nums text-emerald-400">
            {fmtUptime(latest.uptime_seconds)}
          </span>
          <span className="text-xs text-slate-500">{latest.go_os} · {latest.num_cpu} cores</span>
        </div>
      </section>
    )}

    {/* Row 3 — Per-core CPU bars */}
    {latest && latest.cpu_per_core && latest.cpu_per_core.length > 0 && (
      <section className="card mt-4 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
            Per-Core CPU
          </h3>
          <span className="text-xs text-slate-500 tabular-nums">
            {latest.cpu_per_core.length} logical cores
          </span>
        </div>
        <div
          className="grid gap-2"
          style={{ gridTemplateColumns: "repeat(auto-fill, minmax(44px, 1fr))" }}
        >
          {latest.cpu_per_core.map((v, i) => (
            <div key={i} className="flex flex-col items-center gap-1">
              <span className="text-[10px] text-slate-300 tabular-nums">{v.toFixed(0)}%</span>
              <div className="flex h-20 w-full items-end overflow-hidden rounded bg-slate-700/60">
                <div
                  className={`w-full rounded transition-all duration-500 ${
                    v >= 90 ? "bg-red-500" : v >= 75 ? "bg-amber-500" : "bg-emerald-500"
                  }`}
                  style={{ height: `${Math.min(100, Math.max(0, v))}%` }}
                />
              </div>
              <span className="text-[10px] text-slate-500 tabular-nums">#{i}</span>
            </div>
          ))}
        </div>
      </section>
    )}
    </>
  );
}
