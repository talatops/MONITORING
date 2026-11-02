import { useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import type { ContainerInfo, ContainerStatsMap, LogEntry } from "../types";
import ContainerDetailModal from "./ContainerDetailModal";

// ── Formatting ─────────────────────────────────────────────────────────────────

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
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

// ── Stat bar ────────────────────────────────────────────────────────────────────

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

// ── Single card ─────────────────────────────────────────────────────────────────

function ContainerCard({
  container,
  stats,
  onSelect,
}: {
  container: ContainerInfo;
  stats?: ContainerStatsMap[string];
  onSelect: (id: string) => void;
}) {
  const cpu = stats?.cpu_percent ?? 0;
  const mem = stats?.mem_percent ?? 0;

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

  return (
    <div
      className="card flex cursor-pointer flex-col gap-3 transition-shadow hover:ring-1 hover:ring-sky-500/60"
      onClick={() => onSelect(container.id)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(container.id);
        }
      }}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-slate-100">
            {container.name || container.id}
          </p>
          <p className="truncate text-xs text-slate-400">{container.image}</p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={stateBadgeClass(container.state)}>{container.state}</span>
          {hBadge && <span className={`${hBadge} badge text-[10px]`}>{container.health_status}</span>}
          {container.oom_killed && <span className="badge-red badge text-[10px]">OOM Killed</span>}
        </div>
      </div>

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
    </div>
  );
}

// ── Main component ──────────────────────────────────────────────────────────────

export default function ContainerList({
  containers,
  stats,
  logs,
  host,
  hostOS,
}: {
  containers: ContainerInfo[];
  stats: ContainerStatsMap;
  logs: LogEntry[];
  host?: string;
  hostOS?: string;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const trackRef = useRef<HTMLDivElement>(null);

  // Stable alphabetical order (by name, then id). Depends only on `containers`
  // and never on live stats, so each card keeps a fixed position.
  const visible = useMemo(
    () =>
      [...containers].sort((a, b) =>
        (a.name || a.id).localeCompare(b.name || b.id),
      ),
    [containers],
  );

  // Measure the pixel width of one copy so the CSS marquee can translate by
  // exactly that distance and loop seamlessly. Card widths are fixed, so this
  // only changes with the card count — it runs rarely and never per frame.
  const [shiftPx, setShiftPx] = useState(0);
  const [overflowing, setOverflowing] = useState(false);

  useEffect(() => {
    const el = trackRef.current;
    if (!el) return;
    const n = visible.length;
    const first = el.children[0] as HTMLElement | undefined;
    const second = el.children[n] as HTMLElement | undefined;
    const oneCopy =
      first && second
        ? second.offsetLeft - first.offsetLeft
        : Math.round(el.scrollWidth / 3);
    setShiftPx(oneCopy);
    setOverflowing(el.scrollWidth > el.clientWidth + 1);
  }, [visible.length]);

  // Constant speed regardless of card count: duration = distance / speed.
  // Paused when the row already fits (no need to scroll) or the modal is open;
  // hover pause is handled purely in CSS (.marquee-wrap:hover).
  const speed = 40; // px per second
  const paused = !overflowing || selectedId !== null;
  const trackStyle = {
    "--marquee-shift": `${shiftPx}px`,
    animationDuration: shiftPx > 0 ? `${shiftPx / speed}s` : "0s",
  } as CSSProperties;

  return (
    <div className="flex flex-col gap-3">
      {visible.length === 0 ? (
        <div className="card flex items-center justify-center py-12 text-slate-500">
          No running containers detected.
        </div>
      ) : (
        <div className="marquee-wrap relative overflow-hidden">
          <div
            ref={trackRef}
            className={`marquee-track flex gap-4 py-1${paused ? " paused" : ""}`}
            style={trackStyle}
          >
            {[...visible, ...visible, ...visible].map((c, i) => (
              <div key={`${c.id}-${i}`} className="w-72 shrink-0">
                <ContainerCard container={c} stats={stats[c.id]} onSelect={setSelectedId} />
              </div>
            ))}
          </div>
        </div>
      )}

      {selectedId && (() => {
        const selected = containers.find((c) => c.id === selectedId);
        if (!selected) return null;
        return (
          <ContainerDetailModal
            container={selected}
            stats={stats[selected.id]}
            logs={logs}
            host={host}
            hostOS={hostOS}
            onClose={() => setSelectedId(null)}
          />
        );
      })()}
    </div>
  );
}
