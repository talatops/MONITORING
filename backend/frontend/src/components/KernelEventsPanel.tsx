import { useMemo, useState } from "react";
import type { ContainerInfo, KernelEvent } from "../types";

// Severity → badge class (crit=red, warn=amber, info=gray), matching the
// colour scheme used elsewhere in the UI.
function severityClass(sev: KernelEvent["severity"]): string {
  switch (sev) {
    case "crit": return "badge-red";
    case "warn": return "badge-yellow";
    default:     return "badge-gray";
  }
}

function fmtTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString([], { hour12: false });
}

function shortId(id?: string): string {
  if (!id) return "";
  return id.slice(0, 12);
}

/**
 * KernelEventsPanel shows the live, classified kernel/OOM log for a host.
 * It is rendered only on Linux (see Dashboard). Events are newest-first and
 * buffered in the WS hook; here we add a category filter and resolve the
 * correlated container (from a 64-hex cgroup id) to a friendly name when known.
 */
export default function KernelEventsPanel({
  events,
  containers,
}: {
  events: KernelEvent[];
  containers: ContainerInfo[];
}) {
  const [category, setCategory] = useState<string>("all");

  // Full 64-hex id → container, so OOM lines correlate back to a named card.
  const byId = useMemo(() => {
    const map: Record<string, ContainerInfo> = {};
    for (const c of containers) map[c.id] = c;
    return map;
  }, [containers]);

  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const e of events) set.add(e.category);
    return ["all", ...Array.from(set).sort()];
  }, [events]);

  const visible = useMemo(
    () => (category === "all" ? events : events.filter((e) => e.category === category)),
    [events, category],
  );

  return (
    <section className="card flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Kernel Events
        </h2>
        {categories.length > 1 && (
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded border border-surface-border bg-surface px-2 py-1 text-xs text-slate-200 outline-none focus:border-sky-500"
          >
            {categories.map((c) => (
              <option key={c} value={c}>
                {c === "all" ? "All categories" : c}
              </option>
            ))}
          </select>
        )}
      </div>

      {visible.length === 0 ? (
        <p className="py-6 text-center text-xs text-slate-600">
          No kernel events captured yet.
        </p>
      ) : (
        <div className="scroll-thin flex max-h-72 flex-col overflow-y-auto">
          {visible.map((e, i) => {
            const related = e.container_id ? byId[e.container_id] : undefined;
            return (
              <div
                key={i}
                className="flex items-start gap-2 border-b border-slate-800/40 py-1.5 text-[11px]"
              >
                <span className="w-16 shrink-0 font-mono text-[10px] text-slate-500">
                  {fmtTime(e.ts)}
                </span>
                <span className={`badge shrink-0 text-[10px] ${severityClass(e.severity)}`}>
                  {e.severity}
                </span>
                <span className="badge badge-gray shrink-0 text-[10px]">{e.category}</span>
                <span className="min-w-0 flex-1 break-all text-slate-300">{e.message}</span>
                {related && (
                  <span className="shrink-0 rounded bg-sky-950/50 px-1.5 py-0.5 text-[10px] text-sky-300">
                    {related.name || shortId(related.id)}
                  </span>
                )}
                {!related && e.container_id && (
                  <span className="shrink-0 text-[10px] text-slate-600">{shortId(e.container_id)}</span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
