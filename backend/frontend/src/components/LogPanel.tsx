import { useCallback, useMemo, useRef, useState } from "react";
import type { ContainerInfo, LogEntry } from "../types";

// ── Stream colour ───────────────────────────────────────────────────────────────

function streamColor(stream: string): string {
  return stream === "stderr" ? "text-red-400" : "text-slate-300";
}

// ── Filter bar ──────────────────────────────────────────────────────────────────

interface FilterBarProps {
  containers: ContainerInfo[];
  selectedContainer: string;
  onSelectContainer: (id: string) => void;
  query: string;
  onQuery: (q: string) => void;
  showErrorOnly: boolean;
  onToggleError: () => void;
  showStdout: boolean;
  onToggleStdout: () => void;
  count: number;
}

function FilterBar({
  containers,
  selectedContainer,
  onSelectContainer,
  query,
  onQuery,
  showErrorOnly,
  onToggleError,
  showStdout,
  onToggleStdout,
  count,
}: FilterBarProps) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-surface-border px-3 py-2">
      {/* Container selector */}
      <select
        value={selectedContainer}
        onChange={(e) => onSelectContainer(e.target.value)}
        className="rounded border border-surface-border bg-surface px-2 py-1 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
      >
        <option value="">All containers</option>
        {containers.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name || c.id}
          </option>
        ))}
      </select>

      {/* Text search */}
      <input
        type="search"
        placeholder="Search logs…"
        value={query}
        onChange={(e) => onQuery(e.target.value)}
        className="min-w-[160px] flex-1 rounded border border-surface-border bg-surface px-2 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
      />

      {/* Stream toggles */}
      <button
        onClick={onToggleStdout}
        className={`rounded px-2 py-1 text-xs transition-colors ${showStdout ? "bg-sky-800 text-sky-200" : "bg-slate-700 text-slate-400"}`}
      >
        stdout
      </button>
      <button
        onClick={onToggleError}
        className={`rounded px-2 py-1 text-xs transition-colors ${showErrorOnly ? "bg-red-800 text-red-200" : "bg-slate-700 text-slate-400"}`}
      >
        stderr
      </button>

      <span className="ml-auto text-xs text-slate-500 tabular-nums">
        {count.toLocaleString()} lines
      </span>
    </div>
  );
}

// ── Main component ──────────────────────────────────────────────────────────────

export default function LogPanel({
  logs,
  containers,
}: {
  logs: LogEntry[];
  containers: ContainerInfo[];
}) {
  const [selectedContainer, setSelectedContainer] = useState("");
  const [query, setQuery] = useState("");
  const [showErrorOnly, setShowErrorOnly] = useState(false);
  const [showStdout, setShowStdout] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const listRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return logs.filter((e) => {
      if (selectedContainer && e.container_id !== selectedContainer) return false;
      if (!showStdout && e.stream === "stdout") return false;
      if (showErrorOnly && e.stream !== "stderr") return false;
      if (q && !e.line.toLowerCase().includes(q) && !e.container_id.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [logs, selectedContainer, query, showErrorOnly, showStdout]);

  // Auto-scroll to newest (top) when new entries arrive and autoScroll is on
  const handleScroll = useCallback(() => {
    if (autoScroll && listRef.current) {
      listRef.current.scrollTop = 0;
    }
  }, [autoScroll]);

  // Trigger scroll whenever filtered list changes
  useMemo(() => {
    requestAnimationFrame(handleScroll);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered.length]);

  const containerName = (id: string) =>
    containers.find((c) => c.id === id)?.name ?? id.slice(0, 8);

  return (
    <div className="card flex flex-col gap-0 p-0" style={{ height: "480px" }}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-surface-border px-3 py-2">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Container Logs
        </h2>
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-400">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="accent-sky-500"
          />
          Auto-scroll
        </label>
      </div>

      {/* Filter bar */}
      <FilterBar
        containers={containers}
        selectedContainer={selectedContainer}
        onSelectContainer={setSelectedContainer}
        query={query}
        onQuery={setQuery}
        showErrorOnly={showErrorOnly}
        onToggleError={() => setShowErrorOnly((v) => !v)}
        showStdout={showStdout}
        onToggleStdout={() => setShowStdout((v) => !v)}
        count={filtered.length}
      />

      {/* Log list */}
      <div
        ref={listRef}
        className="scroll-thin flex-1 overflow-y-auto font-mono text-xs"
      >
        {filtered.length === 0 ? (
          <p className="px-4 py-8 text-center text-slate-600">
            {logs.length === 0 ? "Waiting for log entries…" : "No lines match the current filters."}
          </p>
        ) : (
          filtered.map((entry, i) => (
            <div
              key={i}
              className="flex gap-2 border-b border-slate-800/40 px-3 py-0.5 hover:bg-slate-800/40"
            >
              <span className="w-24 shrink-0 truncate text-slate-500" title={entry.container_id}>
                {containerName(entry.container_id)}
              </span>
              <span
                className={`w-12 shrink-0 text-center text-[10px] uppercase ${streamColor(entry.stream)}`}
              >
                {entry.stream === "stderr" ? "ERR" : "OUT"}
              </span>
              <span className={`flex-1 whitespace-pre-wrap break-all ${streamColor(entry.stream)}`}>
                {entry.line}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
