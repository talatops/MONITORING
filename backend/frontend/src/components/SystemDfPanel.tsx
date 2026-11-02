import { useSystemDf } from "../hooks/useContainerExtras";

function fmtBytes(b: number): string {
  if (b <= 0) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

function Row({ label, count, size, hint }: { label: string; count: number; size?: number; hint?: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded border border-surface-border bg-surface/60 px-3 py-2">
      <div className="flex flex-col">
        <span className="text-xs font-medium text-slate-200">{label}</span>
        <span className="text-[10px] text-slate-500">
          {count.toLocaleString()} item{count === 1 ? "" : "s"}
          {hint ? ` · ${hint}` : ""}
        </span>
      </div>
      <span className="shrink-0 text-sm tabular-nums text-slate-300">{size != null ? fmtBytes(size) : "—"}</span>
    </div>
  );
}

export default function SystemDfPanel({ host }: { host?: string }) {
  const { data, loading, error } = useSystemDf(host);

  return (
    <section>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-slate-400">
        Docker Disk Usage
      </h2>
      <div className="card flex flex-col gap-2">
        {loading && !data && <p className="text-xs text-slate-500">Loading disk usage…</p>}
        {error && !data && <p className="text-xs text-red-400">Could not load disk usage: {error}</p>}
        {data && (
          <>
            <Row label="Images" count={data.images_count} size={data.images_total_bytes} />
            <Row label="Containers" count={data.containers_count} size={data.containers_rw_bytes} hint="writable layer" />
            <Row label="Volumes" count={data.volumes_count} hint="size not reported by daemon" />
            <Row
              label="Build Cache"
              count={data.build_cache_count}
              size={data.build_cache_total_bytes}
              hint={data.build_cache_reclaimable_bytes > 0 ? `${fmtBytes(data.build_cache_reclaimable_bytes)} reclaimable` : undefined}
            />
          </>
        )}
      </div>
    </section>
  );
}
