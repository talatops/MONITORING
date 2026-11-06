import { useState } from "react";
import { useVolumes, removeVolume } from "../hooks/useResources";
import { ActionError, invalidateAdminToken } from "../lib/api";
import { confirmAction } from "../lib/confirm";

function fmtBytes(b: number): string {
  if (b <= 0) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

export default function VolumePanel({ host }: { host?: string }) {
  const [withSize, setWithSize] = useState(false);
  const { data, loading, error, reload } = useVolumes(host, withSize);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const rows = data ?? [];

  async function doRemove(name: string) {
    if (busy) return;
    const confirmed = await confirmAction({
      title: "Remove volume",
      message: `Remove volume "${name}"?\n\nThis force-detaches it from any running containers and deletes it.`,
      confirmLabel: "Remove",
      danger: true,
      requireAdmin: true,
    });
    if (!confirmed) return;
    setBusy(name);
    setMsg(null);
    try {
      await removeVolume(name, true, host);
      setMsg(`Removed volume ${name}`);
      reload();
    } catch (e) {
      if (e instanceof ActionError && (e.status === 401 || e.status === 403)) invalidateAdminToken(e.status);
      setMsg(`Remove failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Volumes
        </h2>
        <div className="flex items-center gap-2">
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={withSize}
              onChange={(e) => setWithSize(e.target.checked)}
              className="accent-sky-500"
            />
            Compute sizes
          </label>
          <button
            type="button"
            onClick={reload}
            className="rounded border border-surface-border bg-surface/60 px-2 py-1 text-xs text-slate-300 hover:bg-surface-raised"
          >
            Refresh
          </button>
        </div>
      </div>

      {msg && <p className="mb-2 text-[11px] text-slate-400">{msg}</p>}

      <div className="card overflow-hidden p-0">
        {loading && rows.length === 0 && (
          <p className="p-4 text-xs text-slate-500">Loading volumes…</p>
        )}
        {error && rows.length === 0 && (
          <p className="p-4 text-xs text-red-400">Could not load volumes: {error}</p>
        )}
        {!loading && rows.length === 0 && !error && (
          <p className="p-4 text-xs text-slate-500">No volumes found.</p>
        )}
        {rows.length > 0 && (
          <table className="w-full text-left text-xs">
            <thead className="bg-surface/60 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Driver</th>
                <th className="px-4 py-2 font-medium">Scope</th>
                <th className="px-4 py-2 font-medium">Used by</th>
                <th className="px-4 py-2 text-right font-medium">Size</th>
                <th className="px-4 py-2 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {rows.map((v) => (
                <tr key={v.name} className="hover:bg-surface/40">
                  <td className="px-4 py-2">
                    <div className="font-medium text-slate-200">{v.name}</div>
                    <div className="truncate text-[10px] text-slate-500" title={v.mountpoint}>
                      {v.mountpoint}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-slate-400">{v.driver}</td>
                  <td className="px-4 py-2 text-slate-400">{v.scope}</td>
                  <td className="px-4 py-2 text-slate-400">
                    {v.used_by && v.used_by.length > 0 ? (
                      <span title={v.used_by.join(", ")}>
                        {v.used_by.length} container{v.used_by.length === 1 ? "" : "s"}
                      </span>
                    ) : withSize ? (
                      <span className="text-slate-600">unused</span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums text-slate-300">
                    {v.size_computed ? fmtBytes(v.size_bytes) : withSize && loading ? "…" : "—"}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => doRemove(v.name)}
                      disabled={busy !== null}
                      className="rounded border border-red-500/40 bg-red-950/40 px-2 py-0.5 text-[11px] text-red-200 hover:bg-red-900/40 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {busy === v.name ? "Removing…" : "Remove"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {withSize && (
        <p className="mt-2 text-[10px] text-slate-500">
          Sizes are computed by reading each volume's mountpoint on the host; blank ("—")
          means the path was not accessible to the backend.
        </p>
      )}
    </section>
  );
}
