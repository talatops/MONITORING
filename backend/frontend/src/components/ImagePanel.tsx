import { Fragment, useState } from "react";
import {
  useImages,
  useImageLayers,
  pullImage,
  pruneImages,
  pruneAllImages,
  deleteImage,
  scanImage,
} from "../hooks/useResources";
import { ActionError, ensureAdminToken, invalidateAdminToken } from "../lib/api";
import type { ImageInfo } from "../types";

function fmtBytes(b: number): string {
  if (b <= 0) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
}

function fmtDate(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

function primaryTag(img: ImageInfo): string {
  const t = img.repo_tags?.[0];
  if (t && t !== "<none>:<none>") return t;
  return "<none>";
}

// Handle an auth rejection by clearing the stored token so the next attempt
// re-prompts; return the human-readable message for the inline status line.
function fail(e: unknown, verb: string): string {
  if (e instanceof ActionError && (e.status === 401 || e.status === 403)) invalidateAdminToken();
  return `${verb} failed: ${(e as Error).message}`;
}

// Lazy-loads layer diff IDs only while its parent row is expanded.
function LayerList({ imageRef, host }: { imageRef: string; host?: string }) {
  const { data, loading, error } = useImageLayers(imageRef, host);
  if (loading) return <p className="px-4 py-2 text-[11px] text-slate-500">Loading layers…</p>;
  if (error) return <p className="px-4 py-2 text-[11px] text-red-400">{error}</p>;
  const layers = data?.layers ?? [];
  return (
    <ol className="flex flex-col gap-1 px-4 py-2">
      {layers.map((l, i) => (
        <li key={l} className="flex items-center gap-2 text-[11px] text-slate-400">
          <span className="w-6 shrink-0 text-right text-slate-600">{i + 1}</span>
          <span className="truncate font-mono" title={l}>
            {l}
          </span>
        </li>
      ))}
    </ol>
  );
}

export default function ImagePanel({ host }: { host?: string }) {
  const { data, loading, error, reload } = useImages(host);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [ref, setRef] = useState("");
  const [busy, setBusy] = useState<null | "pull" | "prune" | "pruneAll" | string>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const rows = data ?? [];

  async function doPull() {
    const r = ref.trim();
    if (!r || busy) return;
    if (!window.confirm(`Pull image "${r}"?\n\nThis contacts the registry and downloads layers.`)) return;
    if (!ensureAdminToken()) return;
    setBusy("pull");
    setMsg(null);
    try {
      await pullImage(r, host);
      setMsg(`Pulled ${r}`);
      setRef("");
      reload();
    } catch (e) {
      setMsg(fail(e, "Pull"));
    } finally {
      setBusy(null);
    }
  }

  async function doPrune(all: boolean) {
    if (busy) return;
    const ok = window.confirm(
      all
        ? "Prune ALL unused images (not just dangling)?\n\nThis removes every image not referenced by a container."
        : "Prune dangling (untagged) images?\n\nOnly unreferenced image layers are removed.",
    );
    if (!ok) return;
    if (!ensureAdminToken()) return;
    setBusy(all ? "pruneAll" : "prune");
    setMsg(null);
    try {
      const reclaimed = all ? await pruneAllImages(host) : await pruneImages(host);
      setMsg(`Prune complete — reclaimed ${fmtBytes(reclaimed)}`);
      reload();
    } catch (e) {
      setMsg(fail(e, "Prune"));
    } finally {
      setBusy(null);
    }
  }

  async function doDelete(img: ImageInfo) {
    const target = primaryTag(img) !== "<none>" ? primaryTag(img) : img.id;
    if (busy) return;
    if (!window.confirm(`Delete image "${target}"?\n\nA forced removal also deletes children/tags using it.`)) return;
    if (!ensureAdminToken()) return;
    setBusy(img.id);
    setMsg(null);
    try {
      await deleteImage(img.id, true, host);
      setMsg(`Deleted ${target}`);
      reload();
    } catch (e) {
      setMsg(fail(e, "Delete"));
    } finally {
      setBusy(null);
    }
  }

  async function doScan(img: ImageInfo) {
    const target = primaryTag(img) !== "<none>" ? primaryTag(img) : img.id;
    if (busy || target === "<none>") return;
    if (!ensureAdminToken()) return;
    setBusy(`scan-${img.id}`);
    setMsg(null);
    try {
      const res = await scanImage(target, host);
      setMsg(`Scanned ${target} — ${res?.total ?? 0} finding(s)`);
    } catch (e) {
      if (e instanceof ActionError && (e.status === 401 || e.status === 403)) invalidateAdminToken();
      if (e instanceof ActionError && e.status === 501) setMsg("Trivy is not installed on this host.");
      else setMsg(fail(e, "Scan"));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Images
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={ref}
            onChange={(e) => setRef(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doPull()}
            placeholder="image:tag to pull"
            className="w-52 rounded border border-surface-border bg-surface/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-sky-500"
          />
          <button
            type="button"
            onClick={doPull}
            disabled={busy !== null || ref.trim() === ""}
            className="rounded border border-sky-500/40 bg-sky-950/40 px-2 py-1 text-xs text-sky-200 hover:bg-sky-900/40 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy === "pull" ? "Pulling…" : "Pull"}
          </button>
          <button
            type="button"
            onClick={() => doPrune(false)}
            disabled={busy !== null}
            className="rounded border border-amber-500/40 bg-amber-950/40 px-2 py-1 text-xs text-amber-200 hover:bg-amber-900/40 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy === "prune" ? "Pruning…" : "Prune dangling"}
          </button>
          <button
            type="button"
            onClick={() => doPrune(true)}
            disabled={busy !== null}
            className="rounded border border-red-500/40 bg-red-950/40 px-2 py-1 text-xs text-red-200 hover:bg-red-900/40 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy === "pruneAll" ? "Pruning…" : "Prune all"}
          </button>
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
          <p className="p-4 text-xs text-slate-500">Loading images…</p>
        )}
        {error && rows.length === 0 && (
          <p className="p-4 text-xs text-red-400">Could not load images: {error}</p>
        )}
        {!loading && rows.length === 0 && !error && (
          <p className="p-4 text-xs text-slate-500">No images found.</p>
        )}
        {rows.length > 0 && (
          <table className="w-full text-left text-xs">
            <thead className="bg-surface/60 text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-2 font-medium">Repository : Tag</th>
                <th className="px-4 py-2 font-medium">Created</th>
                <th className="px-4 py-2 text-right font-medium">Size</th>
                <th className="px-4 py-2 text-right font-medium">Layers</th>
                <th className="px-4 py-2 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {rows.map((img) => {
                const isOpen = expanded === img.id;
                return (
                  <Fragment key={img.id}>
                    <tr className="hover:bg-surface/40">
                      <td className="px-4 py-2">
                        <div className="font-medium text-slate-200">{primaryTag(img)}</div>
                        <div className="truncate text-[10px] text-slate-500" title={img.id}>
                          {img.id}
                        </div>
                      </td>
                      <td className="px-4 py-2 text-slate-400">{fmtDate(img.created)}</td>
                      <td className="px-4 py-2 text-right tabular-nums text-slate-300">
                        {fmtBytes(img.size_bytes)}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <button
                          type="button"
                          onClick={() => setExpanded(isOpen ? null : img.id)}
                          className="rounded border border-surface-border bg-surface/60 px-2 py-0.5 text-[11px] text-slate-300 hover:bg-surface-raised"
                        >
                          {isOpen ? "Hide" : "Show"}
                        </button>
                      </td>
                      <td className="px-4 py-2 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => doScan(img)}
                            disabled={busy !== null || primaryTag(img) === "<none>"}
                            className="rounded border border-sky-500/40 bg-sky-950/40 px-2 py-0.5 text-[11px] text-sky-200 hover:bg-sky-900/40 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {busy === `scan-${img.id}` ? "Scanning…" : "Scan"}
                          </button>
                          <button
                            type="button"
                            onClick={() => doDelete(img)}
                            disabled={busy !== null}
                            className="rounded border border-red-500/40 bg-red-950/40 px-2 py-0.5 text-[11px] text-red-200 hover:bg-red-900/40 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {busy === img.id ? "Deleting…" : "Delete"}
                          </button>
                        </div>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr key={`${img.id}-layers`} className="bg-surface/20">
                        <td colSpan={5} className="p-0">
                          <LayerList imageRef={img.id} host={host} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
