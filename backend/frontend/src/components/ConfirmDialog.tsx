import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { subscribeConfirm, getConfirmState, resolveConfirm } from "../lib/confirm";
import { getAdminToken, setAdminToken } from "../lib/api";

// Stable subscribe reference so useSyncExternalStore does not re-subscribe each
// render. React's callback takes no args; the store passes state, which is fine.
const subscribe = (cb: () => void) => subscribeConfirm(cb);

// ── Styled destructive-action confirmation card ──────────────────────────────
// Replaces window.confirm. When the action needs the admin token and none is
// stored, it shows an inline token field so confirmation + unlock happen in one
// card. Resolves the awaiting confirmAction() with true/false.

export default function ConfirmDialog() {
  const { open, opts } = useSyncExternalStore(subscribe, getConfirmState, getConfirmState);
  const [token, setToken] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const needsToken = !!opts?.requireAdmin && !getAdminToken();

  // Reset local field each time a dialog opens.
  useEffect(() => {
    if (!open) return;
    setToken("");
    setErr(null);
    if (needsToken) {
      const id = requestAnimationFrame(() => inputRef.current?.focus());
      return () => cancelAnimationFrame(id);
    }
  }, [open, needsToken]);

  // Escape cancels.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") resolveConfirm(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  if (!open || !opts) return null;

  const confirmLabel = opts.confirmLabel ?? "Confirm";
  const cancelLabel = opts.cancelLabel ?? "Cancel";

  function confirm() {
    if (needsToken) {
      const t = token.trim();
      if (!t) {
        setErr("Enter the admin token to continue.");
        return;
      }
      setAdminToken(t);
    }
    resolveConfirm(true);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={() => resolveConfirm(false)} />

      {/* Panel */}
      <div className="card relative z-10 flex w-full max-w-md flex-col gap-4 p-5">
        <div className="flex items-center gap-2">
          <span aria-hidden className={`text-lg leading-none ${opts.danger ? "" : "hidden"}`}>⚠️</span>
          <h2 className="text-sm font-semibold text-slate-100">{opts.title}</h2>
        </div>

        <p className="whitespace-pre-line text-xs leading-relaxed text-slate-400">{opts.message}</p>

        {needsToken && (
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Admin token
            </label>
            <input
              ref={inputRef}
              type="password"
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                setErr(null);
              }}
              placeholder="changeme"
              autoComplete="off"
              spellCheck={false}
              className="rounded border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-500"
            />
            {err && <p className="text-xs text-red-400">{err}</p>}
          </div>
        )}

        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={() => resolveConfirm(false)}
            className="rounded border border-surface-border bg-surface/60 px-3 py-1.5 text-xs text-slate-300 hover:bg-surface-raised"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={confirm}
            className={`rounded px-3 py-1.5 text-xs ${
              opts.danger
                ? "border border-red-500/40 bg-red-950/40 text-red-200 hover:bg-red-900/40"
                : "border border-sky-500/40 bg-sky-950/40 text-sky-200 hover:bg-sky-900/40"
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
