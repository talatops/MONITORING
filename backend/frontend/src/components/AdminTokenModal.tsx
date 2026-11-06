import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import {
  subscribeAdminPrompt,
  getAdminPromptState,
  submitAdminToken,
  cancelAdminTokenPrompt,
  openAdminTokenDialog,
} from "../lib/adminAuth";
import { getAdminToken, setAdminToken, onAdminTokenChange } from "../lib/api";

// ── "Unlock admin actions" modal ─────────────────────────────────────────────
// Replaces the old window.prompt. Driven by the adminAuth external store so the
// non-React API layer can open it and await the entered token. The token lives
// in localStorage (via setAdminToken); this component only collects + validates.

// Stable subscribe reference so useSyncExternalStore does not re-subscribe each
// render. React's callback takes no args; the store passes state, which is fine.
const subscribePrompt = (cb: () => void) => subscribeAdminPrompt(cb);

export default function AdminTokenModal() {
  const state = useSyncExternalStore(subscribePrompt, getAdminPromptState, getAdminPromptState);
  const [value, setValue] = useState("");
  const [localErr, setLocalErr] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // On open: prefill any stored token, clear local error, focus the field.
  useEffect(() => {
    if (!state.open) return;
    setValue(getAdminToken());
    setLocalErr(null);
    const id = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(id);
  }, [state.open]);

  // Escape closes the modal (treated as cancel).
  useEffect(() => {
    if (!state.open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") cancelAdminTokenPrompt();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [state.open]);

  if (!state.open) return null;
  const error = state.error ?? localErr;

  function submit() {
    const t = value.trim();
    if (!t) {
      setLocalErr("Enter the admin token, or Cancel to abort.");
      return;
    }
    setAdminToken(t);
    submitAdminToken(t);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={cancelAdminTokenPrompt} />

      {/* Panel */}
      <div className="card relative z-10 flex w-full max-w-md flex-col gap-4 p-5">
        <div className="flex items-center gap-2">
          <span aria-hidden className="text-lg leading-none">🔒</span>
          <h2 className="text-sm font-semibold text-slate-100">Unlock admin actions</h2>
        </div>

        <p className="text-xs leading-relaxed text-slate-400">
          This action needs the server&rsquo;s admin access token (the <code className="rounded bg-surface-raised px-1 text-slate-300">-admin-token</code> value).
          It is stored in your browser, so you are only asked once.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
          className="flex flex-col gap-3"
        >
          <input
            ref={inputRef}
            type="password"
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              setLocalErr(null);
            }}
            placeholder="Admin token"
            autoComplete="off"
            spellCheck={false}
            className="rounded border border-surface-border bg-surface px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-500"
          />

          {error && <p className="text-xs text-red-400">{error}</p>}

          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={cancelAdminTokenPrompt}
              className="rounded border border-surface-border bg-surface/60 px-3 py-1.5 text-xs text-slate-300 hover:bg-surface-raised"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="rounded border border-sky-500/40 bg-sky-950/40 px-3 py-1.5 text-xs text-sky-200 hover:bg-sky-900/40"
            >
              Unlock
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Header lock/unlock chip ──────────────────────────────────────────────────
// Shows the current session state and lets the user set/change the token without
// triggering an action. Reflects token changes via the api.ts broadcast event.

export function AdminLockChip() {
  const [unlocked, setUnlocked] = useState(() => !!getAdminToken());

  useEffect(() => {
    const sync = () => setUnlocked(!!getAdminToken());
    sync();
    return onAdminTokenChange(sync);
  }, []);

  // Toggle: unlocked → lock (clear the token so actions re-ask); locked → open
  // the token modal to unlock.
  function onClick() {
    if (unlocked) setAdminToken("");
    else openAdminTokenDialog();
  }

  return (
    <button
      type="button"
      onClick={onClick}
      title={
        unlocked
          ? "Admin actions unlocked — click to lock"
          : "Locked — click to enter the admin token"
      }
      className={`badge cursor-pointer select-none ${unlocked ? "badge-green" : "badge-gray"}`}
    >
      <span aria-hidden>{unlocked ? "🔓" : "🔒"}</span>
      {unlocked ? " Admin" : " Locked"}
    </button>
  );
}
