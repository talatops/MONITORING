import { useEffect, useState } from "react";
import { subscribeToasts, dismissToast, type Toast, type ToastTone } from "../lib/toast";

const toneCls: Record<ToastTone, string> = {
  red:     "border-red-500/40     bg-red-950/80     text-red-100",
  amber:   "border-amber-500/40   bg-amber-950/80   text-amber-100",
  emerald: "border-emerald-500/40 bg-emerald-950/80 text-emerald-100",
  slate:   "border-surface-border bg-surface-raised text-slate-100",
};

/** Fixed top-right stack of transient alert toasts (driven by lib/toast store). */
export default function ToastHost() {
  const [items, setItems] = useState<Toast[]>([]);
  useEffect(() => subscribeToasts(setItems), []);

  if (items.length === 0) return null;
  return (
    <div className="fixed right-4 top-4 z-50 flex w-80 flex-col gap-2">
      {items.map((t) => (
        <div
          key={t.id}
          className={`rounded-lg border px-3 py-2 text-xs shadow-lg backdrop-blur ${toneCls[t.tone]}`}
        >
          <div className="flex items-start justify-between gap-2">
            <span className="font-semibold">{t.title}</span>
            <button
              type="button"
              onClick={() => dismissToast(t.id)}
              className="shrink-0 opacity-60 transition-opacity hover:opacity-100"
              aria-label="Dismiss"
            >
              ✕
            </button>
          </div>
          <p className="mt-0.5 text-[11px] opacity-90">{t.body}</p>
        </div>
      ))}
    </div>
  );
}
