// ── Transient toast store ─────────────────────────────────────────────────────
// Framework-free external store (mirrors lib/confirm.ts) so the WebSocket pump
// can push a notification from outside React. Components subscribe to the list
// and render it; each toast auto-dismisses after a few seconds.

export type ToastTone = "red" | "amber" | "emerald" | "slate";

export interface Toast {
  id: string;
  title: string;
  body: string;
  tone: ToastTone;
}

type Listener = (t: Toast[]) => void;

let toasts: Toast[] = [];
const listeners = new Set<Listener>();

function emit(): void {
  for (const l of listeners) l(toasts);
}

export function subscribeToasts(l: Listener): () => void {
  listeners.add(l);
  l(toasts);
  return () => {
    listeners.delete(l);
  };
}

function uid(): string {
  const c = globalThis.crypto;
  if (c && "randomUUID" in c) return c.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function dismissToast(id: string): void {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

/** Show a toast (kept for at most `ttlMs`, default 8 s). Caps the stack to 5. */
export function pushToast(toast: Omit<Toast, "id">, ttlMs = 8000): void {
  const t: Toast = { ...toast, id: uid() };
  toasts = [t, ...toasts].slice(0, 5);
  emit();
  setTimeout(() => dismissToast(t.id), ttlMs);
}
