// ── Destructive-action confirmation modal store ─────────────────────────────
// Framework-free external store so any component can `await confirmAction({...})`
// instead of the native window.confirm. When `requireAdmin` is set and the
// session is locked, the dialog also collects the admin token inline — so a
// single card handles "confirm delete" + "unlock admin" together.

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  /** Show an inline admin-token field when no token is stored yet. */
  requireAdmin?: boolean;
}

export interface ConfirmState {
  open: boolean;
  opts: ConfirmOptions | null;
}

type Listener = (s: ConfirmState) => void;

const listeners = new Set<Listener>();
let state: ConfirmState = { open: false, opts: null };
let resolver: ((ok: boolean) => void) | null = null;

function emit(): void {
  for (const l of listeners) l(state);
}

export function getConfirmState(): ConfirmState {
  return state;
}

export function subscribeConfirm(l: Listener): () => void {
  listeners.add(l);
  l(state);
  return () => {
    listeners.delete(l);
  };
}

function resetPending(): void {
  if (resolver) {
    const r = resolver;
    resolver = null;
    r(false);
  }
}

/** Open the confirm dialog and resolve true (confirmed) / false (cancelled). */
export function confirmAction(opts: ConfirmOptions): Promise<boolean> {
  resetPending();
  state = { open: true, opts };
  emit();
  return new Promise<boolean>((resolve) => {
    resolver = resolve;
  });
}

function finish(ok: boolean): void {
  const r = resolver;
  resolver = null;
  state = { open: false, opts: null };
  emit();
  if (r) r(ok);
}

export function resolveConfirm(ok: boolean): void {
  finish(ok);
}
