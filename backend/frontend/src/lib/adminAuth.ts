// ── Admin-token modal store ─────────────────────────────────────────────────
// A tiny framework-free external store so the non-React API layer (lib/api.ts)
// can open the "Unlock admin actions" modal and React components can subscribe
// to it. This replaces the old synchronous window.prompt with a styled modal.
//
// The store never holds the token itself — that stays in localStorage via
// lib/api.ts. It only tracks open/close + an inline error message, and hands
// the entered token back to whoever awaited requestAdminToken().

export interface AdminPromptState {
  open: boolean;
  error: string | null;
}

type Listener = (s: AdminPromptState) => void;

const listeners = new Set<Listener>();
let state: AdminPromptState = { open: false, error: null };
let resolver: ((token: string) => void) | null = null;

function emit(): void {
  for (const l of listeners) l(state);
}

// Snapshot for useSyncExternalStore — must return a stable reference while
// unchanged, so we keep a single `state` object and only replace it on change.
export function getAdminPromptState(): AdminPromptState {
  return state;
}

export function subscribeAdminPrompt(l: Listener): () => void {
  listeners.add(l);
  l(state);
  return () => {
    listeners.delete(l);
  };
}

// Resolve any pending prompt as cancelled before opening a new one, so we never
// leave a dangling promise (e.g. an action 401-reopens while one is still open).
function resetPending(): void {
  if (resolver) {
    const r = resolver;
    resolver = null;
    r("");
  }
}

/** Open the modal and resolve with the entered token ("" when cancelled). */
export function requestAdminToken(error?: string): Promise<string> {
  resetPending();
  state = { open: true, error: error ?? null };
  emit();
  return new Promise<string>((resolve) => {
    resolver = resolve;
  });
}

/** Open the modal for manual entry from the header chip (no awaiting caller). */
export function openAdminTokenDialog(error?: string): void {
  resetPending();
  state = { open: true, error: error ?? null };
  emit();
}

function finish(token: string): void {
  const r = resolver;
  resolver = null;
  state = { open: false, error: null };
  emit();
  if (r) r(token);
}

/** Called by the modal when the user submits. The token is stored by the modal. */
export function submitAdminToken(token: string): void {
  finish(token);
}

/** Called by the modal on Cancel / backdrop / Escape. */
export function cancelAdminTokenPrompt(): void {
  finish("");
}
