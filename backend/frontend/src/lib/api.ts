import { API_BASE } from "./constants";
import { requestAdminToken } from "./adminAuth";

// ── Admin token (localStorage) ────────────────────────────────────────────────
// Mutating endpoints (pull/prune/delete/start/stop/…) require a Bearer token
// when the server was started with -admin-token. We keep it in localStorage so
// it survives reloads; the UI opens a styled modal (see AdminTokenModal) the
// first time an action needs it, instead of the old window.prompt.

const TOKEN_KEY = "monitor.adminToken";

// Broadcast so the header lock/unlock chip re-renders whenever the token changes.
const TOKEN_EVENT = "monitor:admin-token";

export function getAdminToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setAdminToken(token: string): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode) — actions will just 401 */
  }
  window.dispatchEvent(new Event(TOKEN_EVENT));
}

/** Subscribe to admin-token changes; returns an unsubscribe function. */
export function onAdminTokenChange(cb: () => void): () => void {
  window.addEventListener(TOKEN_EVENT, cb);
  return () => window.removeEventListener(TOKEN_EVENT, cb);
}

/** Authorization headers for a mutating call (empty when no token is set). */
export function authHeaders(): Record<string, string> {
  const t = getAdminToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

/**
 * Return the stored admin token, opening the modal to collect one if none is
 * set. Resolves to an empty string when the user cancels — callers must abort
 * the action then. The modal persists the token itself, so we just await it.
 */
export async function ensureAdminToken(): Promise<string> {
  const existing = getAdminToken();
  if (existing) return existing;
  return (await requestAdminToken()).trim();
}

/**
 * Clear a now-invalid token so the next action re-prompts. When the server
 * rejected the token (401) we immediately reopen the modal with an inline error
 * so the user can correct it; 403 means actions are disabled server-side, so we
 * stay quiet (no token would ever work).
 */
export function invalidateAdminToken(status?: number): void {
  setAdminToken("");
  if (status === 401) {
    requestAdminToken("That token was rejected by the server. Please try again.");
  }
}

// ── Host scoping ───────────────────────────────────────────────────────────────

/** Append `?host=<id>` (or `&host=`) so a request targets a specific host. */
export function withHost(path: string, host?: string): string {
  if (!host) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}host=${encodeURIComponent(host)}`;
}

/** A failed mutating call carrying the HTTP status so callers can distinguish
 *  401/403 (re-prompt for token) from other errors. */
export class ActionError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ActionError";
    this.status = status;
  }
}

/**
 * Issue a mutating request (POST/DELETE) against the API with the admin bearer
 * token and host scoping applied. Resolves with parsed JSON (or null when the
 * response body is empty). Throws ActionError on a non-2xx status.
 */
export async function apiAction<T = unknown>(
  method: "POST" | "DELETE",
  path: string,
  host?: string,
  body?: unknown,
): Promise<T | null> {
  const headers: Record<string, string> = { ...authHeaders() };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(withHost(`${API_BASE}${path}`, host), {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) detail = body.error;
    } catch {
      /* non-JSON error body */
    }
    throw new ActionError(detail, res.status);
  }
  if (res.status === 204) return null;
  const text = await res.text();
  return (text ? (JSON.parse(text) as T) : null) as T | null;
}
