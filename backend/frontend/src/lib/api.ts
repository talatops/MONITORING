import { API_BASE } from "./constants";

// ── Admin token (localStorage) ────────────────────────────────────────────────
// Mutating endpoints (pull/prune/delete/start/stop/…) require a Bearer token
// when the server was started with -admin-token. We keep it in localStorage so
// it survives reloads; the UI prompts for it the first time an action needs it.

const TOKEN_KEY = "monitor.adminToken";

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
}

/** Authorization headers for a mutating call (empty when no token is set). */
export function authHeaders(): Record<string, string> {
  const t = getAdminToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

/**
 * Return the stored admin token, prompting once if none is set. Returning an
 * empty string means the user cancelled — callers should abort the action then.
 */
export function ensureAdminToken(): string {
  const existing = getAdminToken();
  if (existing) return existing;
  const entered = window.prompt(
    "This action needs the admin access token (the server's -admin-token).\n\nEnter it below, or leave blank to cancel.",
  );
  const token = (entered ?? "").trim();
  if (token) setAdminToken(token);
  return token;
}

/** Clear a now-invalid token so the next action re-prompts. */
export function invalidateAdminToken(): void {
  setAdminToken("");
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
): Promise<T | null> {
  const res = await fetch(withHost(`${API_BASE}${path}`, host), {
    method,
    headers: authHeaders(),
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
