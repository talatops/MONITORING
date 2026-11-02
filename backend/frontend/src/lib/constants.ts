/** Base path for REST API calls. The Vite proxy forwards /api → :8080. */
export const API_BASE = "/api/v1";

/**
 * WebSocket URL.
 * In dev mode: connects directly to the Go backend on :8080 (avoids Vite
 * proxy WebSocket issues). In production (embedded): uses same-origin.
 */
export const WS_URL = (() => {
  if (typeof window === "undefined") return "ws://localhost:8080/ws/stream";
  // Vite injects import.meta.env.DEV at build time
  const isDev = (import.meta as any).env?.DEV ?? false;
  const host = isDev ? "localhost:8080" : window.location.host;
  const proto = isDev ? "ws" : (window.location.protocol === "https:" ? "wss" : "ws");
  return `${proto}://${host}/ws/stream`;
})();

/** Max entries in the host metrics ring buffer for the charts. */
export const HOST_HISTORY_LIMIT = 300; // 5 minutes at 1 s interval

/** Max log lines kept in the browser before old entries are dropped. */
export const LOG_BUFFER_LIMIT = 1000;

/** Max classified kernel events kept per host in the live buffer. */
export const KERNEL_EVENT_LIMIT = 300;

/** Host-metrics chart time ranges. "live" uses the in-memory WS buffer. */
export const RANGES: { label: string; value: string }[] = [
  { label: "Live", value: "live" },
  { label: "1m", value: "1m" },
  { label: "5m", value: "5m" },
  { label: "15m", value: "15m" },
  { label: "1h", value: "1h" },
  { label: "24h", value: "24h" },
];
