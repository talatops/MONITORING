import { useCallback, useEffect, useRef, useState } from "react";
import type {
  ContainerInfo,
  ContainerStatsMap,
  ContainerStatsSnapshot,
  HostMetrics,
  HostMetricsPoint,
  KernelEvent,
  LogEntry,
  TypedWSMessage,
  WSStatus,
} from "../types";
import { HOST_HISTORY_LIMIT, KERNEL_EVENT_LIMIT, LOG_BUFFER_LIMIT, WS_URL } from "../lib/constants";
import { pushToast } from "../lib/toast";

/** Live, in-memory metrics for a single host (local or remote agent). */
export interface HostBucket {
  /** Ring buffer of host metric points for charts */
  hostHistory: HostMetricsPoint[];
  /** Most recent host metrics (null before first message) */
  latestHost: HostMetrics | null;
  /** Container list from the last container_list message */
  containers: ContainerInfo[];
  /** Latest stats snapshot per container ID */
  containerStats: ContainerStatsMap;
  /** Buffered log entries (newest first) */
  logs: LogEntry[];
  /** Classified kernel events (newest first), live-only */
  kernelEvents: KernelEvent[];
}

export interface MonitorState {
  /** Connection status of the WebSocket */
  status: WSStatus;
  /** Per-host live buffers keyed by host id ("" / "local" is the hub host). */
  byHost: Record<string, HostBucket>;
}

export const emptyBucket: HostBucket = {
  hostHistory: [],
  latestHost: null,
  containers: [],
  containerStats: {},
  logs: [],
  kernelEvents: [],
};

const initialState: MonitorState = {
  status: "connecting",
  byHost: {},
};

/** Read (or lazily create) the bucket for a host id, treating empty as "local". */
function bucketFor(map: Record<string, HostBucket>, host: string | undefined): {
  key: string;
  bucket: HostBucket;
} {
  const key = host && host !== "" ? host : "local";
  const bucket = map[key] ?? emptyBucket;
  return { key, bucket };
}

/**
 * useMonitorWebSocket opens a connection to the backend WebSocket hub and keeps
 * an independent live buffer per monitored host (the local hub plus any agents).
 * Incoming frames are routed by their `host` tag, so the UI can show one host at
 * a time without mixing data.
 *
 * Reconnects automatically on errors/disconnects with exponential back-off
 * (capped at 30 s). Pass `enabled: false` to defer connecting (e.g. tests).
 */
export function useMonitorWebSocket(enabled = true) {
  const [state, setState] = useState<MonitorState>(initialState);
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── message dispatch ─────────────────────────────────────────────────────
  const handleRaw = useCallback((raw: string) => {
    let msg: TypedWSMessage;
    try {
      msg = JSON.parse(raw) as TypedWSMessage;
    } catch {
      return;
    }

    // Alerts are ephemeral notifications, not per-host live state: pop a toast
    // and stop here so they never touch the metrics buffers.
    if (msg.type === "alert") {
      const a = msg.data;
      pushToast({
        title: `${a.status === "resolved" ? "Resolved" : "Alert"} · ${a.rule_name}`,
        body: a.summary,
        tone: a.status === "resolved" ? "emerald" : a.severity === "critical" ? "red" : "amber",
      });
      return;
    }

    setState((prev) => {
      const { key, bucket } = bucketFor(prev.byHost, msg.host);
      let next: HostBucket;

      switch (msg.type) {
        case "host_metrics": {
          const m = msg.data;
          const point: HostMetricsPoint = {
            ts: new Date(m.timestamp).getTime(),
            cpu: Math.round(m.cpu_percent * 10) / 10,
            mem: Math.round(m.mem_percent * 10) / 10,
            diskRead: m.disk_read_bps,
            diskWrite: m.disk_write_bps,
            netRecv: m.net_recv_bps,
            netSent: m.net_sent_bps,
          };
          const hist = [...bucket.hostHistory, point];
          if (hist.length > HOST_HISTORY_LIMIT) hist.shift();
          next = { ...bucket, latestHost: m, hostHistory: hist };
          break;
        }

        case "container_stats": {
          const s: ContainerStatsSnapshot = msg.data;
          next = {
            ...bucket,
            containerStats: { ...bucket.containerStats, [s.container_id]: s },
          };
          break;
        }

        case "container_log": {
          const entry: LogEntry = msg.data;
          const logs = [entry, ...bucket.logs];
          if (logs.length > LOG_BUFFER_LIMIT) logs.length = LOG_BUFFER_LIMIT;
          next = { ...bucket, logs };
          break;
        }

        case "kernel_event": {
          const ev = msg.data;
          const kernelEvents = [ev, ...bucket.kernelEvents];
          if (kernelEvents.length > KERNEL_EVENT_LIMIT) kernelEvents.length = KERNEL_EVENT_LIMIT;
          next = { ...bucket, kernelEvents };
          break;
        }

        case "container_list": {
          // Prune stats for containers no longer in the list so the map stays
          // bounded across long uptime with container churn.
          const alive = new Set(msg.data.map((c) => c.id));
          const pruned: ContainerStatsMap = {};
          for (const [id, s] of Object.entries(bucket.containerStats)) {
            if (alive.has(id)) pruned[id] = s;
          }
          next = { ...bucket, containers: msg.data, containerStats: pruned };
          break;
        }

        default:
          return prev;
      }

      return { ...prev, byHost: { ...prev.byHost, [key]: next } };
    });
  }, []);

  // ── connect / reconnect ───────────────────────────────────────────────────
  const connect = useCallback(
    (isDisposed: () => boolean) => {
      if (isDisposed() || !enabled) return;

      setState((prev) => ({ ...prev, status: "connecting" }));

      try {
        const ws = new WebSocket(WS_URL);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isDisposed()) {
            ws.close();
            return;
          }
          retriesRef.current = 0;
          setState((prev) => ({ ...prev, status: "open" }));
        };

        ws.onmessage = (e: MessageEvent<string>) => {
          if (!isDisposed()) handleRaw(e.data);
        };

        ws.onerror = () => {
          if (!isDisposed()) setState((prev) => ({ ...prev, status: "error" }));
        };

        ws.onclose = () => {
          if (isDisposed()) return;
          wsRef.current = null;
          setState((prev) => ({ ...prev, status: "closed" }));
          // Exponential back-off: 1 s → 2 s → 4 s → … capped at 30 s
          const delay = Math.min(1000 * 2 ** retriesRef.current, 30_000);
          retriesRef.current += 1;
          timerRef.current = setTimeout(() => connect(isDisposed), delay);
        };
      } catch {
        if (!isDisposed()) setState((prev) => ({ ...prev, status: "error" }));
      }
    },
    [enabled, handleRaw],
  );

  useEffect(() => {
    let disposed = false;
    const isDisposed = () => disposed;

    connect(isDisposed);

    return () => {
      disposed = true;
      if (timerRef.current) clearTimeout(timerRef.current);
      const ws = wsRef.current;
      if (ws) {
        // Strip handlers so onclose doesn't trigger reconnect
        ws.onclose = null;
        ws.onerror = null;
        ws.onmessage = null;
        if (ws.readyState === WebSocket.CONNECTING) {
          // Can't close a CONNECTING socket cleanly; wait for OPEN then close
          ws.onopen = () => ws.close();
        } else {
          ws.close();
        }
        wsRef.current = null;
      }
    };
  }, [connect]);

  return state;
}
