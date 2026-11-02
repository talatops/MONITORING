import { useEffect, useState } from "react";
import type { HostMetrics, HostMetricsPoint } from "../types";
import { API_BASE } from "../lib/constants";

interface RangeHistory {
  data: HostMetricsPoint[];
  loading: boolean;
  error: string | null;
}

/** Map a persisted HostMetrics row into the chart point shape used by the UI. */
function toPoint(m: HostMetrics): HostMetricsPoint {
  return {
    ts: new Date(m.timestamp).getTime(),
    cpu: Math.round(m.cpu_percent * 10) / 10,
    mem: Math.round(m.mem_percent * 10) / 10,
    diskRead: m.disk_read_bps,
    diskWrite: m.disk_write_bps,
    netRecv: m.net_recv_bps,
    netSent: m.net_sent_bps,
  };
}

/**
 * useHostHistoryRange fetches host-metric history for a fixed trailing window
 * (e.g. "15m", "1h", "24h") from the REST API. When range is "live" it returns
 * an empty dataset and defers to the caller's WebSocket ring buffer.
 */
export function useHostHistoryRange(range: string): RangeHistory {
  const [data, setData] = useState<HostMetricsPoint[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (range === "live") {
      setData([]);
      setLoading(false);
      setError(null);
      return;
    }

    const ctrl = new AbortController();
    setLoading(true);
    setError(null);

    fetch(`${API_BASE}/host/history?range=${encodeURIComponent(range)}`, {
      signal: ctrl.signal,
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json() as Promise<HostMetrics[]>;
      })
      .then((rows) => setData((rows ?? []).map(toPoint)))
      .catch((e: unknown) => {
        if ((e as Error)?.name === "AbortError") return;
        setError((e as Error)?.message ?? "failed to load history");
      })
      .finally(() => {
        if (!ctrl.signal.aborted) setLoading(false);
      });

    return () => ctrl.abort();
  }, [range]);

  return { data, loading, error };
}
