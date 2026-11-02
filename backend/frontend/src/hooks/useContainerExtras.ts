import { useEffect, useState } from "react";
import type { ContainerCgroupStats, ContainerProcess, DiskUsageSummary } from "../types";
import { API_BASE } from "../lib/constants";
import { withHost } from "../lib/api";

interface Async<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

// Shared one-shot GET with AbortController cleanup. Returns a setter-free
// effect body so each hook can shape its own endpoint and payload type.
function useGet<T>(url: string, enabled: boolean): Async<T> {
  const [state, setState] = useState<Async<T>>({
    data: null,
    loading: enabled,
    error: null,
  });

  useEffect(() => {
    if (!enabled) {
      setState({ data: null, loading: false, error: null });
      return;
    }
    const ctrl = new AbortController();
    setState({ data: null, loading: true, error: null });

    fetch(url, { signal: ctrl.signal })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json() as Promise<T>;
      })
      .then((payload) => setState({ data: payload, loading: false, error: null }))
      .catch((e: unknown) => {
        if ((e as Error)?.name === "AbortError") return;
        setState({ data: null, loading: false, error: (e as Error)?.message ?? "failed" });
      });

    return () => ctrl.abort();
  }, [url, enabled]);

  return state;
}

/** useContainerTop fetches `docker top` for a container, only when enabled. */
export function useContainerTop(id: string, enabled: boolean, host?: string): Async<ContainerProcess> {
  return useGet<ContainerProcess>(
    withHost(`${API_BASE}/containers/${encodeURIComponent(id)}/top`, host),
    enabled && id !== "",
  );
}

/** useContainerInspect fetches the raw inspect JSON document, only when enabled. */
export function useContainerInspect(id: string, enabled: boolean, host?: string): Async<unknown> {
  return useGet<unknown>(
    withHost(`${API_BASE}/containers/${encodeURIComponent(id)}/inspect`, host),
    enabled && id !== "",
  );
}

/**
 * useContainerCgroup fetches cgroup v2 per-container detail (Linux + root only).
 * A 501 (platform unsupported) surfaces as `error`, so callers can hide the tab.
 */
export function useContainerCgroup(id: string, enabled: boolean, host?: string): Async<ContainerCgroupStats> {
  return useGet<ContainerCgroupStats>(
    withHost(`${API_BASE}/containers/${encodeURIComponent(id)}/cgroup`, host),
    enabled && id !== "",
  );
}

/**
 * useSystemDf polls the normalised `docker system df` summary on an interval.
 * The timer is cleared on unmount and each poll is abortable, so nothing leaks.
 */
export function useSystemDf(host?: string, refreshMs = 15000): Async<DiskUsageSummary> {
  const url = withHost(`${API_BASE}/system/df`, host);
  const [state, setState] = useState<Async<DiskUsageSummary>>({
    data: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    let cancelled = false;
    let ctrl: AbortController | null = null;

    const load = async () => {
      ctrl = new AbortController();
      try {
        const res = await fetch(url, { signal: ctrl.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const payload = (await res.json()) as DiskUsageSummary;
        if (!cancelled) setState({ data: payload, loading: false, error: null });
      } catch (e: unknown) {
        if ((e as Error)?.name === "AbortError" || cancelled) return;
        if (!cancelled) {
          setState((prev) => ({ data: prev.data, loading: false, error: (e as Error)?.message ?? "failed" }));
        }
      }
    };

    load();
    const timer = setInterval(load, refreshMs);
    return () => {
      cancelled = true;
      ctrl?.abort();
      clearInterval(timer);
    };
  }, [url, refreshMs]);

  return state;
}
