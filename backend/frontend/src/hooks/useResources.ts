import { useCallback, useEffect, useState } from "react";
import type { Topology, VolumeInfo, ImageInfo, HostInfo, ImageVulnScan, ScanSummary, SecurityOverview } from "../types";
import { API_BASE } from "../lib/constants";
import { apiAction, withHost } from "../lib/api";

interface Async<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  /** Re-fetch the current URL (e.g. after a pull/prune). */
  reload: () => void;
}

// Shared GET-with-abort hook that also exposes a manual reload. Keeps prior
// data while refetching so toggling "compute sizes" doesn't blank the table.
function useJson<T>(url: string, enabled = true): Async<T> {
  const [state, setState] = useState<{ data: T | null; loading: boolean; error: string | null }>({
    data: null,
    loading: enabled,
    error: null,
  });
  const [nonce, setNonce] = useState(0);
  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    if (!enabled) {
      setState({ data: null, loading: false, error: null });
      return;
    }
    const ctrl = new AbortController();
    setState((s) => ({ data: s.data, loading: true, error: null }));

    fetch(url, { signal: ctrl.signal })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json() as Promise<T>;
      })
      .then((payload) => setState({ data: payload, loading: false, error: null }))
      .catch((e: unknown) => {
        if ((e as Error)?.name === "AbortError") return;
        setState((s) => ({ data: s.data, loading: false, error: (e as Error)?.message ?? "failed" }));
      });

    return () => ctrl.abort();
  }, [url, enabled, nonce]);

  return { ...state, reload };
}

/** useHosts lists the local hub plus connected agents, reloaded on an interval. */
export function useHosts(refreshMs = 10000): Async<HostInfo[]> {
  const res = useJson<HostInfo[]>(`${API_BASE}/hosts`, true);
  const { reload } = res;
  useEffect(() => {
    const t = setInterval(reload, refreshMs);
    return () => clearInterval(t);
  }, [reload, refreshMs]);
  return res;
}

/** useTopology fetches the container<->network graph for one host. */
export function useTopology(host?: string, enabled = true): Async<Topology> {
  return useJson<Topology>(withHost(`${API_BASE}/networks/topology`, host), enabled);
}

/** useVolumes lists volumes; withSize adds the expensive du + usage pass. */
export function useVolumes(host?: string, withSize = false): Async<VolumeInfo[]> {
  const url = withHost(`${API_BASE}/volumes${withSize ? "?size=1" : ""}`, host);
  return useJson<VolumeInfo[]>(url);
}

/** useImages lists images on one host. */
export function useImages(host?: string): Async<ImageInfo[]> {
  return useJson<ImageInfo[]>(withHost(`${API_BASE}/images`, host));
}

/** useImageLayers fetches layer diff IDs for one image, only when enabled. */
export function useImageLayers(ref: string, host?: string, enabled = true): Async<{ ref: string; layers: string[] }> {
  return useJson<{ ref: string; layers: string[] }>(
    withHost(`${API_BASE}/images/layers?ref=${encodeURIComponent(ref)}`, host),
    enabled && ref !== "",
  );
}

// ── Mutating actions (admin token required server-side) ───────────────────────
// All of these go through apiAction, which attaches the Bearer token and host
// scoping and throws ActionError on failure so callers can re-prompt on 401/403.

export async function pullImage(ref: string, host?: string): Promise<void> {
  await apiAction("POST", `/images/pull?ref=${encodeURIComponent(ref)}`, host);
}

export async function pruneImages(host?: string): Promise<number> {
  const d = await apiAction<{ space_reclaimed_bytes?: number }>("POST", "/images/prune", host);
  return d?.space_reclaimed_bytes ?? 0;
}

export async function pruneAllImages(host?: string): Promise<number> {
  const d = await apiAction<{ space_reclaimed_bytes?: number }>("POST", "/images/pruneAll", host);
  return d?.space_reclaimed_bytes ?? 0;
}

export async function deleteImage(ref: string, force: boolean, host?: string): Promise<void> {
  await apiAction("DELETE", `/images?ref=${encodeURIComponent(ref)}${force ? "&force=1" : ""}`, host);
}

export async function removeVolume(name: string, force: boolean, host?: string): Promise<void> {
  await apiAction("DELETE", `/volumes/${encodeURIComponent(name)}${force ? "?force=1" : ""}`, host);
}

export async function containerAction(
  id: string,
  op: "start" | "stop" | "restart" | "remove",
  force: boolean,
  host?: string,
): Promise<void> {
  await apiAction("POST", `/containers/${encodeURIComponent(id)}/action?op=${op}${force ? "&force=1" : ""}`, host);
}

// ── Phase 6: image vulnerability scanning + security posture ──────────────────

/** scanImage runs Trivy on the target host for one image and caches the result. */
export async function scanImage(ref: string, host?: string): Promise<ScanSummary> {
  const r = await apiAction<ScanSummary>("POST", `/images/scan?ref=${encodeURIComponent(ref)}`, host);
  return r as ScanSummary;
}

/** useImageVulns fetches the cached CVE list for one image, only when enabled. */
export function useImageVulns(ref: string, host?: string, enabled = true): Async<ImageVulnScan> {
  return useJson<ImageVulnScan>(
    withHost(`${API_BASE}/images/vulns?ref=${encodeURIComponent(ref)}`, host),
    enabled && ref !== "",
  );
}

/** useSecurityOverview polls the fleet-wide posture + per-image exposure. */
export function useSecurityOverview(refreshMs = 30000): Async<SecurityOverview> {
  const res = useJson<SecurityOverview>(`${API_BASE}/security/overview`, true);
  const { reload } = res;
  useEffect(() => {
    const t = setInterval(reload, refreshMs);
    return () => clearInterval(t);
  }, [reload, refreshMs]);
  return res;
}
