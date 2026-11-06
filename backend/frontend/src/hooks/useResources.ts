import { useCallback, useEffect, useState } from "react";
import type { Topology, VolumeInfo, ImageInfo, HostInfo, ImageVulnScan, ScanSummary, SecurityOverview, ScanTrend, AlertRule, AlertChannel, Alert, SMTPSettings } from "../types";
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

/** useImageHistory returns counts-only trend points for one image (oldest-first). */
export function useImageHistory(ref: string, host?: string, enabled = true): Async<ScanTrend[]> {
  return useJson<ScanTrend[]>(
    withHost(`${API_BASE}/images/history?ref=${encodeURIComponent(ref)}`, host),
    enabled && ref !== "",
  );
}

/** sbomDownloadURL builds a direct download URL for an image SBOM. */
export function sbomDownloadURL(ref: string, format: "cyclonedx" | "spdx", host?: string): string {
  return withHost(
    `${API_BASE}/images/sbom?ref=${encodeURIComponent(ref)}&format=${format}`,
    host,
  );
}

/** securityReportURL builds a direct download URL for the fleet report. */
export function securityReportURL(format: "csv" | "json"): string {
  return `${API_BASE}/security/report?format=${format}`;
}

// ── Phase 8: alerting — rules, channels, history, and delivery actions ────────
// Alert config lives on the hub (not per-agent), so these paths are not
// host-scoped. Reads poll the local SQLite-backed endpoints; mutations go
// through apiAction with the admin bearer token.

/** useAlertRules lists configured alert rules. */
export function useAlertRules(refreshMs = 20000): Async<AlertRule[]> {
  const res = useJson<AlertRule[]>(`${API_BASE}/alerts/rules`, true);
  const { reload } = res;
  useEffect(() => {
    const t = setInterval(reload, refreshMs);
    return () => clearInterval(t);
  }, [reload, refreshMs]);
  return res;
}

/** useAlertChannels lists configured delivery channels. */
export function useAlertChannels(refreshMs = 20000): Async<AlertChannel[]> {
  const res = useJson<AlertChannel[]>(`${API_BASE}/alerts/channels`, true);
  const { reload } = res;
  useEffect(() => {
    const t = setInterval(reload, refreshMs);
    return () => clearInterval(t);
  }, [reload, refreshMs]);
  return res;
}

/** useAlerts polls firing/resolved alert history. */
export function useAlerts(status = "", limit = 100, refreshMs = 15000): Async<Alert[]> {
  const qs = new URLSearchParams();
  if (status) qs.set("status", status);
  if (limit) qs.set("limit", String(limit));
  const q = qs.toString();
  const res = useJson<Alert[]>(`${API_BASE}/alerts${q ? `?${q}` : ""}`, true);
  const { reload } = res;
  useEffect(() => {
    const t = setInterval(reload, refreshMs);
    return () => clearInterval(t);
  }, [reload, refreshMs]);
  return res;
}

export async function saveAlertRule(rule: AlertRule): Promise<AlertRule> {
  const r = await apiAction<AlertRule>("POST", "/alerts/rules", undefined, rule);
  return r as AlertRule;
}

export async function deleteAlertRule(id: string): Promise<void> {
  await apiAction("DELETE", `/alerts/rules/${encodeURIComponent(id)}`);
}

export async function saveAlertChannel(ch: AlertChannel): Promise<AlertChannel> {
  const r = await apiAction<AlertChannel>("POST", "/alerts/channels", undefined, ch);
  return r as AlertChannel;
}

export async function deleteAlertChannel(id: string): Promise<void> {
  await apiAction("DELETE", `/alerts/channels/${encodeURIComponent(id)}`);
}

export async function testAlertChannel(channelId: string): Promise<void> {
  await apiAction("POST", "/alerts/test", undefined, { channel_id: channelId });
}

/** useSMTPSettings reads the effective SMTP config (password never returned). */
export function useSMTPSettings(): Async<SMTPSettings> {
  return useJson<SMTPSettings>(`${API_BASE}/alerts/smtp`, true);
}

export async function saveSMTPSettings(s: SMTPSettings): Promise<SMTPSettings> {
  const r = await apiAction<SMTPSettings>("POST", "/alerts/smtp", undefined, s);
  return r as SMTPSettings;
}

/** testSMTP sends a one-off test email to `to` using the saved SMTP settings. */
export async function testSMTP(to: string): Promise<void> {
  await apiAction("POST", "/alerts/smtp/test", undefined, { to });
}

export async function ackAlert(id: string, note: string): Promise<void> {
  await apiAction("POST", `/alerts/${encodeURIComponent(id)}/ack`, undefined, { note });
}

export async function resolveAlert(id: string): Promise<void> {
  await apiAction("POST", `/alerts/${encodeURIComponent(id)}/resolve`, undefined, {});
}
