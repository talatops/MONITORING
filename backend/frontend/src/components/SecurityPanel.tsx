import { Fragment, useMemo, useState } from "react";
import type { ContainerSecurity, ImageExposure, Vulnerability } from "../types";
import {
  useSecurityOverview,
  useImageVulns,
  scanImage,
} from "../hooks/useResources";
import { ActionError, ensureAdminToken, invalidateAdminToken } from "../lib/api";

// Severity → badge class, mirroring the palette used across the UI.
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

function severityBadge(sev: string): string {
  switch (sev) {
    case "CRITICAL": return "badge-red";
    case "HIGH":     return "badge-red";
    case "MEDIUM":   return "badge-yellow";
    case "LOW":      return "badge-gray";
    default:         return "badge-gray";
  }
}

function fmtTime(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

// Expandable per-image CVE table, fetched lazily from the cached scan.
function VulnDetail({ ref, host }: { ref: string; host?: string }) {
  const { data, loading, error } = useImageVulns(ref, host);
  if (loading) return <p className="px-4 py-2 text-[11px] text-slate-500">Loading vulnerabilities…</p>;
  if (error) return <p className="px-4 py-2 text-[11px] text-red-400">{error}</p>;
  const vulns = data?.vulnerabilities ?? [];
  if (vulns.length === 0) {
    return <p className="px-4 py-2 text-[11px] text-emerald-400">No vulnerabilities reported (clean or not yet scanned).</p>;
  }
  return (
    <div className="scroll-thin max-h-64 overflow-auto px-4 py-2">
      <table className="w-full text-left text-[11px]">
        <thead className="text-[10px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="py-1 pr-3 font-medium">Severity</th>
            <th className="py-1 pr-3 font-medium">CVE</th>
            <th className="py-1 pr-3 font-medium">Package</th>
            <th className="py-1 pr-3 font-medium">Installed</th>
            <th className="py-1 font-medium">Fixed</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-surface-border text-slate-300">
          {vulns.map((v: Vulnerability) => (
            <tr key={`${v.cve_id}-${v.package}`}>
              <td className="py-1 pr-3"><span className={`badge text-[10px] ${severityBadge(v.severity)}`}>{v.severity}</span></td>
              <td className="py-1 pr-3 font-mono" title={v.title}>{v.cve_id}</td>
              <td className="py-1 pr-3">{v.package}</td>
              <td className="py-1 pr-3 tabular-nums">{v.installed_version}</td>
              <td className="py-1 tabular-nums">{v.fixed_version || <span className="text-slate-600">none</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// One risky container as a compact row of posture badges.
function RiskyRow({ c, hostName }: { c: ContainerSecurity; hostName: string }) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/40 py-1.5 text-[11px]">
      <span className="font-medium text-slate-200">{c.name || c.container_id}</span>
      <span className="text-slate-500">{hostName}</span>
      <span className="truncate text-slate-500">{c.image}</span>
      <span className="ml-auto flex flex-wrap items-center gap-1.5">
        {c.privileged && <span className="badge-red badge text-[10px]">privileged</span>}
        {c.root && <span className="badge-yellow badge text-[10px]">root</span>}
        {c.host_network && <span className="badge-red badge text-[10px]">host-net</span>}
        {c.host_pid && <span className="badge-yellow badge text-[10px]">host-pid</span>}
        {c.readonly_rootfs && <span className="badge-green badge text-[10px]">ro-rootfs</span>}
        {(c.cap_add ?? []).map((cap) => (
          <span key={cap} className="badge-gray badge text-[10px]">cap:{cap}</span>
        ))}
        {(c.exposed_ports ?? [])
          .filter((p) => p.public_port)
          .map((p, i) => (
            <span key={`${p.public_port}-${i}`} className="badge-gray badge text-[10px]">
              {p.public_port}→{p.private_port}/{p.type}
            </span>
          ))}
      </span>
    </div>
  );
}

export default function SecurityPanel() {
  const { data, loading, error, reload } = useSecurityOverview();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [scanning, setScanning] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const exposures = useMemo<ImageExposure[]>(() => data?.image_exposure ?? [], [data]);
  const risky = useMemo<ContainerSecurity[]>(() => data?.risky_containers ?? [], [data]);
  const hosts = useMemo(() => data?.hosts ?? [], [data]);

  const hostNameById = useMemo(() => {
    const m: Record<string, string> = {};
    for (const h of hosts) m[h.host_id] = h.host_name;
    return m;
  }, [hosts]);

  async function doScan(exp: ImageExposure) {
    if (scanning) return;
    if (!ensureAdminToken()) return;
    // Scan on the first host that runs the image (empty → the local hub).
    const host = exp.hosts[0] || undefined;
    setScanning(exp.ref);
    setMsg(null);
    try {
      const res = await scanImage(exp.ref, host);
      const total = res?.total ?? 0;
      setMsg(`Scanned ${exp.ref} — ${total} finding(s)${res?.total ? "" : " (clean)"}`);
      reload();
    } catch (e) {
      if (e instanceof ActionError && (e.status === 401 || e.status === 403)) invalidateAdminToken();
      if (e instanceof ActionError && e.status === 501) setMsg(`Trivy is not installed on ${host ? hostNameById[host] ?? host : "this host"}.`);
      else setMsg(`Scan failed: ${(e as Error).message}`);
    } finally {
      setScanning(null);
    }
  }

  return (
    <section className="flex flex-col gap-5">
      {loading && exposures.length === 0 && risky.length === 0 && (
        <p className="text-xs text-slate-500">Building fleet security overview…</p>
      )}
      {error && (
        <p className="text-xs text-red-400">Could not load security overview: {error}</p>
      )}

      {/* Fleet host status strip */}
      {hosts.length > 0 && (
        <div className="flex flex-wrap gap-1.5 text-[10px]">
          {hosts.map((h) => (
            <span key={h.host_id} className={h.offline ? "badge-gray badge" : "badge-green badge"}>
              {h.host_name}{h.offline ? " (unreachable)" : ` · ${h.containers.length} containers`}
            </span>
          ))}
        </div>
      )}

      {/* Section A — Fleet Image Exposure */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
            Fleet Image Exposure
          </h2>
          <button
            type="button"
            onClick={reload}
            className="rounded border border-surface-border bg-surface/60 px-2 py-1 text-xs text-slate-300 hover:bg-surface-raised"
          >
            Refresh
          </button>
        </div>
        {msg && <p className="text-[11px] text-slate-400">{msg}</p>}

        <div className="card overflow-hidden p-0">
          {exposures.length === 0 && !loading ? (
            <p className="p-4 text-xs text-slate-500">No in-use images found across the fleet.</p>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-surface/60 text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-4 py-2 font-medium">Image</th>
                  <th className="px-4 py-2 font-medium">Findings</th>
                  <th className="px-4 py-2 font-medium">Hosts</th>
                  <th className="px-4 py-2 text-right font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {exposures.map((exp) => {
                  const isOpen = expanded === exp.ref;
                  return (
                    <Fragment key={exp.ref}>
                    <tr className="align-top hover:bg-surface/40">
                      <td className="px-4 py-2">
                        <div className="font-medium text-slate-200">{exp.ref}</div>
                        {exp.scanned && (
                          <div className="text-[10px] text-slate-500">scanned {fmtTime(exp.scanned_at ?? "")}</div>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        {!exp.scanned ? (
                          <span className="badge-gray badge text-[10px]">not scanned</span>
                        ) : exp.total === 0 ? (
                          <span className="badge-green badge text-[10px]">clean</span>
                        ) : (
                          <span className="flex flex-wrap gap-1">
                            {SEVERITIES.map((s) => {
                              const n = exp.counts[s] ?? 0;
                              return n > 0 ? (
                                <button
                                  key={s}
                                  type="button"
                                  onClick={() => setExpanded(isOpen ? null : exp.ref)}
                                  className={`badge text-[10px] ${severityBadge(s)}`}
                                >
                                  {n} {s[0] + s.slice(1, 4)}
                                </button>
                              ) : null;
                            })}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-slate-400">
                        {exp.hosts.map((id) => hostNameById[id] ?? id).join(", ")}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <button
                          type="button"
                          onClick={() => doScan(exp)}
                          disabled={scanning !== null}
                          className="rounded border border-sky-500/40 bg-sky-950/40 px-2 py-0.5 text-[11px] text-sky-200 hover:bg-sky-900/40 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {scanning === exp.ref ? "Scanning…" : exp.scanned ? "Re-scan" : "Scan"}
                        </button>
                      </td>
                    </tr>
                    {isOpen && exp.scanned && (
                      <tr className="bg-surface/20">
                        <td colSpan={4} className="p-0">
                          <VulnDetail ref={exp.ref} host={exp.hosts[0] || undefined} />
                        </td>
                      </tr>
                    )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Section B — Risky Containers */}
      <div className="flex flex-col gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Risky Containers ({risky.length})
        </h2>
        <div className="card px-4 py-2">
          {risky.length === 0 ? (
            <p className="py-4 text-center text-xs text-slate-500">
              No privileged / root / cap-added / host-namespace containers found.
            </p>
          ) : (
            risky.map((c) => (
              <RiskyRow key={`${c.host_id}-${c.container_id}`} c={c} hostName={hostNameById[c.host_id] ?? c.host_name} />
            ))
          )}
        </div>
      </div>
    </section>
  );
}
