import { useEffect, useMemo, useState } from "react";
import {
  useAlertRules,
  useAlertChannels,
  useAlerts,
  saveAlertRule,
  deleteAlertRule,
  saveAlertChannel,
  deleteAlertChannel,
  testAlertChannel,
  useSMTPSettings,
  saveSMTPSettings,
  testSMTP,
  ackAlert,
  resolveAlert,
} from "../hooks/useResources";
import { ActionError, ensureAdminToken, invalidateAdminToken } from "../lib/api";
import { confirmAction } from "../lib/confirm";
import type { Alert, AlertChannel, AlertRule } from "../types";

// ── small helpers ─────────────────────────────────────────────────────────────

// Clear the stored token on an auth rejection so the next attempt re-prompts;
// return a human-readable message for the inline status line.
function fail(e: unknown, verb: string): string {
  if (e instanceof ActionError && (e.status === 401 || e.status === 403)) invalidateAdminToken(e.status);
  return `${verb} failed: ${(e as Error).message}`;
}

function fmtTime(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function sevClass(sev: string): string {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "badge-red";
  if (s === "warning") return "badge-yellow";
  return "badge-gray";
}

function statusClass(status: string): string {
  return status === "firing" ? "badge-red" : "badge-green";
}

interface DeliveryEntry {
  name: string;
  status: string;
  attempts: number;
  error?: string;
}

// parseDelivery reads Alert.notified (JSON map of channel -> result) into rows.
function parseDelivery(a: Alert): DeliveryEntry[] {
  if (!a.notified) return [];
  try {
    const m = JSON.parse(a.notified) as Record<string, Partial<DeliveryEntry> | string>;
    return Object.entries(m).map(([name, v]) => {
      // tolerate the legacy string form ("ok" / "error: …") as well as the object.
      if (typeof v === "string") {
        return { name, status: v.startsWith("error") ? "error" : "ok", attempts: 1, error: v.startsWith("error") ? v : undefined };
      }
      return { name, status: v.status ?? "ok", attempts: v.attempts ?? 1, error: v.error };
    });
  } catch {
    return [];
  }
}

// delivery renders a compact one-line summary of the notification result.
function delivery(a: Alert): string {
  const rows = parseDelivery(a);
  if (rows.length === 0) return a.notified || "—";
  return rows.map((r) => `${r.name}: ${r.status}${r.attempts > 1 ? ` (${r.attempts})` : ""}`).join(", ");
}

const blankChannel = (): AlertChannel => ({
  id: "",
  name: "",
  kind: "webhook",
  enabled: true,
  url: "",
  to: "",
});

const blankRule = (): AlertRule => ({
  id: "",
  name: "",
  enabled: true,
  type: "host",
  metric: "cpu",
  op: ">",
  threshold: 90,
  for_seconds: 300,
  severity: "warning",
  event_kinds: ["exit", "oom"],
  min_severity: "CRITICAL",
  count_threshold: 1,
  cooldown_seconds: 600,
  channel_ids: [],
});

// Shared field styles keep the forms visually consistent with other panels.
const inputCls =
  "w-full rounded border border-surface-border bg-surface/60 px-2 py-1 text-xs text-slate-200 outline-none focus:border-sky-500";
const labelCls = "mb-1 block text-[10px] font-medium uppercase tracking-wider text-slate-500";
const btnBase =
  "rounded border px-2 py-1 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50";
const btnSky = `${btnBase} border-sky-500/40 bg-sky-950/40 text-sky-200 hover:bg-sky-900/40`;
const btnGhost = `${btnBase} border-surface-border bg-surface/60 text-slate-300 hover:bg-surface-raised`;
const btnRed = `${btnBase} border-red-500/40 bg-red-950/40 text-red-200 hover:bg-red-900/40`;

// ── Channels ──────────────────────────────────────────────────────────────────

function ChannelsSection({
  channels,
  loading,
  error,
  reload,
  notify,
}: {
  channels: AlertChannel[];
  loading: boolean;
  error: string | null;
  reload: () => void;
  notify: (msg: string) => void;
}) {
  const [draft, setDraft] = useState<AlertChannel>(blankChannel());
  const [busy, setBusy] = useState<null | string>(null);

  const isEmail = draft.kind === "email";

  async function submit() {
    if (busy) return;
    if (!draft.name.trim()) {
      notify("Channel name is required");
      return;
    }
    if (!(await ensureAdminToken())) return;
    setBusy("save");
    try {
      const saved = await saveAlertChannel(draft);
      notify(`Saved channel “${saved.name}”`);
      setDraft(blankChannel());
      reload();
    } catch (e) {
      notify(fail(e, "Save channel"));
    } finally {
      setBusy(null);
    }
  }

  async function toggle(c: AlertChannel) {
    if (!(await ensureAdminToken())) return;
    setBusy(c.id);
    try {
      await saveAlertChannel({ ...c, enabled: !c.enabled });
      reload();
    } catch (e) {
      notify(fail(e, "Toggle channel"));
    } finally {
      setBusy(null);
    }
  }

  async function test(c: AlertChannel) {
    if (!(await ensureAdminToken())) return;
    setBusy(c.id);
    try {
      await testAlertChannel(c.id);
      notify(`Test alert sent to “${c.name}”`);
    } catch (e) {
      notify(fail(e, "Test"));
    } finally {
      setBusy(null);
    }
  }

  async function remove(c: AlertChannel) {
    const ok = await confirmAction({
      title: "Delete channel",
      message: `Delete delivery channel “${c.name}”?\n\nRules targeting it will fall back to all enabled channels.`,
      confirmLabel: "Delete",
      danger: true,
      requireAdmin: true,
    });
    if (!ok) return;
    setBusy(c.id);
    try {
      await deleteAlertChannel(c.id);
      notify(`Deleted channel “${c.name}”`);
      reload();
    } catch (e) {
      notify(fail(e, "Delete channel"));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-slate-400">
        Notification Channels
      </h2>

      <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div>
          <label className={labelCls}>Name</label>
          <input
            className={inputCls}
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder="Ops Slack"
          />
        </div>
        <div>
          <label className={labelCls}>Kind</label>
          <select
            className={inputCls}
            value={draft.kind}
            onChange={(e) => setDraft({ ...draft, kind: e.target.value })}
          >
            <option value="webhook">Webhook</option>
            <option value="slack">Slack</option>
            <option value="email">Email</option>
          </select>
        </div>
        <div className={isEmail ? "" : "sm:col-span-2"}>
          <label className={labelCls}>{isEmail ? "Recipients" : "URL"}</label>
          <input
            className={inputCls}
            value={isEmail ? draft.to ?? "" : draft.url ?? ""}
            onChange={(e) =>
              setDraft(isEmail ? { ...draft, to: e.target.value } : { ...draft, url: e.target.value })
            }
            placeholder={isEmail ? "oncall@example.com" : "https://…"}
          />
        </div>
      </div>

      <button type="button" onClick={submit} disabled={busy !== null} className={btnSky}>
        {busy === "save" ? "Saving…" : "Add channel"}
      </button>

      <div className="mt-3 divide-y divide-surface-border">
        {loading && channels.length === 0 && <p className="py-2 text-xs text-slate-500">Loading channels…</p>}
        {error && channels.length === 0 && <p className="py-2 text-xs text-red-400">{error}</p>}
        {!loading && channels.length === 0 && !error && (
          <p className="py-2 text-xs text-slate-500">No channels configured yet.</p>
        )}
        {channels.map((c) => (
          <div key={c.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="truncate text-xs font-medium text-slate-200">{c.name}</span>
                <span className="badge-gray badge">{c.kind}</span>
                {!c.enabled && <span className="badge-gray badge">disabled</span>}
              </div>
              <div className="truncate text-[10px] text-slate-500" title={c.kind === "email" ? c.to : c.url}>
                {c.kind === "email" ? c.to : c.url}
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              <button type="button" onClick={() => toggle(c)} disabled={busy !== null} className={btnGhost}>
                {c.enabled ? "Disable" : "Enable"}
              </button>
              <button type="button" onClick={() => test(c)} disabled={busy !== null} className={btnSky}>
                {busy === c.id ? "…" : "Send test"}
              </button>
              <button type="button" onClick={() => remove(c)} disabled={busy !== null} className={btnRed}>
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

// ── SMTP mail server ─────────────────────────────────────────────────────────

function SMTPSection({ notify }: { notify: (msg: string) => void }) {
  const { data, loading, error } = useSMTPSettings();
  const [host, setHost] = useState("");
  const [port, setPort] = useState(587);
  const [from, setFrom] = useState("");
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [hasPassword, setHasPassword] = useState(false);
  const [source, setSource] = useState("");
  const [seeded, setSeeded] = useState(false);
  const [busy, setBusy] = useState<null | string>(null);
  const [testTo, setTestTo] = useState("");

  // Seed the form once from the server (password is never sent back).
  useEffect(() => {
    if (data && !seeded) {
      setHost(data.host);
      setPort(data.port || 587);
      setFrom(data.from);
      setUser(data.user);
      setHasPassword(data.has_password);
      setSource(data.source ?? "");
      setSeeded(true);
    }
  }, [data, seeded]);

  async function save() {
    if (!(await ensureAdminToken())) return;
    setBusy("save");
    try {
      const saved = await saveSMTPSettings({ host, port, from, user, password, has_password: hasPassword });
      setHasPassword(saved.has_password);
      setPassword("");
      setSource(saved.source ?? "db");
      notify("Saved SMTP settings");
    } catch (e) {
      notify(fail(e, "Save SMTP"));
    } finally {
      setBusy(null);
    }
  }

  async function sendTest() {
    const to = testTo.trim();
    if (!to) {
      notify("Enter a recipient to test");
      return;
    }
    if (!(await ensureAdminToken())) return;
    setBusy("test");
    try {
      await testSMTP(to);
      notify(`Test email sent to ${to}`);
    } catch (e) {
      notify(fail(e, "Test email"));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Email (SMTP) Server
        </h2>
        {source && <span className="badge-gray badge">{source === "env" ? "from env/flags" : "saved"}</span>}
      </div>

      {loading && !seeded && <p className="mb-2 text-xs text-slate-500">Loading SMTP settings…</p>}
      {error && <p className="mb-2 text-xs text-red-400">{error}</p>}

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <div>
          <label className={labelCls}>SMTP host</label>
          <input className={inputCls} value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" />
        </div>
        <div>
          <label className={labelCls}>Port</label>
          <input type="number" className={inputCls} value={port} onChange={(e) => setPort(Math.round(parseFloat(e.target.value) || 0))} />
        </div>
        <div>
          <label className={labelCls}>From address</label>
          <input className={inputCls} value={from} onChange={(e) => setFrom(e.target.value)} placeholder="monitor@example.com" />
        </div>
        <div>
          <label className={labelCls}>Username</label>
          <input className={inputCls} value={user} onChange={(e) => setUser(e.target.value)} placeholder="(optional)" />
        </div>
        <div className="sm:col-span-2">
          <label className={labelCls}>Password {hasPassword && <span className="text-slate-500">(stored — leave blank to keep)</span>}</label>
          <div className="flex items-center gap-2">
            <input
              type="password"
              className={inputCls}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={hasPassword ? "••••••••" : "SMTP password"}
              autoComplete="new-password"
            />
            {password === " " && (
              <button type="button" onClick={() => setPassword("")} className={`${btnGhost} shrink-0`}>
                undo clear
              </button>
            )}
          </div>
          {hasPassword && (
            <button type="button" onClick={() => setPassword(" ")} className="mt-1 text-[10px] text-slate-500 hover:text-slate-300">
              {password === " " ? "will remove stored password on save" : "remove stored password"}
            </button>
          )}
        </div>
      </div>

      <p className="mt-2 text-[10px] text-slate-500">
        Port 465 uses implicit TLS; other ports use STARTTLS. The password is encrypted at rest and never returned to the browser.
      </p>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button type="button" onClick={save} disabled={busy !== null} className={btnSky}>
          {busy === "save" ? "Saving…" : "Save SMTP"}
        </button>
        <input
          className={`${inputCls} w-56`}
          value={testTo}
          onChange={(e) => setTestTo(e.target.value)}
          placeholder="test recipient email"
        />
        <button type="button" onClick={sendTest} disabled={busy !== null || host === ""} className={btnGhost}>
          {busy === "test" ? "Sending…" : "Send test email"}
        </button>
      </div>
    </section>
  );
}

// ── Rules ───────────────────────────────────────────────────────────────────────

function RulesSection({
  rules,
  channels,
  loading,
  error,
  reload,
  notify,
}: {
  rules: AlertRule[];
  channels: AlertChannel[];
  loading: boolean;
  error: string | null;
  reload: () => void;
  notify: (msg: string) => void;
}) {
  const [draft, setDraft] = useState<AlertRule>(blankRule());
  const [busy, setBusy] = useState<null | string>(null);

  function toggleInList(list: string[] | undefined, value: string): string[] {
    const cur = list ?? [];
    return cur.includes(value) ? cur.filter((x) => x !== value) : [...cur, value];
  }

  async function submit() {
    if (busy) return;
    if (!draft.name.trim()) {
      notify("Rule name is required");
      return;
    }
    if (!(await ensureAdminToken())) return;
    setBusy("save");
    try {
      const saved = await saveAlertRule(draft);
      notify(`Saved rule “${saved.name}”`);
      setDraft(blankRule());
      reload();
    } catch (e) {
      notify(fail(e, "Save rule"));
    } finally {
      setBusy(null);
    }
  }

  async function toggle(r: AlertRule) {
    if (!(await ensureAdminToken())) return;
    setBusy(r.id);
    try {
      await saveAlertRule({ ...r, enabled: !r.enabled });
      reload();
    } catch (e) {
      notify(fail(e, "Toggle rule"));
    } finally {
      setBusy(null);
    }
  }

  async function remove(r: AlertRule) {
    const ok = await confirmAction({
      title: "Delete rule",
      message: `Delete alert rule “${r.name}”?\n\nExisting alert history is kept.`,
      confirmLabel: "Delete",
      danger: true,
      requireAdmin: true,
    });
    if (!ok) return;
    setBusy(r.id);
    try {
      await deleteAlertRule(r.id);
      notify(`Deleted rule “${r.name}”`);
      reload();
    } catch (e) {
      notify(fail(e, "Delete rule"));
    } finally {
      setBusy(null);
    }
  }

  const num = (v: string): number => {
    const n = parseFloat(v);
    return isNaN(n) ? 0 : n;
  };

  return (
    <section className="card">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-slate-400">
        Alert Rules
      </h2>

      <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="col-span-2">
          <label className={labelCls}>Name</label>
          <input
            className={inputCls}
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder="High CPU"
          />
        </div>
        <div>
          <label className={labelCls}>Type</label>
          <select
            className={inputCls}
            value={draft.type}
            onChange={(e) => setDraft({ ...draft, type: e.target.value })}
          >
            <option value="host">Host threshold</option>
            <option value="container">Container exit / OOM</option>
            <option value="cve">New critical CVEs</option>
            <option value="offline">Host / daemon offline</option>
          </select>
        </div>
        <div>
          <label className={labelCls}>Severity</label>
          <select
            className={inputCls}
            value={draft.severity}
            onChange={(e) => setDraft({ ...draft, severity: e.target.value })}
          >
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
        </div>

        {draft.type === "host" && (
          <>
            <div>
              <label className={labelCls}>Metric</label>
              <select
                className={inputCls}
                value={draft.metric}
                onChange={(e) => setDraft({ ...draft, metric: e.target.value })}
              >
                <option value="cpu">CPU %</option>
                <option value="mem">Memory %</option>
                <option value="disk">Disk %</option>
                <option value="swap">Swap %</option>
                <option value="load1">Load 1</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>Operator</label>
              <select
                className={inputCls}
                value={draft.op}
                onChange={(e) => setDraft({ ...draft, op: e.target.value })}
              >
                <option value=">">&gt;</option>
                <option value="<">&lt;</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>Threshold</label>
              <input
                type="number"
                className={inputCls}
                value={draft.threshold}
                onChange={(e) => setDraft({ ...draft, threshold: num(e.target.value) })}
              />
            </div>
            <div>
              <label className={labelCls}>For (seconds)</label>
              <input
                type="number"
                className={inputCls}
                value={draft.for_seconds}
                onChange={(e) => setDraft({ ...draft, for_seconds: Math.round(num(e.target.value)) })}
              />
            </div>
          </>
        )}

        {draft.type === "container" && (
          <div className="col-span-2">
            <label className={labelCls}>Event kinds</label>
            <div className="flex items-center gap-4 pt-1">
              {["exit", "oom", "unhealthy"].map((k) => (
                <label key={k} className="flex items-center gap-1 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={(draft.event_kinds ?? []).includes(k)}
                    onChange={() => setDraft({ ...draft, event_kinds: toggleInList(draft.event_kinds, k) })}
                  />
                  {k}
                </label>
              ))}
            </div>
          </div>
        )}

        {draft.type === "cve" && (
          <>
            <div>
              <label className={labelCls}>Min severity</label>
              <select
                className={inputCls}
                value={draft.min_severity}
                onChange={(e) => setDraft({ ...draft, min_severity: e.target.value })}
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>Count ≥</label>
              <input
                type="number"
                className={inputCls}
                value={draft.count_threshold ?? 1}
                onChange={(e) => setDraft({ ...draft, count_threshold: Math.round(num(e.target.value)) })}
              />
            </div>
          </>
        )}

        {draft.type === "offline" && (
          <div>
            <label className={labelCls}>Grace (seconds)</label>
            <input
              type="number"
              className={inputCls}
              value={draft.for_seconds}
              onChange={(e) => setDraft({ ...draft, for_seconds: Math.round(num(e.target.value)) })}
            />
          </div>
        )}

        <div>
          <label className={labelCls}>Cooldown (seconds)</label>
          <input
            type="number"
            className={inputCls}
            value={draft.cooldown_seconds}
            onChange={(e) => setDraft({ ...draft, cooldown_seconds: Math.round(num(e.target.value)) })}
          />
        </div>

        {channels.length > 0 && (
          <div className="col-span-2 sm:col-span-4">
            <label className={labelCls}>Channels (none = all enabled)</label>
            <div className="flex flex-wrap gap-3 pt-1">
              {channels.map((c) => (
                <label key={c.id} className="flex items-center gap-1 text-xs text-slate-300">
                  <input
                    type="checkbox"
                    checked={(draft.channel_ids ?? []).includes(c.id)}
                    onChange={() => setDraft({ ...draft, channel_ids: toggleInList(draft.channel_ids, c.id) })}
                  />
                  {c.name}
                </label>
              ))}
            </div>
          </div>
        )}
      </div>

      <button type="button" onClick={submit} disabled={busy !== null} className={btnSky}>
        {busy === "save" ? "Saving…" : "Save rule"}
      </button>

      <div className="mt-3 divide-y divide-surface-border">
        {loading && rules.length === 0 && <p className="py-2 text-xs text-slate-500">Loading rules…</p>}
        {error && rules.length === 0 && <p className="py-2 text-xs text-red-400">{error}</p>}
        {!loading && rules.length === 0 && !error && (
          <p className="py-2 text-xs text-slate-500">No rules configured.</p>
        )}
        {rules.map((r) => (
          <div key={r.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="truncate text-xs font-medium text-slate-200">{r.name}</span>
                <span className={`badge ${sevClass(r.severity)}`}>{r.severity}</span>
                <span className="badge-gray badge">{r.type}</span>
                {!r.enabled && <span className="badge-gray badge">disabled</span>}
              </div>
              <div className="truncate text-[10px] text-slate-500">{describeRule(r)}</div>
            </div>
            <div className="flex items-center gap-1.5">
              <button type="button" onClick={() => setDraft(r)} disabled={busy !== null} className={btnGhost}>
                Edit
              </button>
              <button type="button" onClick={() => toggle(r)} disabled={busy !== null} className={btnGhost}>
                {r.enabled ? "Disable" : "Enable"}
              </button>
              <button type="button" onClick={() => remove(r)} disabled={busy !== null} className={btnRed}>
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

// describeRule renders a one-line summary of a rule's condition.
function describeRule(r: AlertRule): string {
  if (r.type === "host") {
    const forTxt = r.for_seconds > 0 ? ` for ${r.for_seconds}s` : "";
    return `${r.metric} ${r.op || ">"} ${r.threshold}${forTxt}`;
  }
  if (r.type === "container") {
    const kinds = (r.event_kinds ?? []).join(", ") || "exit, oom";
    return `container ${kinds}`;
  }
  if (r.type === "cve") {
    return `${r.min_severity || "CRITICAL"} findings ≥ ${r.count_threshold || 1}`;
  }
  if (r.type === "offline") {
    return `fires when host/daemon is unreachable for ${r.for_seconds || 0}s`;
  }
  return r.type;
}

// ── History ─────────────────────────────────────────────────────────────────────

function HistorySection({
  alerts,
  loading,
  error,
  reload,
  notify,
}: {
  alerts: Alert[];
  loading: boolean;
  error: string | null;
  reload: () => void;
  notify: (msg: string) => void;
}) {
  const [showResolved, setShowResolved] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const active = useMemo(() => alerts.filter((a) => a.status === "firing"), [alerts]);
  const history = useMemo(
    () => (showResolved ? alerts.filter((a) => a.status === "resolved") : []),
    [alerts, showResolved],
  );

  async function doAck(a: Alert) {
    if (!(await ensureAdminToken())) return;
    setBusy(a.id);
    try {
      await ackAlert(a.id, "");
      notify(`Acknowledged “${a.rule_name}”`);
      reload();
    } catch (e) {
      notify(fail(e, "Acknowledge"));
    } finally {
      setBusy(null);
    }
  }

  async function doResolve(a: Alert) {
    const ok = await confirmAction({
      title: "Resolve alert",
      message: `Mark “${a.rule_name}” (${a.resource}) as resolved?\n\nIf the condition is still breached it may fire again on the next check.`,
      confirmLabel: "Resolve",
      requireAdmin: true,
    });
    if (!ok) return;
    setBusy(a.id);
    try {
      await resolveAlert(a.id);
      notify(`Resolved “${a.rule_name}”`);
      reload();
    } catch (e) {
      notify(fail(e, "Resolve"));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Alert History
        </h2>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setShowResolved((v) => !v)}
            className={btnGhost}
          >
            {showResolved ? "Hide resolved" : "Show resolved"}
          </button>
          <button type="button" onClick={reload} className={btnGhost}>
            Refresh
          </button>
        </div>
      </div>

      {loading && alerts.length === 0 && <p className="py-2 text-xs text-slate-500">Loading alerts…</p>}
      {error && <p className="py-2 text-xs text-red-400">{error}</p>}

      {active.length === 0 && history.length === 0 && !loading && !error && (
        <p className="py-2 text-xs text-slate-500">No alerts firing.</p>
      )}

      {active.length > 0 && (
        <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {active.map((a) => {
            const entries = parseDelivery(a);
            return (
              <div key={a.id} className="rounded-lg border border-red-500/30 bg-red-950/20 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs font-semibold text-slate-100">{a.rule_name}</span>
                  <span className="flex items-center gap-1.5">
                    {a.acked && <span className="badge-yellow badge">acked</span>}
                    <span className={`badge ${statusClass(a.status)}`}>{a.status}</span>
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-300">{a.summary}</p>
                <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
                  <span className={`badge ${sevClass(a.severity)}`}>{a.severity}</span>
                  <span>{a.resource}</span>
                  <span>since {fmtTime(a.started_at)}</span>
                </div>
                {entries.length > 0 && (
                  <ul className="mt-1.5 flex flex-col gap-0.5 text-[10px] text-slate-500">
                    {entries.map((en) => (
                      <li key={en.name} className="flex items-center gap-1.5">
                        <span className={en.status === "ok" ? "text-emerald-400" : "text-red-400"}>
                          {en.status === "ok" ? "✓" : "✕"}
                        </span>
                        <span className="truncate">{en.name}</span>
                        {en.attempts > 1 && <span>({en.attempts} tries)</span>}
                        {en.error && (
                          <span className="truncate opacity-70" title={en.error}>
                            — {en.error}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                <div className="mt-2 flex items-center gap-1.5">
                  <button type="button" onClick={() => doAck(a)} disabled={busy !== null || a.acked} className={btnGhost}>
                    {busy === a.id ? "…" : a.acked ? "Acknowledged" : "Acknowledge"}
                  </button>
                  <button type="button" onClick={() => doResolve(a)} disabled={busy !== null} className={btnRed}>
                    Resolve
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {showResolved && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-2 py-1.5 font-medium">Rule</th>
                <th className="px-2 py-1.5 font-medium">Resource</th>
                <th className="px-2 py-1.5 font-medium">Started</th>
                <th className="px-2 py-1.5 font-medium">Resolved</th>
                <th className="px-2 py-1.5 font-medium">Delivery</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {history.map((a) => (
                <tr key={a.id} className="hover:bg-surface/40">
                  <td className="px-2 py-1.5">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-slate-200">{a.rule_name}</span>
                      <span className={`badge ${sevClass(a.severity)}`}>{a.severity}</span>
                    </div>
                    <div className="truncate text-[10px] text-slate-500">{a.summary}</div>
                  </td>
                  <td className="px-2 py-1.5 text-slate-400">{a.resource}</td>
                  <td className="px-2 py-1.5 text-slate-400">{fmtTime(a.started_at)}</td>
                  <td className="px-2 py-1.5 text-slate-400">{fmtTime(a.resolved_at)}</td>
                  <td className="px-2 py-1.5 text-slate-400">{delivery(a)}</td>
                </tr>
              ))}
              {history.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-2 py-2 text-slate-500">
                    No resolved alerts.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// ── Panel ───────────────────────────────────────────────────────────────────────

export default function AlertsPanel() {
  const rules = useAlertRules();
  const channels = useAlertChannels();
  const alerts = useAlerts("", 200);
  const [msg, setMsg] = useState<string | null>(null);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Alerting &amp; Notifications
        </h2>
        <span className="text-[11px] text-slate-500">
          Rules are evaluated on the hub every interval — no browser required.
        </span>
      </div>

      {msg && (
        <div className="flex items-center justify-between rounded border border-surface-border bg-surface/60 px-3 py-1.5 text-[11px] text-slate-300">
          <span>{msg}</span>
          <button type="button" onClick={() => setMsg(null)} className="text-slate-500 hover:text-slate-300">
            ✕
          </button>
        </div>
      )}

      <ChannelsSection
        channels={channels.data ?? []}
        loading={channels.loading}
        error={channels.error}
        reload={channels.reload}
        notify={setMsg}
      />
      <SMTPSection notify={setMsg} />
      <RulesSection
        rules={rules.data ?? []}
        channels={channels.data ?? []}
        loading={rules.loading}
        error={rules.error}
        reload={rules.reload}
        notify={setMsg}
      />
      <HistorySection
        alerts={alerts.data ?? []}
        loading={alerts.loading}
        error={alerts.error}
        reload={alerts.reload}
        notify={setMsg}
      />
    </div>
  );
}
