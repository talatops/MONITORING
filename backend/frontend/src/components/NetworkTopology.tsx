import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useTopology } from "../hooks/useResources";

interface ResourceData {
  label: string;
  sub: string;
  kind: "container" | "network";
  state?: string;
  connections: number;
  [key: string]: unknown;
}

// Node + layout geometry.
const NODE_W = 224;
const NODE_H = 78;
const V_GAP = 22;   // vertical gap between stacked nodes
const H_GAP = 200;  // horizontal gap between the container and network columns

// Literal class bundles so Tailwind's JIT keeps them in the bundle.
interface StateStyle { dot: string; bar: string; text: string; ring: string }
function stateStyle(state?: string): StateStyle {
  switch (state) {
    case "running":
      return { dot: "bg-emerald-400", bar: "bg-emerald-500", text: "text-emerald-300", ring: "ring-emerald-500/30" };
    case "exited":
    case "dead":
      return { dot: "bg-red-400", bar: "bg-red-500", text: "text-red-300", ring: "ring-red-500/30" };
    case "paused":
    case "restarting":
    case "created":
      return { dot: "bg-amber-400", bar: "bg-amber-500", text: "text-amber-300", ring: "ring-amber-500/30" };
    default:
      return { dot: "bg-slate-400", bar: "bg-slate-500", text: "text-slate-400", ring: "ring-slate-500/30" };
  }
}

function ResourceNode({ data }: NodeProps) {
  const d = data as ResourceData;
  const isNet = d.kind === "network";
  const st = stateStyle(d.state);
  return (
    <div
      style={{ width: NODE_W }}
      className={`relative flex items-center gap-2.5 overflow-hidden rounded-xl border px-3 py-2.5 text-xs shadow-lg ring-1 ${
        isNet
          ? "border-sky-500/40 bg-gradient-to-br from-sky-800/40 to-slate-900/60 ring-sky-500/20"
          : "border-slate-700/70 bg-slate-800/80 " + st.ring
      }`}
    >
      {!isNet && <span className={`absolute left-0 top-0 h-full w-1 ${st.bar}`} />}

      {isNet ? (
        <Handle type="target" position={Position.Left} className="!h-2.5 !w-2.5 !border-2 !border-slate-900 !bg-sky-400" />
      ) : (
        <Handle type="source" position={Position.Right} className="!h-2.5 !w-2.5 !border-2 !border-slate-900 !bg-slate-400" />
      )}

      <div
        className={`ml-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${
          isNet ? "bg-sky-500/20 text-sky-300" : "bg-slate-900/60"
        }`}
      >
        {isNet ? (
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" />
            <path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4" />
          </svg>
        ) : (
          <span className={`h-3 w-3 rounded-full ${st.dot}`} />
        )}
      </div>

      <div className="min-w-0 flex-1">
        <div className="truncate font-semibold text-slate-100" title={d.label}>{d.label}</div>
        <div className={`truncate text-[10px] font-medium uppercase tracking-wide ${isNet ? "text-sky-300/80" : st.text}`}>
          {isNet ? d.sub : d.state || d.sub}
        </div>
      </div>

      <span
        className="shrink-0 rounded-full bg-slate-900/70 px-2 py-0.5 text-[10px] font-semibold text-slate-300"
        title={`${d.connections} connection(s)`}
      >
        {d.connections}
      </span>
    </div>
  );
}

const nodeTypes = { resource: ResourceNode };

// avg returns the mean of a list, or a fallback when empty.
function avg(xs: number[], fallback = 0): number {
  if (xs.length === 0) return fallback;
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

// layeredLayout is a compact Sugiyama-style ordering for the bipartite
// container↔network graph: two columns, each ordered by the barycenter of its
// neighbours over several sweeps to reduce edge crossings. Positions are then
// assigned with even vertical spacing, the shorter column centred against the
// taller one.
function layeredLayout(
  containers: { id: string }[],
  networks: { id: string }[],
  edges: { source: string; target: string }[],
): Map<string, { x: number; y: number }> {
  const contToNets = new Map<string, string[]>();
  const netToConts = new Map<string, string[]>();
  for (const e of edges) {
    if (!contToNets.has(e.source)) contToNets.set(e.source, []);
    contToNets.get(e.source)!.push(e.target);
    if (!netToConts.has(e.target)) netToConts.set(e.target, []);
    netToConts.get(e.target)!.push(e.source);
  }

  let contOrder = containers.map((c) => c.id);
  let netOrder = networks.map((n) => n.id);
  let contPos = new Map(contOrder.map((id, i) => [id, i]));
  let netPos = new Map(netOrder.map((id, i) => [id, i]));

  for (let it = 0; it < 8; it++) {
    netOrder = [...netOrder].sort(
      (a, b) =>
        avg((netToConts.get(a) ?? []).map((c) => contPos.get(c) ?? 0), Number.MAX_SAFE_INTEGER) -
        avg((netToConts.get(b) ?? []).map((c) => contPos.get(c) ?? 0), Number.MAX_SAFE_INTEGER),
    );
    netPos = new Map(netOrder.map((id, i) => [id, i]));

    contOrder = [...contOrder].sort(
      (a, b) =>
        avg((contToNets.get(a) ?? []).map((n) => netPos.get(n) ?? 0), Number.MAX_SAFE_INTEGER) -
        avg((contToNets.get(b) ?? []).map((n) => netPos.get(n) ?? 0), Number.MAX_SAFE_INTEGER),
    );
    contPos = new Map(contOrder.map((id, i) => [id, i]));
  }

  const maxRows = Math.max(contOrder.length, netOrder.length, 1);
  const totalH = maxRows * (NODE_H + V_GAP);
  const contY0 = (totalH - contOrder.length * (NODE_H + V_GAP)) / 2;
  const netY0 = (totalH - netOrder.length * (NODE_H + V_GAP)) / 2;

  const out = new Map<string, { x: number; y: number }>();
  contOrder.forEach((id, i) => out.set(id, { x: 0, y: contY0 + i * (NODE_H + V_GAP) }));
  netOrder.forEach((id, j) => out.set(id, { x: NODE_W + H_GAP, y: netY0 + j * (NODE_H + V_GAP) }));
  return out;
}

export default function NetworkTopology({ host }: { host?: string }) {
  const { data, loading, error, reload } = useTopology(host);

  const connCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const e of data?.edges ?? []) {
      m[e.source] = (m[e.source] ?? 0) + 1;
      m[e.target] = (m[e.target] ?? 0) + 1;
    }
    return m;
  }, [data]);

  const { nodes, networkCount, containerCount } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], networkCount: 0, containerCount: 0 };
    const containers = data.nodes
      .filter((n) => n.type === "container")
      .sort((a, b) => a.label.localeCompare(b.label));
    const networks = data.nodes
      .filter((n) => n.type === "network")
      .sort((a, b) => a.label.localeCompare(b.label));

    const pos = layeredLayout(containers, networks, data.edges);

    const nodes: Node[] = data.nodes.map((n) => {
      const isNet = n.type === "network";
      return {
        id: n.id,
        type: "resource",
        position: pos.get(n.id) ?? { x: 0, y: 0 },
        data: {
          label: n.label,
          sub: isNet ? n.driver || "network" : "container",
          kind: isNet ? "network" : "container",
          state: n.state,
          connections: connCounts[n.id] ?? 0,
        } as ResourceData,
      };
    });

    return { nodes, networkCount: networks.length, containerCount: containers.length };
  }, [data, connCounts]);

  const edges: Edge[] = useMemo(() => {
    if (!data) return [];
    const showLabels = data.edges.length <= 30;
    return data.edges.map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      type: "smoothstep",
      animated: true,
      label: showLabels && e.ip ? e.ip : undefined,
      labelStyle: { fill: "#7dd3fc", fontSize: 10, fontWeight: 600 },
      labelBgStyle: { fill: "#0b1220", fillOpacity: 0.85 },
      labelBgPadding: [4, 2] as [number, number],
      labelBgBorderRadius: 4,
      style: { stroke: "#38bdf8", strokeWidth: 1.5, strokeOpacity: 0.5 },
    }));
  }, [data]);

  const empty = !loading && !error && nodes.length === 0;

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
            Network Topology
          </h2>
          <span className="text-[11px] text-slate-500">
            {containerCount} containers · {networkCount} networks · {data?.edges.length ?? 0} links
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-3 text-[10px] text-slate-400 sm:flex">
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-400" /> running</span>
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-red-400" /> stopped</span>
            <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-400" /> other</span>
            <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded border border-sky-400 bg-sky-500/30" /> network</span>
          </div>
          <button
            type="button"
            onClick={reload}
            className="rounded border border-surface-border bg-surface/60 px-2 py-1 text-xs text-slate-300 hover:bg-surface-raised"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="card relative h-[560px] overflow-hidden p-0">
        {loading && nodes.length === 0 && (
          <p className="p-4 text-xs text-slate-500">Loading topology…</p>
        )}
        {error && nodes.length === 0 && (
          <p className="p-4 text-xs text-red-400">Could not load topology: {error}</p>
        )}
        {empty && (
          <p className="p-4 text-xs text-slate-500">
            No container-to-network connections found.
          </p>
        )}
        {nodes.length > 0 && (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2, maxZoom: 1.25 }}
            minZoom={0.1}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={24} size={1.5} color="#243244" />
            <Controls
              showInteractive={false}
              className="!rounded-lg !border-0 !bg-slate-800/80 !shadow-none [&_button]:!border-slate-700 [&_button]:!bg-slate-800 [&_button]:!text-slate-300"
            />
          </ReactFlow>
        )}
      </div>
    </section>
  );
}
