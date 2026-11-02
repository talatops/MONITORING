import { useMemo } from "react";
import {
  ReactFlow,
  Background,
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
  [key: string]: unknown;
}

// Custom node: containers emit from the right, networks receive on the left,
// so edges flow left -> right in the two-column layout.
function ResourceNode({ data }: NodeProps) {
  const d = data as ResourceData;
  const isNet = d.kind === "network";
  return (
    <div
      className={`min-w-[140px] rounded-lg border px-3 py-2 text-xs shadow ${
        isNet
          ? "border-sky-500/40 bg-sky-950/50"
          : "border-slate-600/60 bg-slate-800"
      }`}
    >
      {isNet ? (
        <Handle type="target" position={Position.Left} className="!bg-slate-500" />
      ) : (
        <Handle type="source" position={Position.Right} className="!bg-slate-500" />
      )}
      <div className="font-semibold text-slate-100">{d.label}</div>
      <div
        className={`text-[10px] uppercase tracking-wide ${
          isNet ? "text-sky-300/80" : "text-slate-400"
        }`}
      >
        {d.sub}
      </div>
    </div>
  );
}

const nodeTypes = { resource: ResourceNode };

export default function NetworkTopology({ host }: { host?: string }) {
  const { data, loading, error, reload } = useTopology(host);

  const nodes: Node[] = useMemo(() => {
    if (!data) return [];
    const containers = data.nodes.filter((n) => n.type === "container");
    const networks = data.nodes.filter((n) => n.type === "network");
    const spacing = 92;
    return [
      ...containers.map((n, i) => ({
        id: n.id,
        type: "resource",
        position: { x: 0, y: i * spacing },
        data: { label: n.label, sub: "container", kind: "container" } as ResourceData,
      })),
      ...networks.map((n, i) => ({
        id: n.id,
        type: "resource",
        position: { x: 380, y: i * spacing },
        data: { label: n.label, sub: n.driver || "network", kind: "network" } as ResourceData,
      })),
    ];
  }, [data]);

  const edges: Edge[] = useMemo(() => {
    if (!data) return [];
    return data.edges.map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      style: { stroke: "#475569" },
    }));
  }, [data]);

  const empty = !loading && (nodes.length === 0 || edges.length === 0);

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Network Topology
        </h2>
        <button
          type="button"
          onClick={reload}
          className="rounded border border-surface-border bg-surface/60 px-2 py-1 text-xs text-slate-300 hover:bg-surface-raised"
        >
          Refresh
        </button>
      </div>

      <div className="card relative h-[540px] overflow-hidden p-0">
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
            minZoom={0.3}
            nodesConnectable={false}
            elementsSelectable={false}
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={18} color="#1e293b" />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}
      </div>
    </section>
  );
}
