import type { HostMetricsPoint } from "../types";

/**
 * exportHostCSV serialises host-metric chart points into a CSV file and
 * triggers a browser download. No external dependency; the object URL is
 * revoked immediately so no blob lingers in memory.
 */
export function exportHostCSV(points: HostMetricsPoint[], filename = "host-metrics.csv"): void {
  const header = "timestamp,cpu_percent,mem_percent,disk_read_bps,disk_write_bps,net_recv_bps,net_sent_bps";
  const rows = points.map((p) =>
    [
      new Date(p.ts).toISOString(),
      p.cpu,
      p.mem,
      p.diskRead,
      p.diskWrite,
      p.netRecv,
      p.netSent,
    ].join(","),
  );
  const csv = [header, ...rows].join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
