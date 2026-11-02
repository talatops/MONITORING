// ── Backend struct mirrors ────────────────────────────────────────────────────

/** Mirrors collector.HostMetrics JSON tags */
export interface HostMetrics {
  timestamp: string;       // RFC3339Nano
  cpu_percent: number;
  mem_used_bytes: number;
  mem_total_bytes: number;
  mem_percent: number;
  disk_read_bps: number;
  disk_write_bps: number;
  net_recv_bps: number;
  net_sent_bps: number;
  num_cpu: number;
  go_os: string;
  cpu_per_core: number[]; // per-logical-core usage % (empty until first tick)

  // Tier 1 additions
  load_1: number;
  load_5: number;
  load_15: number;
  swap_used_bytes: number;
  swap_total_bytes: number;
  swap_percent: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  disk_free_bytes: number;
  disk_used_percent: number;
  uptime_seconds: number;
}

/** Mirrors collector.ContainerInfo JSON tags */
export interface ContainerInfo {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  created: number;         // Unix timestamp (seconds)
  size_rw_bytes: number;   // writable layer size
  size_rootfs_bytes: number; // total fs size
  // Tier 2
  restart_count: number;
  oom_killed: boolean;
  health_status: string;   // "healthy" | "unhealthy" | "starting" | ""
  exit_code: number;
  ports?: ContainerPort[];
}

/** Mirrors collector.ContainerPort */
export interface ContainerPort {
  ip: string;
  private_port: number;
  public_port: number;
  type: string; // "tcp" | "udp"
}

/** Mirrors collector.ContainerStatsSnapshot JSON tags */
export interface ContainerStatsSnapshot {
  container_id: string;
  name: string;
  cpu_percent: number;
  mem_used_bytes: number;
  mem_limit_bytes: number;
  mem_percent: number;
  net_rx_bytes: number;
  net_tx_bytes: number;
  block_read: number;
  block_write: number;

  // Tier 1 additions
  pids_current: number;
  mem_cache_bytes: number;
  mem_rss_bytes: number;
  mem_swap_bytes: number;
  cpu_throttled_periods: number;
  cpu_throttled_ns: number;
  net_rx_packets: number;
  net_tx_packets: number;
  net_interfaces: NetInterfaceStats[];
}

/** Per-interface network counters */
export interface NetInterfaceStats {
  ifname: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
}

/** Mirrors collector.LogEntry JSON tags */
export interface LogEntry {
  container_id: string;
  stream: "stdout" | "stderr";
  line: string;
}

/** Mirrors collector.ContainerProcess (`docker top`) */
export interface ContainerProcess {
  titles: string[];
  processes: string[][];
}

/** Mirrors collector.DiskUsageSummary (`docker system df`) */
export interface DiskUsageSummary {
  images_count: number;
  images_total_bytes: number;
  containers_count: number;
  containers_rw_bytes: number;
  volumes_count: number;
  volumes_total_bytes: number;
  build_cache_count: number;
  build_cache_total_bytes: number;
  build_cache_reclaimable_bytes: number;
}

// ── Phase 3: topology, volumes, images ───────────────────────────────────────

/** Mirrors collector.TopologyNode */
export interface TopologyNode {
  id: string;
  type: "container" | "network";
  label: string;
  state?: string;
  driver?: string;
}

/** Mirrors collector.TopologyEdge */
export interface TopologyEdge {
  source: string;
  target: string;
}

/** Mirrors collector.Topology */
export interface Topology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

/** Mirrors collector.VolumeInfo */
export interface VolumeInfo {
  name: string;
  driver: string;
  mountpoint: string;
  scope: string;
  labels?: Record<string, string>;
  size_bytes: number;
  size_computed: boolean;
  used_by?: string[];
}

/** Mirrors collector.ImageInfo */
export interface ImageInfo {
  id: string;
  repo_tags: string[];
  created: number;
  size_bytes: number;
  virtual_size_bytes: number;
}

/** Mirrors api.HostInfo — one entry in the host selector. */
export interface HostInfo {
  id: string;
  name: string;
  kind: "local" | "agent";
  online: boolean;
  os?: string;
  num_cpu?: number;
}

// ── Phase 5: cgroup v2 detail + kernel event mining ────────────────────────────

/** Mirrors collector.PSIPressure (one resource's "some" stall info) */
export interface PSIPressure {
  some_avg10: number;
  some_avg60: number;
  some_avg300: number;
  total_usec: number;
}

/** Mirrors collector.PSISet */
export interface PSISet {
  cpu: PSIPressure;
  memory: PSIPressure;
  io: PSIPressure;
}

/** Mirrors collector.CgroupCPU */
export interface CgroupCPU {
  usage_usec: number;
  nr_periods: number;
  nr_throttled: number;
  throttled_usec: number;
}

/** Mirrors collector.CgroupMemory */
export interface CgroupMemory {
  current: number;
  limit: number; // 0 = unlimited
  swap_current: number;
  swap_limit: number;
  anon: number;
  file: number;
  slab: number;
  sock: number;
}

/** Mirrors collector.CgroupIO */
export interface CgroupIO {
  rbytes: number;
  wbytes: number;
  riops: number;
  wiops: number;
}

/** Mirrors collector.ContainerCgroupStats (Linux + root only) */
export interface ContainerCgroupStats {
  cgroup_path: string;
  cpu: CgroupCPU;
  throttled_pct: number;
  cores_allowed: number; // 0 = unlimited
  allowed_cpus: string;
  memory: CgroupMemory;
  psi: PSISet;
  io: CgroupIO;
  numa?: Record<string, number>;
}

/** Mirrors collector.KernelEvent — a classified kernel-log line. */
export interface KernelEvent {
  ts: string;
  category:
    | "oom_kill"
    | "ext4_error"
    | "thermal"
    | "segfault"
    | "hung_task"
    | "soft_lockup"
    | "fs_readonly"
    | "other";
  severity: "crit" | "warn" | "info";
  message: string;
  source: string; // journald | kmsg | dmesg
  container_id?: string;
}

// ── Phase 6: image vulnerability scanning + fleet security posture ─────────────

/** Mirrors collector.Vulnerability — one CVE finding for a package. */
export interface Vulnerability {
  cve_id: string;
  package: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  installed_version: string;
  fixed_version: string; // "" = no fix yet
  title?: string;
}

/** Mirrors collector.ImageVulnScan — the cached Trivy result for one image. */
export interface ImageVulnScan {
  ref: string;
  image_id: string;
  scanner: string;
  scanned_at: string; // RFC3339
  counts: Record<string, number>;
  vulnerabilities: Vulnerability[];
}

/** Lean POST /images/scan response (counts only). */
export interface ScanSummary {
  ref: string;
  image_id: string;
  scanner: string;
  scanned_at: string;
  counts: Record<string, number>;
  total: number;
  host?: string;
}

/** Mirrors collector.ContainerSecurity — live posture of one container. */
export interface ContainerSecurity {
  container_id: string;
  name: string;
  image: string;
  host_id: string;
  host_name: string;
  privileged: boolean;
  root: boolean;
  cap_add?: string[];
  user: string;
  host_network: boolean;
  host_pid: boolean;
  readonly_rootfs: boolean;
  exposed_ports?: ContainerPort[];
}

/** api.HostSecurity — one host's posture in the fleet overview. */
export interface HostSecurity {
  host_id: string;
  host_name: string;
  os?: string;
  offline: boolean;
  containers: ContainerSecurity[];
}

/** api.ImageExposure — an in-use image, its CVE counts and running hosts. */
export interface ImageExposure {
  ref: string;
  counts: Record<string, number>;
  total: number;
  scanned: boolean;
  scanned_at?: string;
  hosts: string[];
}

/** api.SecurityOverview — GET /security/overview payload. */
export interface SecurityOverview {
  generated_at: string;
  hosts: HostSecurity[];
  image_exposure: ImageExposure[];
  risky_containers: ContainerSecurity[];
}

// ── WebSocket envelope ────────────────────────────────────────────────────────

/** Mirrors api.WSMessage */
export interface WSMessage {
  type: WSMessageType;
  data: unknown;
  host?: string;
}

export type WSMessageType =
  | "host_metrics"
  | "container_stats"
  | "container_log"
  | "container_list"
  | "kernel_event";

// Narrowed payload types. `host` tags which monitored host produced the frame
// (empty/absent is treated as the hub's local host).
export interface HostMetricsMsg   { type: "host_metrics";    data: HostMetrics;           host?: string }
export interface ContainerStatsMsg { type: "container_stats"; data: ContainerStatsSnapshot; host?: string }
export interface ContainerLogMsg  { type: "container_log";   data: LogEntry;              host?: string }
export interface ContainerListMsg { type: "container_list";  data: ContainerInfo[];        host?: string }
export interface KernelEventMsg    { type: "kernel_event";     data: KernelEvent;           host?: string }

export type TypedWSMessage =
  | HostMetricsMsg
  | ContainerStatsMsg
  | ContainerLogMsg
  | ContainerListMsg
  | KernelEventMsg;

// ── UI helpers ────────────────────────────────────────────────────────────────

/** Single point in the host metrics history chart buffer */
export interface HostMetricsPoint {
  ts: number;          // Unix ms for Recharts x-axis
  cpu: number;
  mem: number;
  diskRead: number;    // bytes/s
  diskWrite: number;
  netRecv: number;
  netSent: number;
}

/** Latest stats per container, keyed by id */
export type ContainerStatsMap = Record<string, ContainerStatsSnapshot>;

/** Connection status for the WebSocket indicator */
export type WSStatus = "connecting" | "open" | "closed" | "error";
