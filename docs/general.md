# Cross-Platform Custom Monitoring System Architecture
**Target Environments:** Kali Linux & Windows (x86_64 / ARM64)  
**Primary Language:** Go (Golang) / Rust / Node.js  
**Frontend Framework:** React / Vue.js / Svelte  

---

## 1. Why Move Away From Prometheus/Grafana/Loki?

While standard industry tools are powerful, they present significant disadvantages for custom or portable environments:

* **Resource Heavy:** Running Prometheus, Loki, Promtail, Node Exporter, cAdvisor, and Grafana simultaneously consumes 1.5 GB–3 GB of RAM at idle.
* **Complex Configuration:** Requires maintaining 5+ independent YAML configuration files, process orchestration, and continuous service updates.
* **Platform Incompatibility:** `cAdvisor` relies heavily on Linux `cgroups` (`/sys/fs/cgroup`) and the native Docker Unix socket (`/var/run/docker.sock`). It **fails to run natively on Windows** without WSL2 virtualization.
* **Fragmented Query Languages:** Querying metrics requires PromQL, while querying logs requires LogQL.
* **Lack of Direct Control:** Custom UI workflows, custom security layers, embedded SQLite databases, or single-binary executables cannot easily be built into Grafana.

---

## 2. Technical Requirements for Windows & Kali Linux Compatibility

To ensure full cross-platform compatibility across both **Kali Linux** and **Windows**, the custom monitoring tool must meet these criteria:

```
                  +---------------------------------------------------+
                  |                 Unified Frontend                  |
                  |          React / Vue Dashboard UI                |
                  +-------------------------+-------------------------+
                                            | REST API / WebSockets
                  +-------------------------v-------------------------+
                  |               Single Core Backend                 |
                  |                (Go / Rust / Node)                 |
                  +------------+------------------------+-------------+
                               |                        |
       +-----------------------v---+        +-----------v-------------------+
       |     Linux Engine          |        |     Windows Engine            |
       |  (Kali / Debian)          |        |  (Windows 10/11 / Server)     |
       +---------------------------+        +-------------------------------+
       | • Host: /proc, /sys       |        | • Host: gopsutil / WMI        |
       | • Docker: Unix Socket     |        | • Docker: Named Pipes         |
       |   (/var/run/docker.sock)  |        |   (//./pipe/docker_engine)    |
       +---------------------------+        +-------------------------------+
```

### Key Compatibility Rules
1. **Docker Communication:**
   * **Kali Linux:** Connect via Unix Domain Socket: `unix:///var/run/docker.sock`
   * **Windows:** Connect via Named Pipe: `npipe:////./pipe/docker_engine`
2. **System Hardware Metrics:**
   * **Kali Linux:** Read host stats directly from `/proc/stat`, `/proc/meminfo`, and `/sys/class/net`.
   * **Windows:** Read host stats via Windows API calls or WMI counters. Use cross-platform libraries like Golang's `gopsutil` or Rust's `sysinfo` to abstract system dependencies.
3. **Container Metrics & Logs:**
   * Do **not** read `/var/lib/docker/containers` directly from disk.
   * Query the **Docker Engine API** programmatically using official SDKs (`docker/docker/client`). This allows stream parsing of logs and stats (`ContainerStats`, `ContainerLogs`) across both Linux and Windows seamlessly.

---

## 3. High-Level System Architecture

```
+-------------------------------------------------------------------------------+
|                            CUSTOM MONITORING BACKEND                          |
|                                                                               |
|  +------------------------+  +------------------------+  +-----------------+  |
|  |  Host Metric Poller    |  | Docker Engine Poller   |  | Container Log   |  |
|  |  (gopsutil / sysinfo)  |  | (Official Docker SDK)  |  | Streamer (SDK)  |  |
|  +-----------+------------+  +-----------+------------+  +--------+--------+  |
|              |                           |                        |           |
|              +-------------------+-------+                        |           |
|                                  |                                |           |
|                                  v                                v           |
|                    +---------------------------+    +-------------------+     |
|                    | Embedded Database Engine  |    | WebSocket Hub     |     |
|                    | (SQLite / DuckDB / Badgr) |    | (Real-time Feed)  |     |
|                    +-------------+-------------+    +---------+---------+     |
|                                  |                            |               |
|                                  +--------------+-------------+               |
|                                                 |                             |
|                                                 v                             |
|                                     +----------------------+                  |
|                                     | HTTP REST & WS API   |                  |
|                                     +----------+-----------+                  |
+------------------------------------------------|------------------------------+
                                                 |
                                                 v
                                    +--------------------------+
                                    |     React / Vue UI       |
                                    +--------------------------+
```

---

## 4. Backend Implementation Plan (Claude Development Spec)

When building this project with Claude, use this structured module workflow:

### Module A: Cross-Platform System Collector (`collector/host.go` or `host.rs`)
* **Objective:** Collect Host CPU %, Memory usage %, Disk Read/Write speeds, and Network Bandwidth in real-time.
* **Implementation Strategy:**
  * Use cross-platform abstraction (`github.com/shirou/gopsutil` in Go, or `sysinfo` crate in Rust).
  * Run a background ticker every 1000ms to poll hardware channels.

### Module B: Docker SDK Integration (`collector/docker.go`)
* **Objective:** Discover all active containers, collect live CPU/RAM metrics, and monitor status changes (Start/Stop/Crash).
* **Implementation Strategy:**
  * Auto-detect the OS runtime at startup:
    * **Linux:** Initialize SDK using `unix:///var/run/docker.sock`.
    * **Windows:** Initialize SDK using `npipe:////./pipe/docker_engine`.
  * Stream live stats using `cli.ContainerStats(ctx, containerID, stream=true)`.
  * Calculate CPU Percentage manually from raw cgroup values returned by the Docker API:
    $$\text{CPU \%} = \frac{\Delta \text{container\_cpu}}{\Delta \text{system\_cpu}} \times \text{number\_of\_cores} \times 100$$

### Module C: Docker Log Streamer (`collector/logs.go`)
* **Objective:** Read `stdout` and `stderr` streams directly from the Docker Engine API.
* **Implementation Strategy:**
  * Call `cli.ContainerLogs(ctx, containerID, types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "100"})`.
  * Strip the 8-byte Docker multiplexing header from the raw stream buffer to extract clean ASCII/UTF-8 log strings.
  * Push incoming log strings directly to the WebSocket channel and persist them to local storage.

### Module D: Storage Layer (`storage/db.go`)
* **Objective:** Lightweight metric aggregation and log searching.
* **Engine Choices:**
  * **SQLite / DuckDB:** Excellent choice for storing metric time-series data locally without needing an external service.
  * **Memory Ring Buffer:** For real-time UI streaming with lower disk write overhead.

### Module E: API & WebSocket Layer (`api/server.go`)
* **Endpoints:**
  * `GET /api/v1/host` — Current host hardware stats.
  * `GET /api/v1/containers` — List of containers and their operational states.
  * `GET /api/v1/containers/:id/logs` — Query historical logs.
  * `WS /ws/stream` — Real-time stream for metrics and logs.

---

## 5. Unified Single Cross-Platform Docker Deployment

Instead of requiring complex compose files or multi-container stacks, package the single compiled binary and static frontend inside a unified `Dockerfile`.

### `Dockerfile` (Multi-Stage Build)

```dockerfile
# Stage 1: Build Frontend UI
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# Stage 2: Build Cross-Platform Backend Executable
FROM golang:1.22-alpine AS backend-builder
WORKDIR /app
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ .
# Copy compiled frontend into backend for static embedding
COPY --from=frontend-builder /app/frontend/dist ./cmd/server/dist
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o monitoring-server ./cmd/server

# Stage 3: Minimal Runtime Container Image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=backend-builder /app/monitoring-server .

EXPOSE 8080

ENTRYPOINT ["./monitoring-server"]
```

---

## 6. How to Build & Run on Both OS Environments

### 1. Running on Kali Linux (Bash)
Build the image locally:
```bash
docker build -t custom-monitor:latest .
```

Run the container mounting the Linux Unix Socket and host stats:
```bash
docker run -d \
  --name custom-monitor \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  custom-monitor:latest
```

### 2. Running on Windows (PowerShell)
Build the image locally:
```powershell
docker build -t custom-monitor:latest .
```

Run the container mounting the Windows Docker Named Pipe:
```powershell
docker run -d `
  --name custom-monitor `
  --restart unless-stopped `
  -p 8080:8080 `
  -v //./pipe/docker_engine://./pipe/docker_engine `
  custom-monitor:latest
```

---

## 7. Development Roadmap for Claude Code Generation

When prompting Claude to generate code for this system, follow this sequence:

1. **Prompt 1 (Backend Core):** "Write a Go backend server that initializes a cross-platform Docker SDK client supporting both Linux Unix Sockets and Windows Named Pipes. Include functions to list running containers and stream container logs."
2. **Prompt 2 (Hardware Metrics):** "Add host metric collection using `gopsutil` to measure CPU, RAM, Disk, and Network stats. Stream these values alongside Docker stats using WebSockets."
3. **Prompt 3 (Embedded Database):** "Integrate an embedded SQLite database using `modernc.org/sqlite` to persist host/container metrics for up to 24 hours."
4. **Prompt 4 (Frontend UI):** "Build a single-page React UI using Tailwind CSS and Recharts that connects to the WebSocket endpoint to display live system gauges, container cards, and searchable log outputs."