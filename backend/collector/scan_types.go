package collector

import "time"

// ─────────────────────────────────────────────────────────────────────────────
// Image vulnerability scanning + container security posture (Phase 6). These
// types are shared by the local DockerClient and the multi-host agent RPC layer,
// so they live in an untagged file and use snake_case JSON for the REST/WS wire
// format.
// ─────────────────────────────────────────────────────────────────────────────

// ScanOptions configures a Trivy image scan. Zero values fall back to the
// defaults set by the API layer (binary "trivy", all severities, 10 m timeout).
type ScanOptions struct {
	Binary     string        `json:"binary"`     // trivy binary name/path (PATH lookup)
	Severities string        `json:"severities"` // comma list, e.g. "CRITICAL,HIGH"
	Timeout    time.Duration `json:"timeout"`    // overall scan deadline
}

// Vulnerability is one CVE finding for a package inside an image.
type Vulnerability struct {
	CVEID            string `json:"cve_id"`
	Package          string `json:"package"`
	Severity         string `json:"severity"` // CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"` // "" = no fix available yet
	Title            string `json:"title,omitempty"`
}

// ImageVulnScan is the normalised result of scanning one image. Counts holds
// per-severity totals (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN). An empty Vulnerabilities
// list means the image was scanned and found clean (not an error).
type ImageVulnScan struct {
	Ref             string          `json:"ref"`
	ImageID         string          `json:"image_id"`
	Scanner         string          `json:"scanner"` // e.g. "trivy"
	ScannedAt       time.Time       `json:"scanned_at"`
	Counts          map[string]int  `json:"counts"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// ContainerSecurity is the live security posture of one container, read from
// `docker inspect`. It is never persisted — always recomputed on demand.
type ContainerSecurity struct {
	ContainerID    string          `json:"container_id"`
	Name           string          `json:"name"`
	Image          string          `json:"image"`
	HostID         string          `json:"host_id"`
	HostName       string          `json:"host_name"`
	Privileged     bool            `json:"privileged"`
	Root           bool            `json:"root"` // runs as uid 0 / root user
	CapAdd         []string        `json:"cap_add,omitempty"`
	User           string          `json:"user"`
	HostNetwork    bool            `json:"host_network"`
	HostPid        bool            `json:"host_pid"`
	ReadonlyRootfs bool            `json:"readonly_rootfs"`
	ExposedPorts   []ContainerPort `json:"exposed_ports,omitempty"`
}
