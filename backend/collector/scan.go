package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// trivyReport models just the slice of Trivy's `image --format json` output we
// need. Trivy may emit several Results segments (os-pkgs, library-pkgs, …); we
// flatten every segment's Vulnerabilities into one list.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ScanImage runs Trivy against a local image reference and returns the
// normalised vulnerability set. The scan executes on whatever host runs this
// DockerClient (local daemon or a remote agent), so the image and the Trivy DB
// are both host-local. Returns ErrScannerNotAvailable when the binary is absent.
func (dc *DockerClient) ScanImage(ctx context.Context, ref string, opts ScanOptions) (ImageVulnScan, error) {
	var out ImageVulnScan

	bin := opts.Binary
	if bin == "" {
		bin = "trivy"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return out, ErrScannerNotAvailable
	}

	// Resolve ref → full image ID + a scannable target (a real tag when present,
	// else the sha256 ID, which Trivy resolves against the local daemon).
	insp, _, err := dc.CLI.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		return out, fmt.Errorf("collector: ScanImage inspect(%s): %w", ref, err)
	}
	target := ref
	for _, t := range insp.RepoTags {
		if t != "" && !strings.Contains(t, "<none>") {
			target = t
			break
		}
	}
	if target == ref && strings.HasPrefix(ref, "sha256:") {
		target = ref
	}

	severities := opts.Severities
	if severities == "" {
		severities = "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, bin,
		"image", "--format", "json", "--quiet", "--severity", severities, target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// A context deadline shows up as ctx.Err(); report it distinctly.
		if scanCtx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("collector: ScanImage(%s): timed out after %s", target, timeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return out, fmt.Errorf("collector: ScanImage(%s): trivy: %s", target, msg)
	}

	var rep trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		return out, fmt.Errorf("collector: ScanImage(%s): parse trivy json: %w", target, err)
	}

	out.Ref = target
	out.ImageID = insp.ID
	out.Scanner = bin
	out.ScannedAt = time.Now().UTC()
	out.Counts = map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

	seen := map[string]bool{}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue // dedupe across os-pkg / library-pkg segments
			}
			seen[key] = true
			sev := strings.ToUpper(v.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}
			out.Counts[sev]++
			out.Vulnerabilities = append(out.Vulnerabilities, Vulnerability{
				CVEID:            v.VulnerabilityID,
				Package:          v.PkgName,
				Severity:         sev,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Title:            v.Title,
			})
		}
	}
	if out.Vulnerabilities == nil {
		out.Vulnerabilities = []Vulnerability{} // marshal as [] not null
	}
	return out, nil
}
