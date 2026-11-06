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

// trivyReport models the slice of Trivy's `image --format json` output we need.
// Trivy emits several Results segments by Class (os-pkgs/package-pkgs for CVEs,
// secret for leaked secrets, config for misconfigs); we flatten every segment.
type trivyReport struct {
	Results []struct {
		Class string `json:"Class"`
		Type  string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID   string `json:"RuleID"`
			Category string `json:"Category"`
			Severity string `json:"Severity"`
			Title    string `json:"Title"`
			Match    string `json:"Match"`
			Location struct {
				File string `json:"File"`
			} `json:"Location"`
		} `json:"Secrets"`
		Misconfigurations []struct {
			ID         string   `json:"ID"`
			Title      string   `json:"Title"`
			Severity   string   `json:"Severity"`
			Resolution string   `json:"Resolution"`
			Messages   []string `json:"Messages"`
		} `json:"Misconfigurations"`
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
	target, imageID, err := dc.resolveTarget(ctx, ref)
	if err != nil {
		return out, err
	}

	severities := opts.Severities
	if severities == "" {
		severities = "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN"
	}
	modes := opts.Modes
	if modes == "" {
		modes = "vuln"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, bin,
		"image", "--format", "json", "--quiet", "--severity", severities, "--scanners", modes, target)
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
	out.ImageID = imageID
	out.Scanner = bin
	out.ScannedAt = time.Now().UTC()
	out.Counts = map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

	seenCVE := map[string]bool{}
	seenSec := map[string]bool{}
	seenMis := map[string]bool{}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.PkgName
			if seenCVE[key] {
				continue // dedupe across os-pkg / library-pkg segments
			}
			seenCVE[key] = true
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
		for _, s := range r.Secrets {
			key := s.RuleID + "|" + s.Location.File
			if seenSec[key] {
				continue
			}
			seenSec[key] = true
			out.Secrets = append(out.Secrets, SecretFinding{
				RuleID:   s.RuleID,
				Severity: strings.ToUpper(s.Severity),
				Category: s.Category,
				Title:    s.Title,
				Match:    s.Match,
				File:     s.Location.File,
			})
		}
		for _, m := range r.Misconfigurations {
			key := m.ID + "|" + m.Title
			if seenMis[key] {
				continue
			}
			seenMis[key] = true
			out.Misconfigurations = append(out.Misconfigurations, MisconfigFinding{
				ID:         m.ID,
				Title:      m.Title,
				Severity:   strings.ToUpper(m.Severity),
				Resolution: m.Resolution,
				Type:       r.Type,
				Messages:   m.Messages,
			})
		}
	}
	if out.Vulnerabilities == nil {
		out.Vulnerabilities = []Vulnerability{} // marshal as [] not null
	}
	out.SecretCount = len(out.Secrets)
	out.MisconfigCount = len(out.Misconfigurations)
	return out, nil
}

// resolveTarget maps an image reference to a Trivy-scannable target plus its
// full image ID. Prefers the first real tag; falls back to the given ref (which
// Trivy resolves against the local daemon when it is a sha256: ID).
func (dc *DockerClient) resolveTarget(ctx context.Context, ref string) (target, imageID string, err error) {
	insp, _, err := dc.CLI.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		return "", "", fmt.Errorf("collector: image inspect(%s): %w", ref, err)
	}
	target = ref
	for _, t := range insp.RepoTags {
		if t != "" && !strings.Contains(t, "<none>") {
			target = t
			break
		}
	}
	return target, insp.ID, nil
}

// ScanSBOM runs Trivy to produce a CycloneDX (default) or SPDX bill-of-materials
// for one image and returns the raw JSON plus a suggested download filename. It
// executes on the host owning the image, so it is reachable via agent RPC like
// ScanImage. Returns ErrScannerNotAvailable when Trivy is absent.
func (dc *DockerClient) ScanSBOM(ctx context.Context, ref string, opts SBOMOptions) (json.RawMessage, string, error) {
	bin := opts.Binary
	if bin == "" {
		bin = "trivy"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, "", ErrScannerNotAvailable
	}
	format := strings.ToLower(opts.Format)
	ext := ".cdx.json"
	if format == "spdx" {
		ext = ".spdx.json"
	} else {
		format = "cyclonedx"
	}
	target, imageID, err := dc.resolveTarget(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	sbomCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(sbomCtx, bin, "image", "--format", format, "--quiet", target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if sbomCtx.Err() == context.DeadlineExceeded {
			return nil, "", fmt.Errorf("collector: ScanSBOM(%s): timed out after %s", target, timeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, "", fmt.Errorf("collector: ScanSBOM(%s): trivy: %s", target, msg)
	}
	name := sanitizeFilename(target) + ext
	if name == ext { // no usable tag → fall back to the image ID
		name = strings.TrimPrefix(imageID, "sha256:") + ext
	}
	return json.RawMessage(stdout.Bytes()), name, nil
}

// sanitizeFilename reduces an image ref to a safe download basename.
func sanitizeFilename(s string) string {
	rep := strings.NewReplacer("/", "_", ":", "_", "@", "_", " ", "_")
	return rep.Replace(s)
}
