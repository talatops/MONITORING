//go:build linux

package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// StreamKernelEvents mines the kernel log and pushes classified events onto out.
// Source preference: systemd journal (journalctl -k -f) → /dev/kmsg → dmesg
// --follow, so it works on full distros and on WSL2/container images without a
// journal. It blocks until ctx is cancelled and then closes out, so callers can
// simply `for ev := range ch`.
func StreamKernelEvents(ctx context.Context, out chan<- KernelEvent) {
	defer close(out)
	switch {
	case journaldAvailable(ctx):
		log.Println("collector: kernel miner using journald")
		streamJournald(ctx, out)
	case kmsgAvailable():
		log.Println("collector: kernel miner using /dev/kmsg")
		streamKmsg(ctx, out)
	default:
		log.Println("collector: kernel miner using dmesg --follow")
		streamDmesg(ctx, out)
	}
}

// journaldAvailable probes journald once (short timeout) so hosts without a
// journal fall through to the raw ring-buffer readers.
func journaldAvailable(ctx context.Context) bool {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// -n 0 reads nothing but still validates the journal is reachable.
	return exec.CommandContext(probeCtx, "journalctl", "-k", "-n", "0", "-o", "json", "-q").Run() == nil
}

func kmsgAvailable() bool {
	_, err := os.OpenFile("/dev/kmsg", os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	// Immediately reopen for reading; existence + openability is what we test.
	if f, err := os.Open("/dev/kmsg"); err == nil {
		f.Close()
		return true
	}
	return false
}

// streamJournald bootstraps the last 200 kernel lines then follows, decoding
// journald's JSON records.
func streamJournald(ctx context.Context, out chan<- KernelEvent) {
	cmd := exec.CommandContext(ctx, "journalctl", "-k", "-n", "200", "-o", "json", "-f", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("collector: journalctl stdout: %v", err)
		return
	}
	defer stdout.Close()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec map[string]string
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		msg := rec["MESSAGE"]
		if strings.TrimSpace(msg) == "" {
			continue
		}
		emitKernel(ctx, out, KernelEvent{Ts: journalTime(rec["__REALTIME_TIMESTAMP"]), Source: "journald", Message: msg})
		if ctx.Err() != nil {
			return
		}
	}
}

// streamKmsg reads the raw kernel ring buffer. Each record is
// "priority,seq,usec,flags;MESSAGE"; the wall clock is monotonic, so live
// events are timestamped on arrival.
func streamKmsg(ctx context.Context, out chan<- KernelEvent) {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		log.Printf("collector: open /dev/kmsg: %v", err)
		return
	}
	defer f.Close()
	// Unblock the scanner's blocking read when ctx ends.
	go func() {
		<-ctx.Done()
		f.Close()
	}()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		msg := line
		if i := strings.Index(line, ";"); i >= 0 {
			msg = line[i+1:]
		}
		if strings.TrimSpace(msg) == "" {
			continue
		}
		emitKernel(ctx, out, KernelEvent{Ts: time.Now(), Source: "kmsg", Message: msg})
		if ctx.Err() != nil {
			return
		}
	}
}

// streamDmesg is the last-resort reader: util-linux `dmesg --follow` with human
// readable timestamps. Busybox dmesg lacks --follow; it then simply yields no
// stream, which is an acceptable degraded mode.
func streamDmesg(ctx context.Context, out chan<- KernelEvent) {
	cmd := exec.CommandContext(ctx, "dmesg", "--level=err,warn", "-T", "--follow")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("collector: dmesg stdout: %v", err)
		return
	}
	defer stdout.Close()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		msg := strings.TrimSpace(sc.Text())
		if msg == "" {
			continue
		}
		emitKernel(ctx, out, KernelEvent{Ts: time.Now(), Source: "dmesg", Message: msg})
		if ctx.Err() != nil {
			return
		}
	}
}

// emitKernel annotates an event (classification + container correlation) and
// does a context-aware send so a stalled consumer never wedges the reader.
func emitKernel(ctx context.Context, out chan<- KernelEvent, ev KernelEvent) {
	ev.Category, ev.Severity = classifyKernelMessage(ev.Message)
	ev.ContainerID = extractContainerID(ev.Message)
	select {
	case out <- ev:
	case <-ctx.Done():
	}
}

// journalTime parses a journald __REALTIME_TIMESTAMP (microseconds since the
// epoch) falling back to now when absent or unparseable.
func journalTime(us string) time.Time {
	if us == "" {
		return time.Now()
	}
	n, err := strconv.ParseInt(us, 10, 64)
	if err != nil {
		return time.Now()
	}
	return time.UnixMicro(n)
}

// ── Classification ─────────────────────────────────────────────────────────

var (
	reOOM        = regexp.MustCompile(`(?i)out of memory|oom-kill|oom_kill|killed process|oom_reaper`)
	reExt4       = regexp.MustCompile(`(?i)ext4-fs error|ext4.*error|aborting journal`)
	reThermal    = regexp.MustCompile(`(?i)thermal|temperature above|throttl`)
	reSegfault   = regexp.MustCompile(`(?i)segfault`)
	reHung       = regexp.MustCompile(`(?i)hung task|blocked for more than|\btask\b.*blocked`)
	reSoftLockup = regexp.MustCompile(`(?i)soft lockup|BUG:.*lockup`)
	reReadOnly   = regexp.MustCompile(`(?i)remounting filesystem read-only|read-only file system`)
)

// classifyKernelMessage returns (category, severity) for a raw kernel line.
// Severity maps to UI badge colours: crit=red, warn=amber, info=gray.
func classifyKernelMessage(msg string) (string, string) {
	switch {
	case reOOM.MatchString(msg):
		return "oom_kill", "crit"
	case reExt4.MatchString(msg):
		return "ext4_error", "crit"
	case reReadOnly.MatchString(msg):
		return "fs_readonly", "crit"
	case reSoftLockup.MatchString(msg):
		return "soft_lockup", "crit"
	case reHung.MatchString(msg):
		return "hung_task", "warn"
	case reThermal.MatchString(msg):
		return "thermal", "warn"
	case reSegfault.MatchString(msg):
		return "segfault", "warn"
	default:
		return "other", "info"
	}
}

// dockerHex matches a 64-hex container/cgroup id (docker scope names, cgroup
// paths, and "docker-<id>" tokens embedded in OOM/cgroup messages).
var dockerHex = regexp.MustCompile(`[0-9a-f]{64}`)

// extractContainerID best-effort correlates a kernel message to a Docker
// container by pulling the first full 64-hex id from it. Kernel OOM lines
// reference the cgroup path (…/docker-<64hex>.scope), which this catches.
func extractContainerID(msg string) string {
	if m := dockerHex.FindString(msg); m != "" {
		return m
	}
	return ""
}
