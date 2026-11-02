package collector

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
)

// LogEntry represents a single cleaned-up container log line.
// Stream is either "stdout" or "stderr" as tagged by the Docker daemon.
type LogEntry struct {
	ContainerID string `json:"container_id"`
	Stream      string `json:"stream"` // "stdout" | "stderr"
	Line        string `json:"line"`
}

// LogStreamOptions configures a call to StreamContainerLogs.
type LogStreamOptions struct {
	// ShowStdout includes the stdout stream (default true).
	ShowStdout bool
	// ShowStderr includes the stderr stream (default true).
	ShowStderr bool
	// Follow keeps the stream open for new lines after existing logs are
	// drained (maps to Docker's `-f` flag). Default false.
	Follow bool
	// Tail limits how many historical lines are returned before the stream
	// switches to live mode. "all" returns every stored line. Default "100".
	Tail string
	// Since (RFC3339 timestamp) filters logs to entries after this time.
	// Leave empty for no filter.
	Since string
	// Timestamps prepends the Docker-recorded nanosecond UTC timestamp to
	// each log line. Default false.
	Timestamps bool
	// BufferSize sets the channel capacity for the returned LogEntry channel.
	// A value of 0 uses the default (256).
	BufferSize int
}

// DefaultLogStreamOptions returns sensible defaults matching general.md §Module C.
func DefaultLogStreamOptions() LogStreamOptions {
	return LogStreamOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "100",
		BufferSize: 256,
	}
}

// StreamContainerLogs opens a Docker Engine API log stream for containerID
// and returns a receive-only channel of LogEntry values.
//
// The caller MUST cancel the provided context (or defer a cancel) to stop the
// background reader goroutine and close the channel cleanly.
//
// Docker multiplexed stream format (8-byte header per frame):
//
//	byte  0      : stream type  (1=stdout, 2=stderr, 0=stdin)
//	bytes 1–3    : padding (zero)
//	bytes 4–7    : payload length as big-endian uint32
//	bytes 8…N    : raw log line (may contain embedded newlines)
//
// This function strips that header and emits each ASCII line individually.
func (dc *DockerClient) StreamContainerLogs(
	ctx context.Context,
	containerID string,
	opts LogStreamOptions,
) (<-chan LogEntry, error) {
	if containerID == "" {
		return nil, errors.New("collector: containerID must not be empty")
	}

	if opts.Tail == "" {
		opts.Tail = "100"
	}
	bufSize := opts.BufferSize
	if bufSize == 0 {
		bufSize = 256
	}

	logsResp, err := dc.CLI.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: opts.ShowStdout,
		ShowStderr: opts.ShowStderr,
		Follow:     opts.Follow,
		Tail:       opts.Tail,
		Since:      opts.Since,
		Timestamps: opts.Timestamps,
	})
	if err != nil {
		return nil, fmt.Errorf("collector: ContainerLogs(%s) failed: %w", containerID, err)
	}

	ch := make(chan LogEntry, bufSize)

	go func() {
		defer close(ch)
		defer logsResp.Close() //nolint:errcheck

		// bufio.Reader gives us precise control over reading the fixed-size
		// 8-byte header followed by a variable-length payload.
		reader := bufio.NewReader(logsResp)

		for {
			// Context cancellation is the intended shutdown signal.
			select {
			case <-ctx.Done():
				return
			default:
			}

			entry, readErr := readDockerLogFrame(reader, containerID)
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					return // stream ended naturally
				}
				// Context cancellation surfaces as a read error on the socket.
				if ctx.Err() != nil {
					return
				}
				return // non-recoverable; channel closes via defer
			}

			select {
			case ch <- entry:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

// readDockerLogFrame reads exactly one Docker multiplexed frame and returns a
// LogEntry. It handles both multiplexed (TTY-less) and raw (TTY-allocated)
// streams transparently.
func readDockerLogFrame(r *bufio.Reader, containerID string) (LogEntry, error) {
	// Peek the first 8 bytes to decide whether this is a multiplexed frame.
	// A valid header has byte[0] ∈ {0,1,2} and bytes[1..3] == 0.
	peek, err := r.Peek(8)
	if err != nil {
		// For raw TTY streams the entire response body is plain text with no
		// 8-byte framing. io.EOF here means the stream is truly done.
		return LogEntry{}, err
	}

	// If it looks like a valid Docker multiplexed header, decode it.
	if isDockerFrameHeader(peek) {
		header := make([]byte, 8)
		if _, err := io.ReadFull(r, header); err != nil {
			return LogEntry{}, fmt.Errorf("collector: short read on frame header: %w", err)
		}

		streamType := header[0]
		payloadLen := binary.BigEndian.Uint32(header[4:8])

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return LogEntry{}, fmt.Errorf("collector: short read on frame payload: %w", err)
		}

		stream := "stdout"
		if streamType == 2 {
			stream = "stderr"
		}

		return LogEntry{
			ContainerID: containerID,
			Stream:      stream,
			Line:        trimRight(payload),
		}, nil
	}

	// Raw / TTY path: no framing header — read one line as-is.
	// The scanner-based approach keeps memory bounded even for long lines.
	line, err := readRawLine(r)
	if err != nil {
		return LogEntry{}, err
	}
	return LogEntry{
		ContainerID: containerID,
		Stream:      "stdout",
		Line:        line,
	}, nil
}

// isDockerFrameHeader returns true when the first 8 bytes look like a valid
// Docker ENGINE stream multiplexing header.
func isDockerFrameHeader(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	// stream type must be 0 (stdin), 1 (stdout), or 2 (stderr)
	if b[0] > 2 {
		return false
	}
	// bytes 1-3 are always zero padding
	return b[1] == 0 && b[2] == 0 && b[3] == 0
}

// readRawLine reads a single newline-terminated line from a bufio.Reader
// without using bufio.Scanner (which can't mix with Peek-based framing).
func readRawLine(r *bufio.Reader) (string, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return string(buf), nil // last line without trailing \n
			}
			return "", err
		}
		if b == '\n' {
			return trimRight(buf), nil
		}
		buf = append(buf, b)
	}
}

// trimRight removes trailing \r and \n bytes from a byte slice converted to string.
func trimRight(b []byte) string {
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
