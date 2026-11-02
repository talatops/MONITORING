//go:build !linux

package collector

import "context"

// StreamKernelEvents is Linux-only. On other platforms it emits nothing and
// blocks until ctx is cancelled, then closes out, so callers can range over the
// channel uniformly.
func StreamKernelEvents(ctx context.Context, out chan<- KernelEvent) {
	defer close(out)
	<-ctx.Done()
}
