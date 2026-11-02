package collector

import "errors"

// ErrNotSupported is returned by platform-gated collectors (cgroup v2 detail,
// kernel log mining) when the current build target does not implement them —
// i.e. everything non-Linux. The API layer maps it to HTTP 501.
var ErrNotSupported = errors.New("collector: not supported on this platform")

// ErrScannerNotAvailable is returned by ScanImage when no Trivy binary is found
// on the host that owns the image (PATH lookup fails). The API layer maps it to
// HTTP 501 for the local host so the UI can show a "scanner not installed" hint.
var ErrScannerNotAvailable = errors.New("collector: image scanner (trivy) not available on this host")
