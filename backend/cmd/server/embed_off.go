//go:build !embed
// +build !embed

// Default build (no -tags flag): staticFS is nil, so the Go binary serves only
// the REST API and WebSocket endpoints. Use the Vite dev server on :5173
// alongside this binary for local development.

package main

import "io/fs"

// staticFS is always nil in non-embed builds; SetStaticFS is a no-op.
var staticFS fs.FS
