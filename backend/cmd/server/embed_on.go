//go:build embed
// +build embed

// Activated with: go build -tags embed ./cmd/server
// This variant bundles the compiled React SPA into the binary.
// Requires `cd frontend && npm run build && cp -r dist ../cmd/server/dist`
// before compiling (the Dockerfile in general.md §5 does this automatically).

package main

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distEmbedFS embed.FS

// staticFS is the "dist" sub-tree extracted from the full embed.
// api.Server.SetStaticFS expects a root-unscoped fs.FS.
var staticFS fs.FS

func init() {
	sub, err := fs.Sub(distEmbedFS, "dist")
	if err != nil {
		panic("cmd/server: fs.Sub(dist): " + err.Error())
	}
	staticFS = sub
}
