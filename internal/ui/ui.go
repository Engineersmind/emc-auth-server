package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

// dist holds the embedded React SPA build output.
// The "dist" directory is produced by `npm run build` in the ui/ directory
// (with outDir set to '../internal/ui/dist' in vite.config.ts).
//
//go:embed dist
var dist embed.FS

// StaticFS returns the embedded dist/ directory as an http.FileSystem.
// Usage: http.FileServer(ui.StaticFS())
func StaticFS() http.FileSystem {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("ui: failed to sub dist/ from embed: " + err.Error())
	}
	return http.FS(sub)
}

// EmbedFS returns the raw embed.FS for use with echo.FileFS etc.
func EmbedFS() embed.FS {
	return dist
}
