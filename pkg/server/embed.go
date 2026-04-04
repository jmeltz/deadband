//go:build embed_web

package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:static
var webFS embed.FS

func mountFrontend(mux *http.ServeMux) {
	sub, err := fs.Sub(webFS, "static")
	if err != nil {
		return
	}
	fileServer := http.FileServer(http.FS(sub))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Don't serve frontend for API routes
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		// Try to serve the file directly
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		// Check if file exists
		if _, err := fs.Stat(sub, strings.TrimPrefix(path, "/")); err != nil {
			// SPA fallback: serve index.html for client-side routing
			r.URL.Path = "/"
		}

		w.Header().Del("Content-Type") // Let FileServer detect
		fileServer.ServeHTTP(w, r)
	})
}
