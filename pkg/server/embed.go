//go:build embed_web

package server

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:static
var webFS embed.FS

func mountFrontend(mux *http.ServeMux) {
	sub, err := fs.Sub(webFS, "static")
	if err != nil {
		return
	}
	mux.Handle("/", staticFrontend(sub))
}
