//go:build !embed_web

package server

import "net/http"

func mountFrontend(mux *http.ServeMux) {
	// No frontend embedded — API-only mode
}
