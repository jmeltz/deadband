package server

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// Next's static export contains route.html alongside route/ RSC payload
// directories. Resolve the HTML page before directories and never list a
// directory or fall back to the dashboard for a different exported route.
func staticFrontend(files fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		name := strings.Trim(path.Clean("/"+r.URL.Path), "/")
		candidates := []string{name}
		if name == "" {
			candidates = []string{"index.html"}
		} else if path.Ext(name) == "" {
			candidates = append(candidates, name+".html", name+"/index.html")
		}
		for _, candidate := range candidates {
			info, err := fs.Stat(files, candidate)
			if err != nil || info.IsDir() {
				continue
			}
			file, err := files.Open(candidate)
			if err != nil {
				continue
			}
			defer file.Close()
			w.Header().Del("Content-Type")
			if seeker, ok := file.(io.ReadSeeker); ok {
				http.ServeContent(w, r, info.Name(), info.ModTime(), seeker)
				return
			}
			content, err := io.ReadAll(file)
			if err != nil {
				http.Error(w, "could not read frontend asset", 500)
				return
			}
			http.ServeContent(w, r, info.Name(), info.ModTime(), bytes.NewReader(content))
			return
		}
		http.NotFound(w, r)
	})
}
