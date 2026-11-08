package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestStaticExportRouting(t *testing.T) {
	h := staticFrontend(fstest.MapFS{
		"index.html":          {Data: []byte("dashboard")},
		"assets.html":         {Data: []byte("assets page")},
		"assets/detail.html":  {Data: []byte("asset detail page")},
		"assets/__next.txt":   {Data: []byte("rsc payload")},
		"scan.html":           {Data: []byte("scan page")},
		"_next/static/app.js": {Data: []byte("app bundle")},
	})
	for _, tc := range []struct {
		path, want string
		status     int
	}{
		{"/", "dashboard", 200}, {"/assets", "assets page", 200}, {"/assets/", "assets page", 200},
		{"/assets/detail?id=sensor", "asset detail page", 200}, {"/scan", "scan page", 200},
		{"/assets/__next.txt", "rsc payload", 200}, {"/_next/static/app.js", "app bundle", 200},
		{"/assets/missing", "404", 404}, {"/api/missing", "404", 404}, {"/api", "404", 404}, {"/_next/static", "404", 404},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("%d %q", w.Code, w.Body.String())
			}
			if w.Header().Get("Location") != "" {
				t.Fatal("unexpected redirect", w.Header())
			}
		})
	}
}
