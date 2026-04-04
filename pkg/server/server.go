package server

import (
	"log"
	"net/http"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/cli"
)

// Server is the deadband HTTP API server.
type Server struct {
	db     *advisory.Database
	dbPath string
	addr   string
	mux    *http.ServeMux
}

// New creates a new Server that serves the deadband API.
// If the advisory database doesn't exist, the server starts with an empty DB
// and triggers a background update automatically.
func New(addr, dbPath string) (*Server, error) {
	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		log.Printf("[deadband] No advisory database found, starting with empty DB")
		db = &advisory.Database{}
	}

	s := &Server{
		db:     db,
		dbPath: dbPath,
		addr:   addr,
		mux:    http.NewServeMux(),
	}
	s.routes()

	if len(db.Advisories) == 0 {
		s.startBackgroundUpdate()
	}

	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/db/stats", s.handleDBStats)
	s.mux.HandleFunc("GET /api/advisories", s.handleAdvisories)
	s.mux.HandleFunc("GET /api/advisories/{id}", s.handleAdvisory)
	s.mux.HandleFunc("POST /api/check", s.handleCheck)
	s.mux.HandleFunc("POST /api/check/upload", s.handleCheckUpload)
	s.mux.HandleFunc("POST /api/discover", s.handleDiscover)
	s.mux.HandleFunc("GET /api/discover/{id}", s.handleDiscoverStatus)
	s.mux.HandleFunc("GET /api/discover/{id}/events", s.handleDiscoverEvents)
	s.mux.HandleFunc("POST /api/diff", s.handleDiff)
	s.mux.HandleFunc("POST /api/diff/upload", s.handleDiffUpload)
	s.mux.HandleFunc("POST /api/update", s.handleUpdate)
	s.mux.HandleFunc("GET /api/update/events", s.handleUpdateEvents)

	// Serve embedded frontend if available
	mountFrontend(s.mux)
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	handler := corsMiddleware(jsonMiddleware(s.mux))
	log.Printf("[deadband] API server v%s listening on %s", cli.Version, s.addr)
	log.Printf("[deadband] %s", s.db.Stats())
	return http.ListenAndServe(s.addr, handler)
}

// reloadDB reloads the advisory database from disk.
func (s *Server) reloadDB() error {
	db, err := advisory.LoadDatabase(s.dbPath)
	if err != nil {
		return err
	}
	s.db = db
	return nil
}
