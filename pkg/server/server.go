package server

import (
	"log"
	"net/http"
	"path/filepath"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/enrichment"
)

// Server is the deadband HTTP API server.
type Server struct {
	db     *advisory.Database
	edb    *enrichment.DB
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

	// Load enrichment data (KEV/EPSS) from same directory as advisory DB
	edb := enrichment.LoadFromDir(filepath.Dir(dbPath))

	s := &Server{
		db:     db,
		edb:    edb,
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
	s.mux.HandleFunc("GET /api/enrichment/stats", s.handleEnrichmentStats)
	s.mux.HandleFunc("GET /api/compliance/mappings", handleComplianceMappings)
	s.mux.HandleFunc("GET /api/baseline", s.handleGetBaseline)
	s.mux.HandleFunc("POST /api/baseline", s.handleSaveBaseline)
	s.mux.HandleFunc("POST /api/baseline/compare", s.handleCompareBaseline)
	s.mux.HandleFunc("GET /api/assets", s.handleGetAssets)
	s.mux.HandleFunc("POST /api/assets", s.handleImportAssets)
	s.mux.HandleFunc("PUT /api/assets/{id}", s.handleUpdateAsset)
	s.mux.HandleFunc("DELETE /api/assets/{id}", s.handleDeleteAsset)
	s.mux.HandleFunc("POST /api/assets/bulk", s.handleBulkUpdateAssets)

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

// reloadDB reloads the advisory database and enrichment data from disk.
func (s *Server) reloadDB() error {
	db, err := advisory.LoadDatabase(s.dbPath)
	if err != nil {
		return err
	}
	s.db = db
	s.edb = enrichment.LoadFromDir(filepath.Dir(s.dbPath))
	return nil
}
