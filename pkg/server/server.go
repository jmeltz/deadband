package server

import (
	"log"
	"net/http"
	"path/filepath"

	"github.com/jmeltz/deadband/pkg/acl"
	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/enrichment"
	"github.com/jmeltz/deadband/pkg/asa"
	"github.com/jmeltz/deadband/pkg/integration"
	"github.com/jmeltz/deadband/pkg/posture"
	"github.com/jmeltz/deadband/pkg/sentinel"
	"github.com/jmeltz/deadband/pkg/site"
)

// Server is the deadband HTTP API server.
type Server struct {
	db                *advisory.Database
	edb               *enrichment.DB
	dbPath            string
	addr              string
	mux               *http.ServeMux
	scheduler         *discover.Scheduler
	siteStore         *site.Store
	postureStore      *posture.Store
	controlStateStore *posture.ControlStateStore
	aclStore          *acl.Store
	integrationStore  *integration.Store
	sentinelStore     *sentinel.Store
	asaSnapshotStore  *asa.Store
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

	// Load site store
	s.siteStore = site.LoadStore(site.DefaultStorePath())

	// Load posture store
	s.postureStore = posture.LoadStore(posture.DefaultStorePath())

	// Load control state store
	s.controlStateStore = posture.LoadControlStateStore(posture.DefaultControlStatePath())

	// Load ACL policy store
	s.aclStore = acl.LoadStore(acl.DefaultStorePath())

	// Load integration config store
	s.integrationStore = integration.LoadStore(integration.DefaultStorePath())

	// Load Sentinel flow store
	s.sentinelStore = sentinel.LoadStore(sentinel.DefaultStorePath())

	// Load ASA snapshot store
	s.asaSnapshotStore = asa.LoadStore(asa.DefaultStorePath())

	// Start discovery scheduler
	schedStore := discover.LoadScheduleStore(discover.DefaultScheduleStorePath())
	s.scheduler = discover.NewScheduler(schedStore, func(sched discover.Schedule) {
		s.runScheduledDiscovery(sched)
	})
	s.scheduler.Start()

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
	s.mux.HandleFunc("GET /api/discover/jobs/{id}", s.handleDiscoverStatus)
	s.mux.HandleFunc("GET /api/discover/jobs/{id}/events", s.handleDiscoverEvents)
	s.mux.HandleFunc("POST /api/diff", s.handleDiff)
	s.mux.HandleFunc("POST /api/diff/upload", s.handleDiffUpload)
	s.mux.HandleFunc("POST /api/update", s.handleUpdate)
	s.mux.HandleFunc("GET /api/update/events", s.handleUpdateEvents)
	s.mux.HandleFunc("POST /api/reports/html", s.handleExportReport)
	s.mux.HandleFunc("GET /api/enrichment/stats", s.handleEnrichmentStats)
	s.mux.HandleFunc("GET /api/compliance/mappings", handleComplianceMappings)
	s.mux.HandleFunc("GET /api/baseline", s.handleGetBaseline)
	s.mux.HandleFunc("POST /api/baseline", s.handleSaveBaseline)
	s.mux.HandleFunc("POST /api/baseline/compare", s.handleCompareBaseline)
	s.mux.HandleFunc("GET /api/assets", s.handleGetAssets)
	s.mux.HandleFunc("GET /api/assets/{id}", s.handleGetAsset)
	s.mux.HandleFunc("POST /api/assets", s.handleImportAssets)
	s.mux.HandleFunc("POST /api/assets/check", s.handleCheckAssets)
	s.mux.HandleFunc("PUT /api/assets/{id}", s.handleUpdateAsset)
	s.mux.HandleFunc("DELETE /api/assets/{id}", s.handleDeleteAsset)
	s.mux.HandleFunc("POST /api/assets/bulk", s.handleBulkUpdateAssets)
	s.mux.HandleFunc("GET /api/assets/summary", s.handleAssetSummary)
	s.mux.HandleFunc("GET /api/assets/export", s.handleAssetExport)
	s.mux.HandleFunc("GET /api/discover/history", s.handleDiscoverHistory)
	s.mux.HandleFunc("GET /api/discover/history/{id}", s.handleDiscoverHistoryDetail)
	s.mux.HandleFunc("GET /api/discover/schedules", s.handleGetSchedules)
	s.mux.HandleFunc("POST /api/discover/schedule", s.handleCreateSchedule)
	s.mux.HandleFunc("DELETE /api/discover/schedule/{id}", s.handleDeleteSchedule)

	// Sites
	s.mux.HandleFunc("GET /api/sites", s.handleGetSites)
	s.mux.HandleFunc("POST /api/sites", s.handleUpsertSite)
	s.mux.HandleFunc("GET /api/sites/{id}", s.handleGetSite)
	s.mux.HandleFunc("DELETE /api/sites/{id}", s.handleDeleteSite)
	s.mux.HandleFunc("POST /api/sites/reassign", s.handleReassignSites)

	// Zones (nested under sites)
	s.mux.HandleFunc("GET /api/sites/{id}/zones", s.handleGetZones)
	s.mux.HandleFunc("POST /api/sites/{id}/zones", s.handleUpsertZone)
	s.mux.HandleFunc("DELETE /api/sites/{id}/zones/{zoneId}", s.handleDeleteZone)

	// Asset bundle import
	s.mux.HandleFunc("POST /api/assets/import/dbd", s.handleImportDBD)

	// Posture analysis
	s.mux.HandleFunc("POST /api/posture/scan", s.handlePostureScan)
	s.mux.HandleFunc("GET /api/posture", s.handleGetPosture)
	s.mux.HandleFunc("GET /api/posture/reports", s.handleListPostureReports)
	s.mux.HandleFunc("GET /api/posture/reports/{id}", s.handleGetPostureReport)
	s.mux.HandleFunc("GET /api/posture/findings", s.handleGetFindings)
	s.mux.HandleFunc("GET /api/posture/controls", s.handleGetControlMappings)
	s.mux.HandleFunc("GET /api/posture/host/{ip}", s.handleGetPostureHost)

	// Control states + risk simulation
	s.mux.HandleFunc("GET /api/posture/control-states", s.handleGetControlStates)
	s.mux.HandleFunc("POST /api/posture/control-states", s.handleSetControlState)
	s.mux.HandleFunc("POST /api/posture/simulate", s.handleRiskSimulation)

	// Integrations
	s.mux.HandleFunc("GET /api/integrations/sentinel", s.handleGetSentinelConfigs)
	s.mux.HandleFunc("POST /api/integrations/sentinel", s.handleUpsertSentinelConfig)
	s.mux.HandleFunc("DELETE /api/integrations/sentinel/{id}", s.handleDeleteSentinelConfig)
	s.mux.HandleFunc("POST /api/integrations/sentinel/{id}/test", s.handleTestSentinelConfig)
	s.mux.HandleFunc("GET /api/integrations/asa", s.handleGetASAConfigs)
	s.mux.HandleFunc("POST /api/integrations/asa", s.handleUpsertASAConfig)
	s.mux.HandleFunc("DELETE /api/integrations/asa/{id}", s.handleDeleteASAConfig)
	s.mux.HandleFunc("POST /api/integrations/asa/{id}/test", s.handleTestASAConfig)
	s.mux.HandleFunc("POST /api/integrations/sentinel/{id}/query", s.handleQuerySentinel)
	s.mux.HandleFunc("GET /api/integrations/sentinel/{id}/query/events", s.handleQuerySentinelEvents)
	s.mux.HandleFunc("POST /api/integrations/asa/{id}/collect", s.handleCollectASA)
	s.mux.HandleFunc("GET /api/integrations/asa/{id}/collect/events", s.handleCollectASAEvents)

	// Sentinel data views
	s.mux.HandleFunc("GET /api/sentinel/snapshots", s.handleGetSentinelSnapshots)
	s.mux.HandleFunc("GET /api/sentinel/snapshots/{id}", s.handleGetSentinelSnapshot)
	s.mux.HandleFunc("GET /api/sentinel/traffic-summary", s.handleGetTrafficSummary)
	s.mux.HandleFunc("POST /api/sentinel/scoping", s.handleScopingRecommendations)

	// ASA data views
	s.mux.HandleFunc("GET /api/asa/snapshots", s.handleGetASASnapshots)
	s.mux.HandleFunc("GET /api/asa/snapshots/{id}", s.handleGetASASnapshot)
	s.mux.HandleFunc("POST /api/asa/drift", s.handleAnalyzeDrift)

	// ACL policies
	s.mux.HandleFunc("GET /api/acl/policies", s.handleGetPolicies)
	s.mux.HandleFunc("POST /api/acl/policies", s.handleUpsertPolicy)
	s.mux.HandleFunc("DELETE /api/acl/policies/{id}", s.handleDeletePolicy)
	s.mux.HandleFunc("POST /api/acl/policies/generate", s.handleGenerateDefaultPolicy)
	s.mux.HandleFunc("POST /api/acl/policies/{id}/analyze", s.handleAnalyzeGaps)

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
