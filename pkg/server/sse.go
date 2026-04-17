package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"path/filepath"
	"strings"

	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/enrichment"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
	"github.com/jmeltz/deadband/pkg/posture"
	"github.com/jmeltz/deadband/pkg/updater"
)

func newJobID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Discovery job management ---

type jobStatus string

const (
	jobRunning  jobStatus = "running"
	jobComplete jobStatus = "complete"
	jobError    jobStatus = "error"
)

type discoverJob struct {
	ID       string              `json:"job_id"`
	Status   jobStatus           `json:"status"`
	Error    string              `json:"error,omitempty"`
	Devices  []inventory.Device  `json:"devices,omitempty"`
	Results  *checkResponse      `json:"check_results,omitempty"`
	Progress []string            `json:"progress,omitempty"`

	mu       sync.Mutex
	subs     []chan string
}

func (j *discoverJob) addProgress(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Progress = append(j.Progress, msg)
	for _, ch := range j.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (j *discoverJob) subscribe() chan string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch := make(chan string, 64)
	// Send buffered progress
	for _, msg := range j.Progress {
		ch <- msg
	}
	j.subs = append(j.subs, ch)
	return ch
}

func (j *discoverJob) complete(devices []inventory.Device, results *checkResponse, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Devices = devices
	j.Results = results
	if errMsg != "" {
		j.Status = jobError
		j.Error = errMsg
	} else {
		j.Status = jobComplete
	}
	// Signal completion to all subscribers
	for _, ch := range j.subs {
		close(ch)
	}
	j.subs = nil
}

var (
	discoverJobs   sync.Map
	discoverMu     sync.Mutex // Limits to one concurrent discovery
)

// runScheduledDiscovery executes a discovery scan triggered by the scheduler.
func (s *Server) runScheduledDiscovery(sched discover.Schedule) {
	if !discoverMu.TryLock() {
		log.Printf("[deadband] Scheduled scan for %s skipped: another scan is running", sched.CIDR)
		return
	}
	defer discoverMu.Unlock()

	log.Printf("[deadband] Scheduled scan starting: %s (mode: %s)", sched.CIDR, sched.Mode)
	startedAt := time.Now().UTC()

	mode := discover.DiscoveryMode(sched.Mode)
	if sched.Mode == "" {
		mode = discover.ModeAuto
	}

	opts := discover.Opts{
		CIDR:        sched.CIDR,
		Timeout:     2 * time.Second,
		HTTPTimeout: 5 * time.Second,
		Concurrency: 50,
		Mode:        mode,
		Progress: func(msg string) {
			log.Printf("[deadband] [sched:%s] %s", sched.ID[:8], msg)
		},
	}

	devices, err := discover.Run(opts)
	if err != nil {
		log.Printf("[deadband] Scheduled scan error: %v", err)
		s.persistJobRecord(sched.ID+"-"+fmt.Sprintf("%d", startedAt.Unix()), sched.CIDR, string(mode), "error", err.Error(), startedAt, 0, 0, 0)
		return
	}

	log.Printf("[deadband] Scheduled scan complete: %d devices found", len(devices))

	// Auto-import
	var importNew, importUpdated int
	if len(devices) > 0 {
		path := asset.DefaultPath()
		store := asset.LoadOrEmpty(path)
		result := store.Import(devices, "discovery")
		if s.siteStore != nil {
			s.siteStore.AssignAll(store.Assets)
		}
		if err := asset.Save(path, store); err != nil {
			log.Printf("[deadband] Warning: failed to save assets: %v", err)
		} else {
			importNew = result.Added
			importUpdated = result.Updated
		}
	}

	// Auto-check if configured
	if sched.AutoCheck && len(devices) > 0 {
		resp := s.runCheck(devices, "low", 0, "")
		s.writeVulnStateToAssets(devices, resp)
		log.Printf("[deadband] Scheduled check complete: %d vulnerable, %d potential",
			resp.Summary.Vulnerable, resp.Summary.Potential)
	}

	// Posture analysis
	s.runPostureAnalysis(sched.CIDR, func(msg string) {
		log.Printf("[deadband] [sched:%s] %s", sched.ID[:8], msg)
	})

	jobID := sched.ID + "-" + fmt.Sprintf("%d", startedAt.Unix())
	s.persistJobRecord(jobID, sched.CIDR, string(mode), "complete", "", startedAt, len(devices), importNew, importUpdated)
}

// --- Update job management ---

type updateJob struct {
	mu       sync.Mutex
	subs     []chan string
	done     bool
}

func (j *updateJob) addProgress(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, ch := range j.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (j *updateJob) finish() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	for _, ch := range j.subs {
		close(ch)
	}
	j.subs = nil
}

func (j *updateJob) subscribe() chan string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch := make(chan string, 64)
	j.subs = append(j.subs, ch)
	return ch
}

var (
	activeUpdate   *updateJob
	activeUpdateMu sync.Mutex
)

// startBackgroundUpdate kicks off an advisory DB update when the server starts with no data.
func (s *Server) startBackgroundUpdate() {
	activeUpdateMu.Lock()
	job := &updateJob{}
	activeUpdate = job
	activeUpdateMu.Unlock()

	go func() {
		defer job.finish()
		log.Printf("[deadband] Starting automatic advisory database update...")

		opts := updater.UpdateOpts{
			DBPath: s.dbPath,
			Progress: func(msg string) {
				log.Printf("[deadband] %s", msg)
				job.addProgress(msg)
			},
		}

		_, err := updater.Update(opts)
		if err != nil {
			log.Printf("[deadband] Auto-update error: %v", err)
			job.addProgress(fmt.Sprintf("Error: %v", err))
			return
		}

		// Fetch enrichment data
		fetchEnrichment(s.dbPath, opts.Progress)

		if err := s.reloadDB(); err != nil {
			log.Printf("[deadband] Reload error: %v", err)
			return
		}

		log.Printf("[deadband] Auto-update complete. %s", s.db.Stats())
		job.addProgress(fmt.Sprintf("Update complete. %s", s.db.Stats()))
	}()
}

// fetchEnrichment downloads KEV + EPSS and saves to the enrichment cache directory.
func fetchEnrichment(dbPath string, progress func(string)) {
	enrichDir := filepath.Dir(dbPath)
	edb, _ := enrichment.FetchAll(progress)
	if edb != nil && edb.Loaded() {
		if err := edb.SaveToDir(enrichDir); err != nil && progress != nil {
			progress(fmt.Sprintf("Warning: failed to save enrichment data: %v", err))
		}
	}
}

// --- Discovery handlers ---

type discoverRequest struct {
	CIDR        string `json:"cidr"`
	Mode        string `json:"mode"`
	TimeoutMS   int    `json:"timeout_ms"`
	Concurrency int    `json:"concurrency"`
	AutoCheck   bool   `json:"auto_check"`
	AutoImport  *bool  `json:"auto_import,omitempty"` // default true
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var req discoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cidr is required"})
		return
	}

	if !discoverMu.TryLock() {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "a discovery scan is already running"})
		return
	}

	jobID := newJobID()
	job := &discoverJob{ID: jobID, Status: jobRunning}
	discoverJobs.Store(jobID, job)

	timeout := 2 * time.Second
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	concurrency := 50
	if req.Concurrency > 0 {
		concurrency = req.Concurrency
	}
	mode := discover.ModeAuto
	switch req.Mode {
	case "cip":
		mode = discover.ModeCIP
	case "s7":
		mode = discover.ModeS7
	case "modbus":
		mode = discover.ModeModbusTCP
	case "melsec":
		mode = discover.ModeMELSEC
	case "bacnet":
		mode = discover.ModeBACnet
	case "fins":
		mode = discover.ModeFINS
	case "srtp":
		mode = discover.ModeSRTP
	case "http":
		mode = discover.ModeLegacyHTTP
	}

	autoImport := req.AutoImport == nil || *req.AutoImport // default true
	startedAt := time.Now().UTC()

	go func() {
		defer discoverMu.Unlock()

		opts := discover.Opts{
			CIDR:        req.CIDR,
			Timeout:     timeout,
			HTTPTimeout: 5 * time.Second,
			Concurrency: concurrency,
			Mode:        mode,
			Progress: func(msg string) {
				job.addProgress(msg)
			},
		}

		devices, err := discover.Run(opts)
		if err != nil {
			job.complete(nil, nil, err.Error())
			s.persistJobRecord(jobID, req.CIDR, string(mode), "error", err.Error(), startedAt, 0, 0, 0)
			return
		}

		job.addProgress(fmt.Sprintf("Discovered %d devices", len(devices)))

		// Auto-import into asset inventory
		var importNew, importUpdated int
		if autoImport && len(devices) > 0 {
			job.addProgress("Importing devices into asset inventory...")
			path := asset.DefaultPath()
			store := asset.LoadOrEmpty(path)
			result := store.Import(devices, "discovery")
			if s.siteStore != nil {
				s.siteStore.AssignAll(store.Assets)
			}
			if err := asset.Save(path, store); err != nil {
				job.addProgress(fmt.Sprintf("Warning: failed to save assets: %v", err))
			} else {
				importNew = result.Added
				importUpdated = result.Updated
				job.addProgress(fmt.Sprintf("Assets: %d added, %d updated (%d total)", result.Added, result.Updated, result.Total))
			}
		}

		// Auto-check vulnerabilities
		var results *checkResponse
		if req.AutoCheck && len(devices) > 0 {
			job.addProgress("Running vulnerability check on discovered devices...")
			resp := s.runCheck(devices, "low", 0, "")
			results = &resp
			job.addProgress(fmt.Sprintf("Check complete: %d vulnerable, %d potential, %d ok",
				resp.Summary.Vulnerable, resp.Summary.Potential, resp.Summary.OK))

			// Write vuln state back to assets
			if autoImport {
				s.writeVulnStateToAssets(devices, resp)
			}
		}

		// Posture analysis — scan for all hosts, classify, generate findings
		s.runPostureAnalysis(req.CIDR, func(msg string) {
			job.addProgress(msg)
		})

		job.complete(devices, results, "")
		s.persistJobRecord(jobID, req.CIDR, string(mode), "complete", "", startedAt, len(devices), importNew, importUpdated)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID, "status": "running"})
}

// persistJobRecord saves a completed discovery job to the persistent store.
func (s *Server) persistJobRecord(id, cidr, mode, status, errMsg string, startedAt time.Time, deviceCount, newCount, updatedCount int) {
	store := discover.LoadJobStore(discover.DefaultJobStorePath())
	now := time.Now().UTC()
	rec := discover.JobRecord{
		ID:           id,
		CIDR:         cidr,
		Mode:         mode,
		Status:       status,
		Error:        errMsg,
		StartedAt:    startedAt,
		CompletedAt:  &now,
		DeviceCount:  deviceCount,
		NewCount:     newCount,
		UpdatedCount: updatedCount,
		Duration:     now.Sub(startedAt).Round(time.Millisecond).String(),
	}
	store.Add(rec)
	store.Save()
}

// runPostureAnalysis performs host scanning, classification, subnet analysis,
// and finding generation as part of the discovery flow.
func (s *Server) runPostureAnalysis(cidr string, progress func(string)) {
	if s.postureStore == nil {
		return
	}

	scanStart := time.Now().UTC()
	progress("Posture: scanning subnet for all live hosts...")

	// Load assets first so the scanner can pre-tag known OT devices
	// and skip IT probes on them (sensitivity-ordered scanning).
	store := asset.LoadOrEmpty(asset.DefaultPath())

	hosts, err := posture.ScanSubnetWithAssets(cidr, 2*time.Second, 100, store.Assets, func(msg string) {
		progress("Posture: " + msg)
	})
	if err != nil {
		progress(fmt.Sprintf("Posture: scan error: %v", err))
		return
	}
	if len(hosts) == 0 {
		progress("Posture: no live hosts found, skipping analysis")
		return
	}

	progress("Posture: classifying hosts and probing service banners...")
	classified := posture.ClassifyHostsWithProgress(hosts, store.Assets, 2*time.Second, 32, func(msg string) {
		progress("Posture: " + msg)
	})

	otCount, itCount := 0, 0
	for _, h := range classified {
		switch h.DeviceClass {
		case posture.ClassOT:
			otCount++
		case posture.ClassIT:
			itCount++
		}
	}
	progress(fmt.Sprintf("Posture: classified %d hosts (%d OT, %d IT)", len(classified), otCount, itCount))

	var subnets []posture.SubnetAnalysis
	if _, cidrNet, err := net.ParseCIDR(cidr); err == nil && s.siteStore != nil {
		repIP := make(net.IP, len(cidrNet.IP))
		copy(repIP, cidrNet.IP)
		repIP[len(repIP)-1]++
		if matchedSite := s.siteStore.MatchIP(repIP.String()); matchedSite != nil && len(matchedSite.Zones) > 0 {
			progress(fmt.Sprintf("Posture: analyzing %d zones in site '%s'...", len(matchedSite.Zones), matchedSite.Name))
			subnets = posture.AnalyzeWithZones(classified, matchedSite.Zones)
		}
	}
	if subnets == nil {
		subnets = posture.AnalyzeSubnets(classified)
	}
	findings := posture.GenerateFindings(subnets)
	summary := posture.BuildSummary(subnets, findings)
	duration := time.Since(scanStart).Round(time.Millisecond).String()

	b := make([]byte, 8)
	rand.Read(b)
	report := posture.PostureReport{
		ID:        hex.EncodeToString(b),
		CIDR:      cidr,
		ScannedAt: scanStart,
		Duration:  duration,
		Subnets:   subnets,
		Findings:  findings,
		Summary:   summary,
	}

	s.postureStore.AddReport(report)
	if err := s.postureStore.Save(); err != nil {
		progress(fmt.Sprintf("Posture: failed to save report: %v", err))
		return
	}

	progress(fmt.Sprintf("Posture: complete — %d findings (%d critical), risk score %.1f",
		len(findings), summary.CriticalCount, summary.OverallScore))
}

// writeVulnStateToAssets writes check results back to the asset store.
func (s *Server) writeVulnStateToAssets(devices []inventory.Device, resp checkResponse) {
	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)
	if len(store.Assets) == 0 {
		return
	}

	// Index assets
	idx := make(map[string]*asset.Asset, len(store.Assets))
	for i := range store.Assets {
		a := &store.Assets[i]
		key := strings.ToLower(a.IP + "|" + a.Vendor + "|" + a.Model)
		idx[key] = a
	}

	now := time.Now().UTC()
	// Re-run matcher to get full Result objects (resp only has the HTTP-formatted output)
	filterOpts := matcher.FilterOpts{}
	results := matcher.MatchAll(devices, s.db, filterOpts)

	for _, r := range results {
		key := strings.ToLower(r.Device.IP + "|" + r.Device.Vendor + "|" + r.Device.Model)
		a, ok := idx[key]
		if !ok {
			continue
		}

		bestConf := "LOW"
		for _, m := range r.Matches {
			c := strings.ToUpper(string(m.Confidence))
			if c == "HIGH" || (c == "MEDIUM" && bestConf != "HIGH") {
				bestConf = c
			}
		}

		vs := &asset.VulnState{
			CheckedAt:  now,
			Status:     strings.ToUpper(r.Status),
			Confidence: bestConf,
		}
		for _, m := range r.Matches {
			va := asset.VulnAdvisory{
				ID:     m.Advisory.ID,
				Title:  m.Advisory.Title,
				CVEs:   m.Advisory.CVEs,
				CVSSv3: m.Advisory.CVSSv3Max,
				KEV:    m.KEV,
				RiskScore: m.RiskScore,
			}
			vs.CVECount += len(m.Advisory.CVEs)
			if m.KEV {
				vs.KEVCount++
			}
			if m.RiskScore > vs.RiskScore {
				vs.RiskScore = m.RiskScore
			}
			vs.Advisories = append(vs.Advisories, va)
		}
		a.VulnState = vs
	}

	asset.Save(path, store)
}

func (s *Server) handleDiscoverStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	val, ok := discoverJobs.Load(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, val.(*discoverJob))
}

func (s *Server) handleDiscoverEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	val, ok := discoverJobs.Load(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "job not found"})
		return
	}
	job := val.(*discoverJob)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "streaming not supported"})
		return
	}

	ch := job.subscribe()
	for msg := range ch {
		fmt.Fprintf(w, "data: %s\n\n", msg)
		flusher.Flush()
	}

	// Send final status
	data, _ := json.Marshal(map[string]any{
		"type":    "complete",
		"status":  job.Status,
		"devices": job.Devices,
		"results": job.Results,
		"error":   job.Error,
	})
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

// --- Update handlers ---

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	activeUpdateMu.Lock()
	if activeUpdate != nil && !activeUpdate.done {
		activeUpdateMu.Unlock()
		writeJSON(w, http.StatusConflict, errorResponse{Error: "an update is already running"})
		return
	}
	job := &updateJob{}
	activeUpdate = job
	activeUpdateMu.Unlock()

	go func() {
		defer job.finish()

		opts := updater.UpdateOpts{
			DBPath: s.dbPath,
			Since:  req.Since,
			Source: req.Source,
			Progress: func(msg string) {
				job.addProgress(msg)
			},
		}

		_, err := updater.Update(opts)
		if err != nil {
			job.addProgress(fmt.Sprintf("Error: %v", err))
			log.Printf("[deadband] Update error: %v", err)
			return
		}

		// Fetch enrichment data
		fetchEnrichment(s.dbPath, opts.Progress)

		if err := s.reloadDB(); err != nil {
			job.addProgress(fmt.Sprintf("Warning: failed to reload DB: %v", err))
			log.Printf("[deadband] Reload error: %v", err)
			return
		}

		job.addProgress(fmt.Sprintf("Update complete. %s", s.db.Stats()))
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "updating"})
}

func (s *Server) handleUpdateEvents(w http.ResponseWriter, r *http.Request) {
	activeUpdateMu.Lock()
	job := activeUpdate
	activeUpdateMu.Unlock()

	if job == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no update in progress"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "streaming not supported"})
		return
	}

	ch := job.subscribe()
	for msg := range ch {
		fmt.Fprintf(w, "data: %s\n\n", msg)
		flusher.Flush()
	}

	fmt.Fprintf(w, "data: {\"type\":\"complete\"}\n\n")
	flusher.Flush()
}

