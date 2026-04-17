package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/asa"
	"github.com/jmeltz/deadband/pkg/integration"
	"github.com/jmeltz/deadband/pkg/sentinel"
)

func sentinelClientFromConfig(cfg integration.SentinelConfig) *sentinel.Client {
	return sentinel.NewClient(cfg)
}

func asaClientFromConfig(cfg integration.ASAConfig) *asa.Client {
	return asa.NewClient(cfg)
}

// Default KQL query for Sentinel flow collection.
const defaultFlowQuery = `CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Cisco" and DeviceProduct == "ASA"
| where Activity has "connection" or Activity has "Built" or Activity has "Teardown"
| summarize ConnectionCount=count() by
    DeviceHostname=DeviceCustomString1,
    SourceZone=DeviceCustomString2,
    SourceAddr=SourceIP,
    DestZone=DeviceCustomString3,
    DestAddr=DestinationIP,
    DestPort=DestinationPort
| extend DestNATAddr="", DestNATPort=0
| join kind=leftouter (
    IntuneDevices
    | summarize arg_max(TimeGenerated, *) by DeviceName
    | project ComputerName=DeviceName, UserName=UserEmail, FullName=UserName,
              JobTitle="", Department="", MailAddress=UserEmail,
              CompanyName=CompanyName, OsName=OS
) on $left.SourceAddr == $right.ComputerName
| project DeviceHostname, SourceZone, SourceAddr, DestZone, DestAddr, DestPort,
          DestNATAddr, DestNATPort, ConnectionCount,
          ComputerName, UserName, FullName, JobTitle, Department, MailAddress,
          CompanyName, OsName`

// --- Sentinel query job ---

type sentinelQueryJob struct {
	mu       sync.Mutex
	subs     []chan string
	done     bool
	snapshot *sentinel.SentinelSnapshot
	errMsg   string
}

func (j *sentinelQueryJob) addProgress(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, ch := range j.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (j *sentinelQueryJob) finish(snap *sentinel.SentinelSnapshot, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	j.snapshot = snap
	j.errMsg = errMsg
	for _, ch := range j.subs {
		close(ch)
	}
	j.subs = nil
}

func (j *sentinelQueryJob) subscribe() chan string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch := make(chan string, 64)
	j.subs = append(j.subs, ch)
	return ch
}

var (
	sentinelJobs   sync.Map
	sentinelJobsMu sync.Mutex
)

func (s *Server) handleQuerySentinel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cfg := s.integrationStore.GetSentinel(id)
	if cfg == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "sentinel config not found"})
		return
	}

	if !sentinelJobsMu.TryLock() {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "a sentinel query is already running"})
		return
	}

	jobID := newJobID()
	job := &sentinelQueryJob{}
	sentinelJobs.Store(id, job)

	go func() {
		defer sentinelJobsMu.Unlock()

		job.addProgress("Connecting to Azure Log Analytics...")
		client := sentinelClientFromConfig(*cfg)

		query := cfg.DefaultQuery
		if query == "" {
			query = defaultFlowQuery
		}

		job.addProgress("Executing KQL query...")
		flows, err := client.QueryFlows(r.Context(), query)
		if err != nil {
			job.addProgress(fmt.Sprintf("Error: %v", err))
			job.finish(nil, err.Error())
			return
		}

		job.addProgress(fmt.Sprintf("Received %d flows", len(flows)))

		b := make([]byte, 8)
		rand.Read(b)
		now := time.Now().UTC()
		snap := &sentinel.SentinelSnapshot{
			ID:        hex.EncodeToString(b),
			SiteID:    cfg.SiteID,
			ConfigID:  cfg.ID,
			QueriedAt: now,
			FlowCount: len(flows),
			Flows:     flows,
		}

		s.sentinelStore.AddSnapshot(*snap)
		if err := s.sentinelStore.Save(); err != nil {
			job.addProgress(fmt.Sprintf("Warning: failed to save snapshot: %v", err))
		}

		// Update last query time on the config
		cfg.LastQueryAt = &now
		s.integrationStore.UpsertSentinel(*cfg)
		s.integrationStore.Save()

		job.addProgress(fmt.Sprintf("Complete: %d flows stored in snapshot %s", len(flows), snap.ID[:8]))
		job.finish(snap, "")
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID, "status": "running"})
}

func (s *Server) handleQuerySentinelEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	val, ok := sentinelJobs.Load(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no query in progress for this config"})
		return
	}
	job := val.(*sentinelQueryJob)

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

	data, _ := json.Marshal(map[string]any{
		"type":     "complete",
		"snapshot": job.snapshot,
		"error":    job.errMsg,
	})
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

func (s *Server) handleGetSentinelSnapshots(w http.ResponseWriter, r *http.Request) {
	siteID := r.URL.Query().Get("site_id")
	var snaps []sentinel.SentinelSnapshot
	if siteID != "" {
		snaps = s.sentinelStore.ListBySite(siteID)
	} else {
		snaps = s.sentinelStore.List()
	}

	// Return without full flow data for list view
	type snapSummary struct {
		ID        string    `json:"id"`
		SiteID    string    `json:"site_id"`
		ConfigID  string    `json:"config_id"`
		QueriedAt time.Time `json:"queried_at"`
		FlowCount int       `json:"flow_count"`
	}
	summaries := make([]snapSummary, len(snaps))
	for i, sn := range snaps {
		summaries[i] = snapSummary{
			ID:        sn.ID,
			SiteID:    sn.SiteID,
			ConfigID:  sn.ConfigID,
			QueriedAt: sn.QueriedAt,
			FlowCount: sn.FlowCount,
		}
	}
	writeJSON(w, http.StatusOK, summaries)
}

func (s *Server) handleGetSentinelSnapshot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap := s.sentinelStore.GetSnapshot(id)
	if snap == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "snapshot not found"})
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleGetTrafficSummary(w http.ResponseWriter, r *http.Request) {
	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "site_id is required"})
		return
	}

	snap := s.sentinelStore.GetLatest(siteID)
	if snap == nil {
		writeJSON(w, http.StatusOK, []sentinel.ZoneTrafficSummary{})
		return
	}

	st := s.siteStore.Get(siteID)
	if st == nil || len(st.Zones) == 0 {
		writeJSON(w, http.StatusOK, []sentinel.ZoneTrafficSummary{})
		return
	}

	summaries := sentinel.ComputeTrafficSummary(snap.Flows, st.Zones)
	if summaries == nil {
		summaries = []sentinel.ZoneTrafficSummary{}
	}
	writeJSON(w, http.StatusOK, summaries)
}

func (s *Server) handleScopingRecommendations(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	policy := s.aclStore.Get(req.PolicyID)
	if policy == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "policy not found"})
		return
	}

	st := s.siteStore.Get(policy.SiteID)
	if st == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}

	snap := s.sentinelStore.GetLatest(st.ID)
	if snap == nil {
		writeJSON(w, http.StatusOK, []sentinel.ScopingRecommendation{})
		return
	}

	recs := sentinel.BuildScopingRecommendations(*policy, snap.Flows, st.Zones)
	if recs == nil {
		recs = []sentinel.ScopingRecommendation{}
	}
	writeJSON(w, http.StatusOK, recs)
}

// --- ASA collection job ---

type asaCollectJob struct {
	mu       sync.Mutex
	subs     []chan string
	done     bool
	errMsg   string
}

func (j *asaCollectJob) addProgress(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, ch := range j.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (j *asaCollectJob) finish(errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	j.errMsg = errMsg
	for _, ch := range j.subs {
		close(ch)
	}
	j.subs = nil
}

func (j *asaCollectJob) subscribe() chan string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch := make(chan string, 64)
	j.subs = append(j.subs, ch)
	return ch
}

var (
	asaJobs   sync.Map
	asaJobsMu sync.Mutex
)

func (s *Server) handleCollectASA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cfg := s.integrationStore.GetASA(id)
	if cfg == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "asa config not found"})
		return
	}

	if !asaJobsMu.TryLock() {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "an ASA collection is already running"})
		return
	}

	job := &asaCollectJob{}
	asaJobs.Store(id, job)

	go func() {
		defer asaJobsMu.Unlock()

		job.addProgress(fmt.Sprintf("Connecting to %s:%d...", cfg.Host, cfg.Port))
		client := asaClientFromConfig(*cfg)

		if err := client.Connect(r.Context()); err != nil {
			job.addProgress(fmt.Sprintf("Error: %v", err))
			job.finish(err.Error())
			return
		}
		defer client.Close()

		job.addProgress("Running show commands...")
		result, err := asa.Collect(client, func(msg string) {
			job.addProgress(msg)
		})
		if err != nil {
			job.addProgress(fmt.Sprintf("Collection error: %v", err))
			job.finish(err.Error())
			return
		}

		now := time.Now().UTC()

		// Update last collect time
		cfg.LastCollectAt = &now
		s.integrationStore.UpsertASA(*cfg)
		s.integrationStore.Save()

		// Store snapshot
		if s.asaSnapshotStore != nil {
			b := make([]byte, 8)
			rand.Read(b)
			snap := asa.ASASnapshot{
				ID:          hex.EncodeToString(b),
				SiteID:      cfg.SiteID,
				ConfigID:    cfg.ID,
				CollectedAt: now,
				Result:      *result,
			}
			s.asaSnapshotStore.AddSnapshot(snap)
			s.asaSnapshotStore.Save()
			job.addProgress(fmt.Sprintf("Complete: %d ACL rules, %d connections, %d interfaces",
				len(result.ACLRules), len(result.Connections), len(result.Interfaces)))
		}

		job.finish("")
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "running"})
}

func (s *Server) handleCollectASAEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	val, ok := asaJobs.Load(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no collection in progress for this config"})
		return
	}
	job := val.(*asaCollectJob)

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

	data, _ := json.Marshal(map[string]any{
		"type":  "complete",
		"error": job.errMsg,
	})
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

func (s *Server) handleGetASASnapshots(w http.ResponseWriter, r *http.Request) {
	if s.asaSnapshotStore == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	siteID := r.URL.Query().Get("site_id")
	var snaps []asa.ASASnapshot
	if siteID != "" {
		snaps = s.asaSnapshotStore.ListBySite(siteID)
	} else {
		snaps = s.asaSnapshotStore.List()
	}

	// Return summaries without full result data
	type snapSummary struct {
		ID          string    `json:"id"`
		SiteID      string    `json:"site_id"`
		ConfigID    string    `json:"config_id"`
		CollectedAt time.Time `json:"collected_at"`
		Duration    string    `json:"duration"`
		ACLRules    int       `json:"acl_rules"`
		Connections int       `json:"connections"`
		Interfaces  int       `json:"interfaces"`
	}
	summaries := make([]snapSummary, len(snaps))
	for i, sn := range snaps {
		summaries[i] = snapSummary{
			ID:          sn.ID,
			SiteID:      sn.SiteID,
			ConfigID:    sn.ConfigID,
			CollectedAt: sn.CollectedAt,
			Duration:    sn.Duration,
			ACLRules:    len(sn.Result.ACLRules),
			Connections: len(sn.Result.Connections),
			Interfaces:  len(sn.Result.Interfaces),
		}
	}
	writeJSON(w, http.StatusOK, summaries)
}

func (s *Server) handleGetASASnapshot(w http.ResponseWriter, r *http.Request) {
	if s.asaSnapshotStore == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "snapshot not found"})
		return
	}
	id := r.PathValue("id")
	snap := s.asaSnapshotStore.GetSnapshot(id)
	if snap == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "snapshot not found"})
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleAnalyzeDrift(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PolicyID   string `json:"policy_id"`
		SnapshotID string `json:"snapshot_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON"})
		return
	}
	if body.PolicyID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "policy_id required"})
		return
	}

	policy := s.aclStore.Get(body.PolicyID)
	if policy == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "policy not found"})
		return
	}

	// Get ASA snapshot
	var snap *asa.ASASnapshot
	if body.SnapshotID != "" {
		snap = s.asaSnapshotStore.GetSnapshot(body.SnapshotID)
	} else {
		// Find latest snapshot for this policy's site
		snapshots := s.asaSnapshotStore.ListBySite(policy.SiteID)
		if len(snapshots) > 0 {
			snap = &snapshots[0]
		}
	}
	if snap == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no ASA snapshot found for this site"})
		return
	}

	site := s.siteStore.Get(policy.SiteID)
	if site == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}

	drifts := asa.ComparePolicyToASA(*policy, snap.Result, site.Zones)
	writeJSON(w, http.StatusOK, drifts)
}
