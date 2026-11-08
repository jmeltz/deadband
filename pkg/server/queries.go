package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/query"
)

type queryExclusion struct {
	AssetID string `json:"asset_id"`
	Reason  string `json:"reason"`
}
type queryRecord struct {
	Plan        query.Plan                    `json:"plan"`
	Status      string                        `json:"status"`
	Excluded    []queryExclusion              `json:"excluded"`
	Result      *query.Result                 `json:"result,omitempty"`
	Error       string                        `json:"error,omitempty"`
	Applied     bool                          `json:"applied"`
	Snapshots   map[string]queryAssetSnapshot `json:"asset_snapshots,omitempty"`
	Assessments []queryAssessment             `json:"assessments,omitempty"`
}

type queryAssessment struct {
	AssetID        string           `json:"asset_id"`
	FirmwareBefore string           `json:"firmware_before"`
	FirmwareAfter  string           `json:"firmware_after"`
	Previous       *asset.VulnState `json:"previous,omitempty"`
	Current        *asset.VulnState `json:"current"`
}

type queryAssetSnapshot struct {
	Firmware  string            `json:"firmware"`
	Site      string            `json:"site"`
	Zone      string            `json:"zone"`
	Protocol  string            `json:"protocol"`
	Port      int               `json:"port"`
	Overrides map[string]string `json:"overrides,omitempty"`
}

func assetQuerySnapshot(a *asset.Asset) queryAssetSnapshot {
	return queryAssetSnapshot{Firmware: a.Firmware, Site: a.Site, Zone: a.Zone, Protocol: a.Protocol, Port: a.Port, Overrides: a.Overrides}
}

var queryJobsMu sync.Mutex
var queryCancels = map[string]context.CancelFunc{}
var queryIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type queryExecution func(context.Context, query.Plan) (query.Result, error)

func (s *Server) queryRecordPath(id string) (string, error) {
	if !queryIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid query ID")
	}
	return filepath.Join(filepath.Dir(s.assetStorePath()), "query-jobs", id+".json"), nil
}
func (s *Server) saveQueryRecord(rec queryRecord) error {
	path, err := s.queryRecordPath(rec.Plan.ID)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".query-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (s *Server) loadQueryRecord(id string) (queryRecord, error) {
	var rec queryRecord
	path, err := s.queryRecordPath(id)
	if err != nil {
		return rec, err
	}
	f, err := os.Open(path)
	if err != nil {
		return rec, err
	}
	defer f.Close()
	err = json.NewDecoder(io.LimitReader(f, 4<<20)).Decode(&rec)
	return rec, err
}
func decodeQueryBody(w http.ResponseWriter, r *http.Request, out any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON value")
	}
	return nil
}

func queryFields(a asset.Asset, purpose string) ([]string, string) {
	if a.Status != "" && a.Status != "active" {
		return nil, "Asset is not active"
	}
	if a.Protocol != "cip" && a.Protocol != "enip" {
		return nil, "No known EtherNet/IP endpoint"
	}
	if a.Port != 0 && a.Port != 44818 {
		return nil, "Endpoint does not match TCP/44818"
	}
	if a.Slot != 0 || a.Extra["slot"] != "" || a.Extra["device_instance"] != "" {
		return nil, "Component needs a routed or chassis profile"
	}
	if purpose == "verify" {
		return []string{"firmware"}, ""
	}
	fields := []string{}
	for _, f := range []struct{ name, value string }{{"vendor", a.Vendor}, {"model", a.Model}, {"firmware", a.Firmware}, {"serial", a.Serial}} {
		if strings.TrimSpace(f.value) == "" {
			fields = append(fields, f.name)
		}
	}
	if len(fields) == 0 {
		return nil, "Requested asset details are already populated"
	}
	return fields, ""
}

func (s *Server) handlePreviewQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs     []string `json:"ids"`
		Purpose string   `json:"purpose"`
	}
	if err := decodeQueryBody(w, r, &req); err != nil {
		writeJSON(w, 400, errorResponse{Error: "invalid preview request"})
		return
	}
	if req.Purpose != "enrich" && req.Purpose != "verify" {
		writeJSON(w, 400, errorResponse{Error: "purpose must be enrich or verify"})
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > query.MaxTargets {
		writeJSON(w, 400, errorResponse{Error: "select between 1 and 256 assets"})
		return
	}
	assetStoreMu.Lock()
	store, loadErr := asset.Load(s.assetStorePath())
	assetStoreMu.Unlock()
	if loadErr != nil {
		writeJSON(w, 500, errorResponse{Error: "could not load asset inventory"})
		return
	}
	targets := []query.Target{}
	excluded := []queryExclusion{}
	seen := map[string]bool{}
	snapshots := map[string]queryAssetSnapshot{}
	for _, id := range req.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		a := store.Get(id)
		if a == nil {
			excluded = append(excluded, queryExclusion{id, "Asset no longer exists"})
			continue
		}
		fields, reason := queryFields(*a, req.Purpose)
		if reason != "" {
			excluded = append(excluded, queryExclusion{id, reason})
			continue
		}
		d := deviceForAsset(*a)
		targets = append(targets, query.Target{AssetID: id, IP: a.IP, Port: 44818, RequestedFields: fields, Expected: query.ExpectedIdentity{Vendor: d.Vendor, Model: d.Model, Serial: d.Serial}})
		snapshots[id] = assetQuerySnapshot(a)
	}
	if len(targets) == 0 {
		writeJSON(w, 400, map[string]any{"error": "No eligible assets for this query profile", "excluded": excluded})
		return
	}
	plan, err := query.NewPlan(targets, req.Purpose)
	if err != nil {
		writeJSON(w, 400, errorResponse{Error: err.Error()})
		return
	}
	rec := queryRecord{Plan: plan, Status: "preview", Excluded: excluded, Snapshots: snapshots}
	queryJobsMu.Lock()
	err = s.saveQueryRecord(rec)
	queryJobsMu.Unlock()
	if err != nil {
		writeJSON(w, 500, errorResponse{Error: "could not save query preview"})
		return
	}
	writeJSON(w, 200, rec)
}

func unchangedQueryTarget(a *asset.Asset, t query.Target) bool {
	if a == nil || a.IP != t.IP || (a.Status != "" && a.Status != "active") {
		return false
	}
	if _, reason := queryFields(*a, "verify"); reason != "" {
		return false
	}
	d := deviceForAsset(*a)
	return d.Vendor == t.Expected.Vendor && d.Model == t.Expected.Model && d.Serial == t.Expected.Serial
}

func (s *Server) handleExecuteQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanHash string `json:"plan_hash"`
	}
	if err := decodeQueryBody(w, r, &req); err != nil {
		writeJSON(w, 400, errorResponse{Error: "invalid execution request"})
		return
	}
	queryJobsMu.Lock()
	defer queryJobsMu.Unlock()
	rec, err := s.loadQueryRecord(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, errorResponse{Error: "query preview not found"})
		return
	}
	if rec.Status != "preview" {
		writeJSON(w, 409, errorResponse{Error: "query has already been started"})
		return
	}
	if req.PlanHash != rec.Plan.PlanHash {
		writeJSON(w, 409, errorResponse{Error: "preview has changed; create a new preview"})
		return
	}
	if err = query.Validate(rec.Plan); err != nil {
		writeJSON(w, 400, errorResponse{Error: err.Error()})
		return
	}
	assetStoreMu.Lock()
	store := asset.LoadOrEmpty(s.assetStorePath())
	valid := true
	for _, t := range rec.Plan.Targets {
		if !unchangedQueryTarget(store.Get(t.AssetID), t) || !reflect.DeepEqual(assetQuerySnapshot(store.Get(t.AssetID)), rec.Snapshots[t.AssetID]) {
			valid = false
			break
		}
	}
	assetStoreMu.Unlock()
	if !valid {
		writeJSON(w, 409, errorResponse{Error: "asset identity or scope changed; create a new preview"})
		return
	}
	if !discoverMu.TryLock() {
		writeJSON(w, 409, errorResponse{Error: "another discovery or enrichment job is running"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rec.Status = "running"
	if err = s.saveQueryRecord(rec); err != nil {
		cancel()
		discoverMu.Unlock()
		writeJSON(w, 500, errorResponse{Error: "could not save query job"})
		return
	}
	queryCancels[rec.Plan.ID] = cancel
	go s.executeQuery(ctx, rec)
	writeJSON(w, 202, rec)
}

func (s *Server) executeQuery(ctx context.Context, rec queryRecord) {
	defer discoverMu.Unlock()
	executor := s.queryExecutor
	if executor == nil {
		executor = query.Execute
	}
	result, err := executor(ctx, rec.Plan)
	rec.Result = &result
	if err != nil {
		rec.Error = err.Error()
		rec.Status = "error"
	} else {
		rec.Status = "complete"
	}
	for _, o := range result.Outcomes {
		if o.Status == "canceled" {
			rec.Status = "canceled"
		}
	}
	// Persist the result before updating the projection; failed writes cannot
	// silently discard the response or make a second device query necessary.
	finalStatus := rec.Status
	rec.Status = "applying"
	queryJobsMu.Lock()
	saveErr := s.saveQueryRecord(rec)
	queryJobsMu.Unlock()
	if saveErr == nil && err == nil {
		saveErr = s.applyQueryResult(&rec)
	}
	queryJobsMu.Lock()
	defer queryJobsMu.Unlock()
	rec.Status = finalStatus
	if saveErr != nil {
		rec.Status = "error"
		rec.Error = "Evidence or asset persistence failed: " + saveErr.Error()
	}
	if cancel := queryCancels[rec.Plan.ID]; cancel != nil {
		cancel()
	}
	delete(queryCancels, rec.Plan.ID)
	if err := s.saveQueryRecord(rec); err != nil {
		fmt.Printf("[deadband] persist query %s: %v\n", rec.Plan.ID, err)
	}
}

func (s *Server) applyQueryResult(rec *queryRecord) error {
	assetStoreMu.Lock()
	defer assetStoreMu.Unlock()
	store, loadErr := asset.Load(s.assetStorePath())
	if loadErr != nil {
		return loadErr
	}
	targets := map[string]query.Target{}
	for _, t := range rec.Plan.Targets {
		targets[t.AssetID] = t
	}
	for i := range rec.Result.Outcomes {
		o := &rec.Result.Outcomes[i]
		t, ok := targets[o.AssetID]
		if !ok {
			return fmt.Errorf("result target outside plan")
		}
		a := store.Get(o.AssetID)
		if a == nil {
			o.Status = "identity_conflict"
			o.Error = "Selected asset was removed during execution; response retained in query evidence"
			continue
		}
		firmwareBefore := deviceForAsset(*a).Firmware
		previous := a.VulnState
		conflict := o.Status == "identity_conflict" || !unchangedQueryTarget(a, t)
		if snapshot, exists := rec.Snapshots[o.AssetID]; exists && !reflect.DeepEqual(assetQuerySnapshot(a), snapshot) {
			conflict = true
		}
		if conflict {
			o.Status = "identity_conflict"
			o.Error = "Identity changed or conflicts with the selected asset"
		}
		requested := map[string]bool{}
		for _, f := range t.RequestedFields {
			requested[f] = true
		}
		observed := false
		for _, v := range o.Observations {
			a.Observations = append(a.Observations, asset.FieldObservation{PlanID: rec.Plan.ID, PlanHash: rec.Plan.PlanHash, Field: v.Field, Value: v.Value, RawValue: v.RawValue, Protocol: v.Protocol, Operation: v.Operation, Component: v.Component, VersionKind: v.VersionKind, ObservedAt: o.ObservedAt, Conflict: conflict})
			if conflict || (o.Status != "success" && o.Status != "partial") || v.Value == "" {
				continue
			}
			observed = true
			if _, override := a.Overrides[v.Field]; override {
				continue
			}
			// Identity is checked against the selected component; only requested
			// fields and missing vendor information update the projection.
			if !requested[v.Field] && !(v.Field == "vendor" && a.Vendor == "") {
				continue
			}
			switch v.Field {
			case "vendor":
				a.Vendor = v.Value
			case "model":
				a.Model = v.Value
			case "firmware":
				a.Firmware = v.Value
			case "serial":
				a.Serial = v.Value
			}
		}
		if len(a.Observations) > 1000 {
			a.Observations = a.Observations[len(a.Observations)-1000:]
		}
		if observed {
			if when, err := time.Parse(time.RFC3339Nano, o.ObservedAt); err == nil {
				a.LastSeen = when
			}
			store.UpdateVulnState(a.ID, s.assessDevice(deviceForAsset(*a)))
			rec.Assessments = append(rec.Assessments, queryAssessment{AssetID: a.ID, FirmwareBefore: firmwareBefore, FirmwareAfter: deviceForAsset(*a).Firmware, Previous: previous, Current: a.VulnState})
		}
	}
	if err := asset.Save(s.assetStorePath(), store); err != nil {
		return err
	}
	rec.Applied = true
	return nil
}

func (s *Server) handleGetQuery(w http.ResponseWriter, r *http.Request) {
	queryJobsMu.Lock()
	defer queryJobsMu.Unlock()
	rec, err := s.loadQueryRecord(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, errorResponse{Error: "query not found"})
		return
	}
	if (rec.Status == "running" || rec.Status == "applying") && queryCancels[rec.Plan.ID] == nil {
		rec.Status = "interrupted"
		rec.Error = "Scanner restarted before completion; review retained evidence and inventory before creating another query"
	}
	writeJSON(w, 200, rec)
}
func (s *Server) handleCancelQuery(w http.ResponseWriter, r *http.Request) {
	queryJobsMu.Lock()
	defer queryJobsMu.Unlock()
	if cancel := queryCancels[r.PathValue("id")]; cancel != nil {
		cancel()
		writeJSON(w, 202, map[string]string{"status": "canceling"})
		return
	}
	writeJSON(w, 409, errorResponse{Error: "query is not running"})
}
func (s *Server) handleQueryHistory(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Join(filepath.Dir(s.assetStorePath()), "query-jobs")
	entries, _ := os.ReadDir(dir)
	records := []queryRecord{}
	queryJobsMu.Lock()
	defer queryJobsMu.Unlock()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rec, err := s.loadQueryRecord(strings.TrimSuffix(e.Name(), ".json"))
		if err == nil {
			if (rec.Status == "running" || rec.Status == "applying") && queryCancels[rec.Plan.ID] == nil {
				rec.Status = "interrupted"
			}
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Plan.CreatedAt > records[j].Plan.CreatedAt })
	if len(records) > 50 {
		records = records[:50]
	}
	writeJSON(w, 200, records)
}
func (s *Server) handleQueryAccess(w http.ResponseWriter, r *http.Request) {
	queryJobsMu.Lock()
	rec, err := s.loadQueryRecord(r.PathValue("id"))
	queryJobsMu.Unlock()
	if err != nil {
		writeJSON(w, 404, errorResponse{Error: "query not found"})
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="deadband-query-access.csv"`)
	c := csv.NewWriter(w)
	defer c.Flush()
	c.Write([]string{"Source", "Destination", "Transport", "Port", "Operation", "Asset ID"})
	for _, t := range rec.Plan.Targets {
		c.Write([]string{"Scanner host", t.IP, "TCP", "44818", "ENIP ListIdentity", t.AssetID})
	}
}
