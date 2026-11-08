package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/query"
)

func queryTestServer(t *testing.T) (*Server, *asset.Store) {
	t.Helper()
	s := &Server{db: &advisory.Database{Updated: time.Now(), Advisories: []advisory.Advisory{{ID: "unrelated", Vendor: "Other", Products: []string{"Other"}}}}, assetPath: filepath.Join(t.TempDir(), "assets.json"), mux: http.NewServeMux()}
	s.routes()
	store := &asset.Store{Version: 1, Assets: []asset.Asset{{ID: "sensor", IP: "192.0.2.10", Vendor: "SICK", Model: "CLV650", Firmware: "1.0", Serial: "ABC", Protocol: "cip", Port: 44818, Status: "active", VulnState: &asset.VulnState{Status: "VULNERABLE"}}}}
	if err := asset.Save(s.assetPath, store); err != nil {
		t.Fatal(err)
	}
	return s, store
}
func queryRequest(t *testing.T, s *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(b)))
	return w
}
func TestQueryPreviewAndExecutionPreserveAssetAndReassessment(t *testing.T) {
	s, _ := queryTestServer(t)
	w := queryRequest(t, s, "POST", "/api/queries/preview", map[string]any{"ids": []string{"sensor"}, "purpose": "verify"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rec queryRecord
	json.Unmarshal(w.Body.Bytes(), &rec)
	if len(rec.Plan.Targets) != 1 || rec.Plan.Targets[0].RequestedFields[0] != "firmware" {
		t.Fatal(rec)
	}
	s.queryExecutor = func(_ context.Context, p query.Plan) (query.Result, error) {
		return query.Result{PlanID: p.ID, PlanHash: p.PlanHash, Outcomes: []query.Outcome{{AssetID: "sensor", IP: "192.0.2.10", Status: "success", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Observations: []query.Observation{{Field: "firmware", Value: "2.0", Protocol: "enip", Operation: "ListIdentity", Component: "identity", VersionKind: "identity_revision"}}}}}, nil
	}
	w = queryRequest(t, s, "POST", "/api/queries/"+rec.Plan.ID+"/execute", map[string]string{"plan_hash": rec.Plan.PlanHash})
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		w = queryRequest(t, s, "GET", "/api/queries/"+rec.Plan.ID, nil)
		json.Unmarshal(w.Body.Bytes(), &rec)
		if rec.Status != "running" && rec.Status != "applying" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if rec.Status != "complete" || !rec.Applied {
		t.Fatalf("%+v", rec)
	}
	store, err := asset.Load(s.assetPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Assets) != 1 || store.Assets[0].ID != "sensor" || store.Assets[0].Firmware != "2.0" {
		t.Fatal(store)
	}
	a := store.Assets[0]
	if a.VulnState.Status != "NO_MATCH" || len(a.AssessmentHistory) != 1 || len(a.Observations) != 1 {
		t.Fatal(a)
	}
	w = queryRequest(t, s, "POST", "/api/queries/"+rec.Plan.ID+"/execute", map[string]string{"plan_hash": rec.Plan.PlanHash})
	if w.Code != 409 {
		t.Fatal("query may execute only once", w.Code)
	}
}
func TestQueryScopeAndIdentityChangesFailBeforeExecution(t *testing.T) {
	s, store := queryTestServer(t)
	w := queryRequest(t, s, "POST", "/api/queries/preview", map[string]any{"ids": []string{"sensor"}, "purpose": "verify"})
	var rec queryRecord
	json.Unmarshal(w.Body.Bytes(), &rec)
	store.Assets[0].IP = "192.0.2.11"
	asset.Save(s.assetPath, store)
	s.queryExecutor = func(context.Context, query.Plan) (query.Result, error) {
		t.Error("changed target executed")
		return query.Result{}, nil
	}
	w = queryRequest(t, s, "POST", "/api/queries/"+rec.Plan.ID+"/execute", map[string]string{"plan_hash": rec.Plan.PlanHash})
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	store.Assets[0].Slot = 0
	store.Assets[0].Extra = map[string]string{"slot": "0"}
	asset.Save(s.assetPath, store)
	w = queryRequest(t, s, "POST", "/api/queries/preview", map[string]any{"ids": []string{"sensor"}, "purpose": "verify"})
	if w.Code != 400 {
		t.Fatal("adapter query targeted slot0", w.Code)
	}
	w = queryRequest(t, s, "POST", "/api/discover", map[string]any{"cidr": "192.0.2.0/24", "mode": "enrich-typo"})
	if w.Code != 400 {
		t.Fatal("unknown mode accepted", w.Code)
	}
}
func TestQueryConflictsAndOverridesRetainEvidence(t *testing.T) {
	s, store := queryTestServer(t)
	store.Assets[0].Overrides = map[string]string{"firmware": "manual-2"}
	asset.Save(s.assetPath, store)
	p, _ := query.NewPlan([]query.Target{{AssetID: "sensor", IP: "192.0.2.10", Port: 44818, RequestedFields: []string{"firmware"}, Expected: query.ExpectedIdentity{Vendor: "SICK", Model: "CLV650", Serial: "ABC"}}}, "verify")
	rec := queryRecord{Plan: p, Result: &query.Result{Outcomes: []query.Outcome{{AssetID: "sensor", IP: "192.0.2.10", Status: "identity_conflict", ObservedAt: time.Now().Format(time.RFC3339), Observations: []query.Observation{{Field: "firmware", Value: "other"}}}}}}
	if err := s.applyQueryResult(&rec); err != nil {
		t.Fatal(err)
	}
	store, _ = asset.Load(s.assetPath)
	a := store.Assets[0]
	if a.Firmware != "1.0" || a.Overrides["firmware"] != "manual-2" || len(a.Observations) != 1 || !a.Observations[0].Conflict {
		t.Fatal(a)
	}
}
func TestReassessmentKeepsSameModelSlotsIndependent(t *testing.T) {
	s, store := queryTestServer(t)
	store.Assets[0].Slot = 1
	store.Assets[0].Extra = map[string]string{"slot": "1"}
	b := store.Assets[0]
	b.ID = "slot2"
	b.Slot = 2
	b.Extra = map[string]string{"slot": "2"}
	store.Assets = append(store.Assets, b)
	asset.Save(s.assetPath, store)
	s.writeVulnStateToAssets([]inventory.Device{{IP: b.IP, Vendor: b.Vendor, Model: b.Model, Slot: 2, Extra: b.Extra}}, checkResponse{})
	store, _ = asset.Load(s.assetPath)
	if store.Assets[0].VulnState.Status != "VULNERABLE" || store.Assets[1].VulnState.Status != "NO_MATCH" {
		t.Fatal(store)
	}
}

func TestNewerFirmwareAndComponentChangesDoNotGetOverwritten(t *testing.T) {
	s, store := queryTestServer(t)
	p, _ := query.NewPlan([]query.Target{{AssetID: "sensor", IP: "192.0.2.10", Port: 44818, RequestedFields: []string{"firmware"}, Expected: query.ExpectedIdentity{Vendor: "SICK", Model: "CLV650", Serial: "ABC"}}}, "verify")
	rec := queryRecord{Plan: p, Snapshots: map[string]queryAssetSnapshot{"sensor": assetQuerySnapshot(&store.Assets[0])}, Result: &query.Result{Outcomes: []query.Outcome{{AssetID: "sensor", IP: "192.0.2.10", Status: "success", Observations: []query.Observation{{Field: "firmware", Value: "2.0"}}}}}}
	store.Assets[0].Firmware = "3.0"
	if err := asset.Save(s.assetPath, store); err != nil {
		t.Fatal(err)
	}
	if err := s.applyQueryResult(&rec); err != nil {
		t.Fatal(err)
	}
	store, _ = asset.Load(s.assetPath)
	if store.Assets[0].Firmware != "3.0" || rec.Result.Outcomes[0].Status != "identity_conflict" || len(rec.Assessments) != 0 {
		t.Fatal(rec, store)
	}
	for _, mutate := range []func(*asset.Asset){func(a *asset.Asset) { a.Port = 102 }, func(a *asset.Asset) { a.Protocol = "s7" }, func(a *asset.Asset) { a.Extra = map[string]string{"slot": "0"} }} {
		a := store.Assets[0]
		mutate(&a)
		if unchangedQueryTarget(&a, p.Targets[0]) {
			t.Fatal("changed component accepted", a)
		}
	}
}

func TestInterruptedApplyingIsTerminalForViewer(t *testing.T) {
	s, _ := queryTestServer(t)
	p, _ := query.NewPlan([]query.Target{{AssetID: "sensor", IP: "192.0.2.10", Port: 44818, RequestedFields: []string{"firmware"}}}, "verify")
	if err := s.saveQueryRecord(queryRecord{Plan: p, Status: "applying", Excluded: []queryExclusion{}}); err != nil {
		t.Fatal(err)
	}
	w := queryRequest(t, s, "GET", "/api/queries/"+p.ID, nil)
	var rec queryRecord
	json.Unmarshal(w.Body.Bytes(), &rec)
	if rec.Status != "interrupted" {
		t.Fatal(w.Body.String())
	}
}

func TestDeletedTargetRetainsOutcomeAndOtherTargetsApply(t *testing.T) {
	s, store := queryTestServer(t)
	b := store.Assets[0]
	b.ID = "remaining"
	b.IP = "192.0.2.11"
	store.Assets = []asset.Asset{b}
	if err := asset.Save(s.assetPath, store); err != nil {
		t.Fatal(err)
	}
	target := func(id, ip string) query.Target {
		return query.Target{AssetID: id, IP: ip, Port: 44818, RequestedFields: []string{"firmware"}, Expected: query.ExpectedIdentity{Vendor: "SICK", Model: "CLV650", Serial: "ABC"}}
	}
	p, _ := query.NewPlan([]query.Target{target("sensor", "192.0.2.10"), target("remaining", b.IP)}, "verify")
	outcome := func(id, ip string) query.Outcome {
		return query.Outcome{AssetID: id, IP: ip, Status: "success", Observations: []query.Observation{{Field: "firmware", Value: "2.0"}}}
	}
	rec := queryRecord{Plan: p, Result: &query.Result{Outcomes: []query.Outcome{outcome("sensor", "192.0.2.10"), outcome("remaining", b.IP)}}}
	if err := s.applyQueryResult(&rec); err != nil {
		t.Fatal(err)
	}
	store, _ = asset.Load(s.assetPath)
	if len(rec.Result.Outcomes) != 2 || rec.Result.Outcomes[0].Status != "identity_conflict" || len(store.Assets) != 1 || store.Assets[0].Firmware != "2.0" {
		t.Fatal(rec, store)
	}
}
