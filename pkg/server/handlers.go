package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/baseline"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/compliance"
	"github.com/jmeltz/deadband/pkg/diff"
	"github.com/jmeltz/deadband/pkg/enrichment"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

// --- JSON response types ---

type healthResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	DBLoaded bool   `json:"db_loaded"`
}

type statsResponse struct {
	AdvisoryCount   int               `json:"advisory_count"`
	Updated         string            `json:"updated"`
	Source          string            `json:"source"`
	PreviousUpdated *string           `json:"previous_updated"`
	AddedSinceLast  int               `json:"added_since_last"`
	ChronicCount    int               `json:"chronic_count"`
	Vendors         map[string]int    `json:"vendors"`
}

type advisoryListResponse struct {
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PerPage    int                  `json:"per_page"`
	Advisories []advisory.Advisory  `json:"advisories"`
}

type checkRequest struct {
	Devices       []inventory.Device `json:"devices"`
	MinConfidence string             `json:"min_confidence"`
	MinCVSS       float64            `json:"min_cvss"`
	Vendor        string             `json:"vendor"`
}

type checkResponse struct {
	CheckedAt      string               `json:"checked_at"`
	DBUpdated      string               `json:"db_updated"`
	DevicesChecked int                  `json:"devices_checked"`
	Results        []checkDeviceResult  `json:"results"`
	Summary        checkSummary         `json:"summary"`
}

type checkDeviceResult struct {
	IP         string           `json:"ip"`
	Vendor     string           `json:"vendor"`
	Model      string           `json:"model"`
	Firmware   string           `json:"firmware"`
	Status     string           `json:"status"`
	Confidence string           `json:"confidence"`
	Advisories []checkAdvisory  `json:"advisories,omitempty"`
}

type checkAdvisory struct {
	ID             string   `json:"id"`
	CVEs           []string `json:"cves"`
	CVSSv3         float64  `json:"cvss_v3"`
	Title          string   `json:"title"`
	URL            string   `json:"url"`
	KEV            bool     `json:"kev"`
	KEVRansomware  bool     `json:"kev_ransomware,omitempty"`
	EPSSScore      float64  `json:"epss_score,omitempty"`
	EPSSPercentile float64  `json:"epss_percentile,omitempty"`
	RiskScore      float64  `json:"risk_score"`
}

type checkSummary struct {
	Vulnerable int `json:"vulnerable"`
	Potential  int `json:"potential"`
	OK         int `json:"ok"`
	NoMatch    int `json:"no_match"`
}

type diffRequest struct {
	BaseDevices    []inventory.Device `json:"base_devices"`
	CompareDevices []inventory.Device `json:"compare_devices"`
	MinConfidence  string             `json:"min_confidence"`
	MinCVSS        float64            `json:"min_cvss"`
	Vendor         string             `json:"vendor"`
}

type diffResponse struct {
	ComparedAt         string              `json:"compared_at"`
	Summary            diffSummary         `json:"summary"`
	NewDevices         []diffDevice        `json:"new_devices"`
	RemovedDevices     []diffDevice        `json:"removed_devices"`
	FirmwareChanges    []diffFWChange      `json:"firmware_changes"`
	NewVulnerabilities []diffNewVuln       `json:"new_vulnerabilities"`
}

type diffSummary struct {
	NewDevices         int `json:"new_devices"`
	RemovedDevices     int `json:"removed_devices"`
	FirmwareChanges    int `json:"firmware_changes"`
	NewVulnerabilities int `json:"new_vulnerabilities"`
}

type diffDevice struct {
	IP       string `json:"ip"`
	Vendor   string `json:"vendor"`
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
}

type diffFWChange struct {
	IP          string `json:"ip"`
	Vendor      string `json:"vendor"`
	Model       string `json:"model"`
	OldFirmware string `json:"old_firmware"`
	NewFirmware string `json:"new_firmware"`
}

type diffNewVuln struct {
	IP         string          `json:"ip"`
	Model      string          `json:"model"`
	Firmware   string          `json:"firmware"`
	Advisories []checkAdvisory `json:"advisories"`
}

type updateRequest struct {
	Since  string `json:"since"`
	Source string `json:"source"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:   "ok",
		Version:  cli.Version,
		DBLoaded: s.db != nil,
	})
}

func (s *Server) handleDBStats(w http.ResponseWriter, r *http.Request) {
	vendors := make(map[string]int)
	for _, a := range s.db.Advisories {
		vendors[a.Vendor]++
	}

	addedSince, chronic := s.db.StalenessStats(s.db.PreviousUpdated)

	resp := statsResponse{
		AdvisoryCount:  len(s.db.Advisories),
		Updated:        s.db.Updated.Format(time.RFC3339),
		Source:         s.db.Source,
		AddedSinceLast: addedSince,
		ChronicCount:   chronic,
		Vendors:        vendors,
	}
	if s.db.PreviousUpdated != nil {
		t := s.db.PreviousUpdated.Format(time.RFC3339)
		resp.PreviousUpdated = &t
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdvisories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}

	vendorFilter := strings.ToLower(q.Get("vendor"))
	minCVSS, _ := strconv.ParseFloat(q.Get("min_cvss"), 64)
	search := strings.ToLower(q.Get("q"))
	sortField := q.Get("sort")

	// Filter
	filtered := make([]advisory.Advisory, 0, len(s.db.Advisories))
	for _, a := range s.db.Advisories {
		if vendorFilter != "" && !strings.Contains(strings.ToLower(a.Vendor), vendorFilter) {
			continue
		}
		if minCVSS > 0 && a.CVSSv3Max < minCVSS {
			continue
		}
		if search != "" {
			match := strings.Contains(strings.ToLower(a.ID), search) ||
				strings.Contains(strings.ToLower(a.Title), search) ||
				strings.Contains(strings.ToLower(a.Vendor), search)
			if !match {
				for _, cve := range a.CVEs {
					if strings.Contains(strings.ToLower(cve), search) {
						match = true
						break
					}
				}
			}
			if !match {
				continue
			}
		}
		filtered = append(filtered, a)
	}

	// Sort — field:dir format (e.g. "cvss:desc", "vendor:asc")
	sortParts := strings.SplitN(sortField, ":", 2)
	sortKey := sortParts[0]
	sortAsc := len(sortParts) > 1 && sortParts[1] == "asc"

	switch sortKey {
	case "cvss":
		sort.Slice(filtered, func(i, j int) bool {
			if sortAsc {
				return filtered[i].CVSSv3Max < filtered[j].CVSSv3Max
			}
			return filtered[i].CVSSv3Max > filtered[j].CVSSv3Max
		})
	case "published":
		sort.Slice(filtered, func(i, j int) bool {
			if sortAsc {
				return filtered[i].Published < filtered[j].Published
			}
			return filtered[i].Published > filtered[j].Published
		})
	case "id":
		sort.Slice(filtered, func(i, j int) bool {
			if sortAsc {
				return filtered[i].ID < filtered[j].ID
			}
			return filtered[i].ID > filtered[j].ID
		})
	case "vendor":
		sort.Slice(filtered, func(i, j int) bool {
			if sortAsc {
				return strings.ToLower(filtered[i].Vendor) < strings.ToLower(filtered[j].Vendor)
			}
			return strings.ToLower(filtered[i].Vendor) > strings.ToLower(filtered[j].Vendor)
		})
	default:
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Published > filtered[j].Published })
	}

	// Paginate
	total := len(filtered)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	writeJSON(w, http.StatusOK, advisoryListResponse{
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		Advisories: filtered[start:end],
	})
}

type advisoryDetailResponse struct {
	advisory.Advisory
	KEV            bool    `json:"kev"`
	KEVRansomware  bool    `json:"kev_ransomware,omitempty"`
	EPSSScore      float64 `json:"epss_score,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	RiskScore      float64 `json:"risk_score"`
}

func (s *Server) handleAdvisory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, a := range s.db.Advisories {
		if strings.EqualFold(a.ID, id) {
			resp := advisoryDetailResponse{Advisory: a}
			if s.edb != nil && s.edb.Loaded() {
				ae := s.edb.EnrichAdvisory(a.CVEs, a.CVSSv3Max)
				resp.KEV = ae.KEV
				resp.KEVRansomware = ae.KEVRansomware
				resp.EPSSScore = ae.MaxEPSS
				resp.EPSSPercentile = ae.MaxEPSSPercent
				resp.RiskScore = ae.RiskScore
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, errorResponse{Error: "advisory not found"})
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.Devices) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no devices provided"})
		return
	}

	resp := s.runCheck(req.Devices, req.MinConfidence, req.MinCVSS, req.Vendor)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCheckUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid multipart form"})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "missing file field"})
		return
	}
	defer file.Close()

	format := r.FormValue("format")
	if format == "" {
		format = "auto"
	}
	minConfidence := r.FormValue("min_confidence")
	minCVSS, _ := strconv.ParseFloat(r.FormValue("min_cvss"), 64)
	vendor := r.FormValue("vendor")

	// Write to temp file for inventory.ParseFile
	tmp, err := os.CreateTemp("", "deadband-upload-*-"+header.Filename)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create temp file"})
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := io.Copy(tmp, file); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to save upload"})
		return
	}
	tmp.Close()

	devices, err := inventory.ParseFile(tmp.Name(), format)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("failed to parse inventory: %v", err)})
		return
	}

	resp := s.runCheck(devices, minConfidence, minCVSS, vendor)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	var req diffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.BaseDevices) == 0 || len(req.CompareDevices) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "both base_devices and compare_devices are required"})
		return
	}

	conf := matcher.ParseConfidence(req.MinConfidence)
	opts := matcher.FilterOpts{MinConfidence: conf, MinCVSS: req.MinCVSS, Vendor: req.Vendor}
	report := diff.Compute(req.BaseDevices, req.CompareDevices, s.db, opts)
	writeJSON(w, http.StatusOK, buildDiffResponse(report))
}

func (s *Server) handleDiffUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid multipart form"})
		return
	}

	baseDevices, err := parseUploadedInventory(r, "base")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("base file: %v", err)})
		return
	}
	compareDevices, err := parseUploadedInventory(r, "compare")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("compare file: %v", err)})
		return
	}

	minConfidence := r.FormValue("min_confidence")
	minCVSS, _ := strconv.ParseFloat(r.FormValue("min_cvss"), 64)
	vendor := r.FormValue("vendor")

	conf := matcher.ParseConfidence(minConfidence)
	opts := matcher.FilterOpts{MinConfidence: conf, MinCVSS: minCVSS, Vendor: vendor}
	report := diff.Compute(baseDevices, compareDevices, s.db, opts)
	writeJSON(w, http.StatusOK, buildDiffResponse(report))
}

func (s *Server) handleEnrichmentStats(w http.ResponseWriter, r *http.Request) {
	if s.edb == nil {
		writeJSON(w, http.StatusOK, enrichment.Stats{})
		return
	}
	writeJSON(w, http.StatusOK, s.edb.GetStats())
}

// --- Helpers ---

func (s *Server) runCheck(devices []inventory.Device, minConfidence string, minCVSS float64, vendor string) checkResponse {
	conf := matcher.ParseConfidence(minConfidence)
	opts := matcher.FilterOpts{MinConfidence: conf, MinCVSS: minCVSS, Vendor: vendor}
	results := matcher.MatchAll(devices, s.db, opts)

	resp := checkResponse{
		CheckedAt:      time.Now().UTC().Format(time.RFC3339),
		DBUpdated:      s.db.Updated.Format(time.RFC3339),
		DevicesChecked: len(devices),
		Results:        make([]checkDeviceResult, 0, len(results)),
	}

	for _, r := range results {
		confidence := ""
		if len(r.Matches) > 0 {
			confidence = string(r.Matches[0].Confidence)
		}
		dr := checkDeviceResult{
			IP:         r.Device.IP,
			Vendor:     r.Device.Vendor,
			Model:      r.Device.Model,
			Firmware:   r.Device.Firmware,
			Status:     r.Status,
			Confidence: confidence,
		}
		for _, m := range r.Matches {
			ca := checkAdvisory{
				ID:     m.Advisory.ID,
				CVEs:   m.Advisory.CVEs,
				CVSSv3: m.Advisory.CVSSv3Max,
				Title:  strings.TrimSpace(m.Advisory.Title),
				URL:    m.Advisory.URL,
			}
			if s.edb != nil && s.edb.Loaded() {
				ae := s.edb.EnrichAdvisory(m.Advisory.CVEs, m.Advisory.CVSSv3Max)
				ca.KEV = ae.KEV
				ca.KEVRansomware = ae.KEVRansomware
				ca.EPSSScore = ae.MaxEPSS
				ca.EPSSPercentile = ae.MaxEPSSPercent
				ca.RiskScore = ae.RiskScore
			}
			dr.Advisories = append(dr.Advisories, ca)
		}
		resp.Results = append(resp.Results, dr)

		switch strings.ToUpper(r.Status) {
		case "VULNERABLE":
			resp.Summary.Vulnerable++
		case "POTENTIAL":
			resp.Summary.Potential++
		case "OK":
			resp.Summary.OK++
		}
	}
	resp.Summary.NoMatch = len(devices) - len(results)

	return resp
}

func buildDiffResponse(report *diff.DiffReport) diffResponse {
	resp := diffResponse{
		ComparedAt:         time.Now().UTC().Format(time.RFC3339),
		NewDevices:         make([]diffDevice, 0, len(report.NewDevices)),
		RemovedDevices:     make([]diffDevice, 0, len(report.RemovedDevices)),
		FirmwareChanges:    make([]diffFWChange, 0, len(report.FirmwareChanges)),
		NewVulnerabilities: make([]diffNewVuln, 0, len(report.NewVulnerabilities)),
	}

	for _, d := range report.NewDevices {
		resp.NewDevices = append(resp.NewDevices, diffDevice{IP: d.IP, Vendor: d.Vendor, Model: d.Model, Firmware: d.Firmware})
	}
	for _, d := range report.RemovedDevices {
		resp.RemovedDevices = append(resp.RemovedDevices, diffDevice{IP: d.IP, Vendor: d.Vendor, Model: d.Model, Firmware: d.Firmware})
	}
	for _, fc := range report.FirmwareChanges {
		resp.FirmwareChanges = append(resp.FirmwareChanges, diffFWChange{
			IP: fc.Device.IP, Vendor: fc.Device.Vendor, Model: fc.Device.Model,
			OldFirmware: fc.OldFirmware, NewFirmware: fc.NewFirmware,
		})
	}
	for _, nv := range report.NewVulnerabilities {
		jnv := diffNewVuln{IP: nv.Device.IP, Model: nv.Device.Model, Firmware: nv.Device.Firmware}
		for _, m := range nv.NewMatches {
			jnv.Advisories = append(jnv.Advisories, checkAdvisory{
				ID: m.Advisory.ID, CVEs: m.Advisory.CVEs,
				CVSSv3: m.Advisory.CVSSv3Max, Title: strings.TrimSpace(m.Advisory.Title),
				URL: m.Advisory.URL,
			})
		}
		resp.NewVulnerabilities = append(resp.NewVulnerabilities, jnv)
	}

	resp.Summary = diffSummary{
		NewDevices:         len(report.NewDevices),
		RemovedDevices:     len(report.RemovedDevices),
		FirmwareChanges:    len(report.FirmwareChanges),
		NewVulnerabilities: len(report.NewVulnerabilities),
	}

	return resp
}

func parseUploadedInventory(r *http.Request, fieldName string) ([]inventory.Device, error) {
	file, header, err := r.FormFile(fieldName)
	if err != nil {
		return nil, fmt.Errorf("missing %s file", fieldName)
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "deadband-"+fieldName+"-*-"+header.Filename)
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := io.Copy(tmp, file); err != nil {
		return nil, fmt.Errorf("saving upload: %w", err)
	}
	tmp.Close()

	return inventory.ParseFile(tmp.Name(), "auto")
}

type baselineResponse struct {
	Exists    bool                `json:"exists"`
	UpdatedAt string              `json:"updated_at,omitempty"`
	Devices   []inventory.Device  `json:"devices,omitempty"`
	Count     int                 `json:"count"`
}

func (s *Server) handleGetBaseline(w http.ResponseWriter, r *http.Request) {
	path := baseline.DefaultPath()
	b, err := baseline.Load(path)
	if err != nil {
		writeJSON(w, http.StatusOK, baselineResponse{Exists: false})
		return
	}
	writeJSON(w, http.StatusOK, baselineResponse{
		Exists:    true,
		UpdatedAt: b.UpdatedAt.Format(time.RFC3339),
		Devices:   b.Devices,
		Count:     len(b.Devices),
	})
}

func (s *Server) handleSaveBaseline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Devices []inventory.Device `json:"devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.Devices) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no devices provided"})
		return
	}

	b := baseline.NewFromDevices(req.Devices)
	path := baseline.DefaultPath()
	if err := baseline.Save(path, b); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving baseline: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, baselineResponse{
		Exists:    true,
		UpdatedAt: b.UpdatedAt.Format(time.RFC3339),
		Count:     len(b.Devices),
	})
}

func (s *Server) handleCompareBaseline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Devices       []inventory.Device `json:"devices"`
		MinConfidence string             `json:"min_confidence"`
		MinCVSS       float64            `json:"min_cvss"`
		Vendor        string             `json:"vendor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.Devices) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no devices provided"})
		return
	}

	conf := matcher.ParseConfidence(req.MinConfidence)
	opts := matcher.FilterOpts{MinConfidence: conf, MinCVSS: req.MinCVSS, Vendor: req.Vendor}

	path := baseline.DefaultPath()
	report, err := baseline.Compare(path, req.Devices, s.db, opts)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: fmt.Sprintf("baseline comparison: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, buildDiffResponse(report))
}

type complianceMappingsResponse struct {
	Frameworks []string                    `json:"frameworks"`
	Mappings   []compliance.ControlMapping `json:"mappings"`
}

func handleComplianceMappings(w http.ResponseWriter, r *http.Request) {
	framework := r.URL.Query().Get("framework")
	var mappings []compliance.ControlMapping
	if framework == "" {
		mappings = compliance.AllMappings()
	} else {
		frameworks := strings.Split(framework, ",")
		mappings = compliance.ForFrameworks(frameworks)
	}
	writeJSON(w, http.StatusOK, complianceMappingsResponse{
		Frameworks: compliance.Frameworks(),
		Mappings:   mappings,
	})
}

// --- Asset handlers ---

type assetListResponse struct {
	Total  int           `json:"total"`
	Assets []asset.Asset `json:"assets"`
	// Facets for filter dropdowns
	Sites []string `json:"sites"`
	Zones []string `json:"zones"`
	Tags  []string `json:"tags"`
}

func (s *Server) handleGetAssets(w http.ResponseWriter, r *http.Request) {
	store := asset.LoadOrEmpty(asset.DefaultPath())

	q := r.URL.Query()
	sortParts := strings.SplitN(q.Get("sort"), ":", 2)
	sortField := sortParts[0]
	sortAsc := len(sortParts) > 1 && sortParts[1] == "asc"

	opts := asset.FilterOpts{
		Vendor:      q.Get("vendor"),
		Site:        q.Get("site"),
		Zone:        q.Get("zone"),
		Criticality: q.Get("criticality"),
		Tag:         q.Get("tag"),
		Search:      q.Get("q"),
		SortField:   sortField,
		SortAsc:     sortAsc,
	}

	filtered := store.Filter(opts)
	sites, zones, tags := store.DistinctValues()

	writeJSON(w, http.StatusOK, assetListResponse{
		Total:  len(filtered),
		Assets: filtered,
		Sites:  sites,
		Zones:  zones,
		Tags:   tags,
	})
}

type assetImportRequest struct {
	Devices []inventory.Device `json:"devices"`
	Source  string             `json:"source"`
}

func (s *Server) handleImportAssets(w http.ResponseWriter, r *http.Request) {
	var req assetImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.Devices) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no devices provided"})
		return
	}
	if req.Source == "" {
		req.Source = "manual"
	}

	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)
	result := store.Import(req.Devices, req.Source)

	if err := asset.Save(path, store); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving assets: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var patch asset.AssetPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)

	if !store.Update(id, patch) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "asset not found"})
		return
	}

	if err := asset.Save(path, store); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving assets: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, store.Get(id))
}

func (s *Server) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)

	if !store.Delete(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "asset not found"})
		return
	}

	if err := asset.Save(path, store); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving assets: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type bulkTagRequest struct {
	IDs    []string `json:"ids"`
	AddTags    []string `json:"add_tags,omitempty"`
	RemoveTags []string `json:"remove_tags,omitempty"`
	SetSite    *string  `json:"set_site,omitempty"`
	SetZone    *string  `json:"set_zone,omitempty"`
	SetCriticality *string `json:"set_criticality,omitempty"`
}

func (s *Server) handleBulkUpdateAssets(w http.ResponseWriter, r *http.Request) {
	var req bulkTagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if len(req.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no asset IDs provided"})
		return
	}

	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)

	updated := 0
	idSet := make(map[string]bool, len(req.IDs))
	for _, id := range req.IDs {
		idSet[id] = true
	}

	for i := range store.Assets {
		if !idSet[store.Assets[i].ID] {
			continue
		}
		a := &store.Assets[i]
		if req.SetSite != nil {
			a.Site = *req.SetSite
		}
		if req.SetZone != nil {
			a.Zone = *req.SetZone
		}
		if req.SetCriticality != nil {
			a.Criticality = *req.SetCriticality
		}
		for _, t := range req.AddTags {
			if !hasTag(a.Tags, t) {
				a.Tags = append(a.Tags, t)
			}
		}
		for _, t := range req.RemoveTags {
			a.Tags = removeTag(a.Tags, t)
		}
		updated++
	}

	if err := asset.Save(path, store); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving assets: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]int{"updated": updated})
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

func removeTag(tags []string, tag string) []string {
	out := tags[:0]
	for _, t := range tags {
		if !strings.EqualFold(t, tag) {
			out = append(out, t)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

