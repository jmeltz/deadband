package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/acl"
	"github.com/jmeltz/deadband/pkg/acl/simulate"
	"github.com/jmeltz/deadband/pkg/flow"
	"github.com/jmeltz/deadband/pkg/integration"
	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/baseline"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/compliance"
	"github.com/jmeltz/deadband/pkg/diff"
	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/enrichment"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
	"github.com/jmeltz/deadband/pkg/output"
	"github.com/jmeltz/deadband/pkg/posture"
	"github.com/jmeltz/deadband/pkg/site"
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

	// Auto-enrich unassigned assets with site from CIDR matching (read-time only)
	if s.siteStore != nil {
		for i := range store.Assets {
			if store.Assets[i].Site == "" {
				if matched := s.siteStore.MatchIP(store.Assets[i].IP); matched != nil {
					store.Assets[i].Site = matched.Name
				}
			}
		}
	}

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
		Status:      q.Get("status"),
		VulnStatus:  q.Get("vuln_status"),
		CVE:         q.Get("cve"),
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

	// Auto-assign sites based on CIDR matching
	if s.siteStore != nil {
		s.siteStore.AssignAll(store.Assets)
	}

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

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	store := asset.LoadOrEmpty(asset.DefaultPath())

	a := store.Get(id)
	if a == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "asset not found"})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type checkAssetsRequest struct {
	IDs         []string `json:"ids,omitempty"`
	Site        string   `json:"site,omitempty"`
	Zone        string   `json:"zone,omitempty"`
	Criticality string   `json:"criticality,omitempty"`
}

type checkAssetsResponse struct {
	Checked     int `json:"checked"`
	Vulnerable  int `json:"vulnerable"`
	Potential   int `json:"potential"`
	OK          int `json:"ok"`
}

func (s *Server) handleCheckAssets(w http.ResponseWriter, r *http.Request) {
	var req checkAssetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)

	if len(store.Assets) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no assets in inventory"})
		return
	}

	// Select which assets to check
	var targets []asset.Asset
	if len(req.IDs) > 0 {
		idSet := make(map[string]bool, len(req.IDs))
		for _, id := range req.IDs {
			idSet[id] = true
		}
		for _, a := range store.Assets {
			if idSet[a.ID] {
				targets = append(targets, a)
			}
		}
	} else {
		opts := asset.FilterOpts{
			Site:        req.Site,
			Zone:        req.Zone,
			Criticality: req.Criticality,
		}
		targets = store.Filter(opts)
	}

	if len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no assets match the given filters"})
		return
	}

	// Convert assets to devices for matching
	devices := make([]inventory.Device, len(targets))
	assetIDs := make([]string, len(targets))
	for i, a := range targets {
		devices[i] = inventory.Device{
			IP: a.IP, Vendor: a.Vendor, Model: a.Model, Firmware: a.Firmware,
		}
		assetIDs[i] = a.ID
	}

	// Run vulnerability check
	filterOpts := matcher.FilterOpts{}
	results := matcher.MatchAll(devices, s.db, filterOpts)
	now := time.Now().UTC()

	resp := checkAssetsResponse{Checked: len(targets)}

	// Build result map keyed by IP+Vendor+Model for matching back to assets
	type resultKey struct{ ip, vendor, model string }
	resultMap := make(map[resultKey]*matcher.Result)
	for i := range results {
		r := &results[i]
		resultMap[resultKey{r.Device.IP, r.Device.Vendor, r.Device.Model}] = r
	}

	// Write vuln state back to assets
	for i, a := range targets {
		_ = assetIDs[i]
		key := resultKey{a.IP, a.Vendor, a.Model}
		r, ok := resultMap[key]

		state := &asset.VulnState{CheckedAt: now, Status: "OK"}

		if ok && len(r.Matches) > 0 {
			state.Status = r.Status
			if len(r.Matches) > 0 {
				state.Confidence = string(r.Matches[0].Confidence)
			}
			for _, m := range r.Matches {
				va := asset.VulnAdvisory{
					ID:     m.Advisory.ID,
					Title:  strings.TrimSpace(m.Advisory.Title),
					CVEs:   m.Advisory.CVEs,
					CVSSv3: m.Advisory.CVSSv3Max,
				}
				if s.edb != nil && s.edb.Loaded() {
					ae := s.edb.EnrichAdvisory(m.Advisory.CVEs, m.Advisory.CVSSv3Max)
					va.KEV = ae.KEV
					va.RiskScore = ae.RiskScore
					state.KEVCount += boolToInt(ae.KEV)
				}
				state.CVECount += len(m.Advisory.CVEs)
				state.Advisories = append(state.Advisories, va)
				if va.RiskScore > state.RiskScore {
					state.RiskScore = va.RiskScore
				}
			}
		}

		store.UpdateVulnState(a.ID, state)

		switch strings.ToUpper(state.Status) {
		case "VULNERABLE":
			resp.Vulnerable++
		case "POTENTIAL":
			resp.Potential++
		default:
			resp.OK++
		}
	}

	if err := asset.Save(path, store); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving assets: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
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

// --- Discovery history + schedule handlers ---

func (s *Server) handleDiscoverHistory(w http.ResponseWriter, r *http.Request) {
	store := discover.LoadJobStore(discover.DefaultJobStorePath())
	writeJSON(w, http.StatusOK, store.List())
}

func (s *Server) handleDiscoverHistoryDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	store := discover.LoadJobStore(discover.DefaultJobStorePath())
	rec := store.Get(id)
	if rec == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleGetSchedules(w http.ResponseWriter, r *http.Request) {
	store := discover.LoadScheduleStore(discover.DefaultScheduleStorePath())
	writeJSON(w, http.StatusOK, store.List())
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var sched discover.Schedule
	if err := json.NewDecoder(r.Body).Decode(&sched); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if sched.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cidr is required"})
		return
	}
	if sched.ID == "" {
		sched.ID = newScheduleID()
	}
	if sched.Interval == "" {
		sched.Interval = "24h"
	}

	store := discover.LoadScheduleStore(discover.DefaultScheduleStorePath())
	result := store.Upsert(sched)
	if err := store.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving schedule: %v", err)})
		return
	}

	// Update scheduler timer if running
	if s.scheduler != nil {
		s.scheduler.Reschedule(result)
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	store := discover.LoadScheduleStore(discover.DefaultScheduleStorePath())
	if !store.Delete(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "schedule not found"})
		return
	}
	if err := store.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving schedule: %v", err)})
		return
	}
	if s.scheduler != nil {
		s.scheduler.Cancel(id)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func newScheduleID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Asset summary + export handlers ---

func (s *Server) handleAssetSummary(w http.ResponseWriter, r *http.Request) {
	store := asset.LoadOrEmpty(asset.DefaultPath())
	writeJSON(w, http.StatusOK, store.ComputeSummary())
}

func (s *Server) handleAssetExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	store := asset.LoadOrEmpty(asset.DefaultPath())
	assets := store.Filter(asset.FilterOpts{})

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=deadband-assets.json")
		output.WriteAssetsJSON(w, assets)
	case "dbd":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=deadband-assets.dbd")
		output.WriteDBD(w, assets, s.siteStore.List(), s.postureStore.List())
	default:
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=deadband-assets.csv")
		output.WriteAssetsCSV(w, assets)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// --- Site handlers ---

func (s *Server) handleGetSites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.siteStore.List())
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st := s.siteStore.Get(id)
	if st == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleUpsertSite(w http.ResponseWriter, r *http.Request) {
	var st site.Site
	if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if st.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "name is required"})
		return
	}
	if len(st.CIDRs) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "at least one CIDR is required"})
		return
	}
	for _, cidr := range st.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid CIDR %q: %v", cidr, err)})
			return
		}
	}

	now := time.Now().UTC()
	if st.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		st.ID = hex.EncodeToString(b)
		st.CreatedAt = now
	}
	st.UpdatedAt = now

	result := s.siteStore.Upsert(st)
	if err := s.siteStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving site: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.siteStore.Delete(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}
	if err := s.siteStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving sites: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleReassignSites(w http.ResponseWriter, r *http.Request) {
	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)
	count := s.siteStore.AssignAll(store.Assets)
	if err := asset.Save(path, store); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving assets: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"reassigned": count})
}

// --- Zone handlers ---

func (s *Server) handleGetZones(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	st := s.siteStore.Get(siteID)
	if st == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}
	zones := st.Zones
	if zones == nil {
		zones = []site.Zone{}
	}
	writeJSON(w, http.StatusOK, zones)
}

func (s *Server) handleUpsertZone(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	var z site.Zone
	if err := json.NewDecoder(r.Body).Decode(&z); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if z.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "name is required"})
		return
	}
	if len(z.CIDRs) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "at least one CIDR is required"})
		return
	}
	for _, cidr := range z.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid CIDR %q: %v", cidr, err)})
			return
		}
	}
	if z.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		z.ID = hex.EncodeToString(b)
	}

	if err := s.siteStore.UpsertZone(siteID, z); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: err.Error()})
		return
	}
	if err := s.siteStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving site: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, z)
}

func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	zoneID := r.PathValue("zoneId")
	if err := s.siteStore.DeleteZone(siteID, zoneID); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: err.Error()})
		return
	}
	if err := s.siteStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving site: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- .dbd import handler ---

func (s *Server) handleImportDBD(w http.ResponseWriter, r *http.Request) {
	dbd, err := output.ReadDBDFull(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid .dbd file: %v", err)})
		return
	}

	// Import posture reports
	postureImported := 0
	if len(dbd.PostureReports) > 0 {
		existing := make(map[string]bool)
		for _, r := range s.postureStore.List() {
			existing[r.ID] = true
		}
		for _, rpt := range dbd.PostureReports {
			if !existing[rpt.ID] {
				s.postureStore.AddReport(rpt)
				postureImported++
			}
		}
		if postureImported > 0 {
			s.postureStore.Save()
		}
	}

	// Import sites
	sitesImported := 0
	for _, st := range dbd.Sites {
		if st.Name == "" {
			continue
		}
		if st.ID == "" {
			b := make([]byte, 8)
			rand.Read(b)
			st.ID = hex.EncodeToString(b)
		}
		st.UpdatedAt = time.Now().UTC()
		s.siteStore.Upsert(st)
		sitesImported++
	}
	if sitesImported > 0 {
		if err := s.siteStore.Save(); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving sites: %v", err)})
			return
		}
	}

	// Import assets with merge logic
	path := asset.DefaultPath()
	store := asset.LoadOrEmpty(path)

	added, updated := 0, 0
	idIdx := make(map[string]int, len(store.Assets))
	dedupIdx := make(map[string]int, len(store.Assets))
	for i, a := range store.Assets {
		idIdx[a.ID] = i
		dedupIdx[strings.ToLower(a.IP+"|"+a.Vendor+"|"+a.Model)] = i
	}

	for _, incoming := range dbd.Assets {
		existIdx := -1
		if incoming.ID != "" {
			if idx, ok := idIdx[incoming.ID]; ok {
				existIdx = idx
			}
		}
		if existIdx < 0 {
			key := strings.ToLower(incoming.IP + "|" + incoming.Vendor + "|" + incoming.Model)
			if idx, ok := dedupIdx[key]; ok {
				existIdx = idx
			}
		}

		if existIdx >= 0 {
			existing := &store.Assets[existIdx]
			existing.Name = incoming.Name
			existing.Site = incoming.Site
			existing.Zone = incoming.Zone
			existing.Criticality = incoming.Criticality
			existing.Tags = incoming.Tags
			existing.Notes = incoming.Notes
			existing.Status = incoming.Status
			existing.Firmware = incoming.Firmware
			if incoming.VulnState != nil {
				existing.VulnState = incoming.VulnState
			}
			if !incoming.LastSeen.IsZero() {
				existing.LastSeen = incoming.LastSeen
			}
			updated++
		} else {
			if incoming.ID == "" {
				b := make([]byte, 8)
				rand.Read(b)
				incoming.ID = hex.EncodeToString(b)
			}
			if incoming.Tags == nil {
				incoming.Tags = []string{}
			}
			store.Assets = append(store.Assets, incoming)
			added++
		}
	}

	if err := asset.Save(path, store); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving assets: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]int{
		"sites_imported":   sitesImported,
		"assets_added":     added,
		"assets_updated":   updated,
		"total_assets":     len(store.Assets),
		"posture_imported": postureImported,
	})
}

// --- Posture Analysis handlers ---

type postureScanRequest struct {
	CIDR        string `json:"cidr"`
	TimeoutMS   int    `json:"timeout_ms"`
	Concurrency int    `json:"concurrency"`
}

func (s *Server) handlePostureScan(w http.ResponseWriter, r *http.Request) {
	var req postureScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cidr is required"})
		return
	}

	timeout := 2 * time.Second
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	concurrency := 100
	if req.Concurrency > 0 {
		concurrency = req.Concurrency
	}

	// Set up SSE streaming
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "streaming not supported"})
		return
	}

	sendEvent := func(eventType, msg string) {
		data, _ := json.Marshal(map[string]string{"type": eventType, "message": msg})
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	startedAt := time.Now().UTC()

	// Load assets first for OT-safe scanning (known OT hosts skip IT probes)
	sendEvent("progress", fmt.Sprintf("Starting posture scan on %s...", req.CIDR))
	store := asset.LoadOrEmpty(asset.DefaultPath())

	hosts, err := posture.ScanSubnetWithAssets(req.CIDR, timeout, concurrency, store.Assets, func(msg string) {
		sendEvent("progress", msg)
	})
	if err != nil {
		sendEvent("error", fmt.Sprintf("Scan failed: %v", err))
		return
	}

	// Classification + banner probing
	sendEvent("progress", "Classifying hosts and probing service banners...")
	classified := posture.ClassifyHostsWithProgress(hosts, store.Assets, timeout, 32, func(msg string) {
		sendEvent("progress", msg)
	})

	otCount, itCount, netCount, unkCount := 0, 0, 0, 0
	for _, h := range classified {
		switch h.DeviceClass {
		case posture.ClassOT:
			otCount++
		case posture.ClassIT:
			itCount++
		case posture.ClassNetwork:
			netCount++
		default:
			unkCount++
		}
	}
	sendEvent("progress", fmt.Sprintf("Classified %d hosts: %d OT, %d IT, %d network, %d unknown",
		len(classified), otCount, itCount, netCount, unkCount))

	// Phase 3: Subnet analysis (zone-aware if zones exist)
	var subnets []posture.SubnetAnalysis
	var usedZones bool
	if _, cidrNet, err := net.ParseCIDR(req.CIDR); err == nil {
		// Use the network address +1 as a representative IP for site matching
		repIP := make(net.IP, len(cidrNet.IP))
		copy(repIP, cidrNet.IP)
		repIP[len(repIP)-1]++
		if matchedSite := s.siteStore.MatchIP(repIP.String()); matchedSite != nil && len(matchedSite.Zones) > 0 {
			sendEvent("progress", fmt.Sprintf("Analyzing %d zones in site '%s'...", len(matchedSite.Zones), matchedSite.Name))
			subnets = posture.AnalyzeWithZones(classified, matchedSite.Zones)
			usedZones = true
		}
	}
	if !usedZones {
		sendEvent("progress", "Analyzing subnets...")
		subnets = posture.AnalyzeSubnets(classified)
	}
	mixedCount := 0
	for _, sa := range subnets {
		if sa.IsMixed {
			mixedCount++
		}
	}
	sendEvent("progress", fmt.Sprintf("Analyzed %d subnets (%d mixed)", len(subnets), mixedCount))

	// Phase 4: Generate findings
	sendEvent("progress", "Generating findings...")
	findings := posture.GenerateFindings(subnets)
	critCount := 0
	for _, f := range findings {
		if f.Severity == "critical" {
			critCount++
		}
	}
	sendEvent("progress", fmt.Sprintf("Generated %d findings (%d critical)", len(findings), critCount))

	// Build and save report
	summary := posture.BuildSummary(subnets, findings)
	duration := time.Since(startedAt).Round(time.Millisecond).String()

	b := make([]byte, 8)
	rand.Read(b)
	report := posture.PostureReport{
		ID:        hex.EncodeToString(b),
		CIDR:      req.CIDR,
		ScannedAt: startedAt,
		Duration:  duration,
		Subnets:   subnets,
		Findings:  findings,
		Summary:   summary,
	}

	s.postureStore.AddReport(report)
	if err := s.postureStore.Save(); err != nil {
		sendEvent("error", fmt.Sprintf("Failed to save report: %v", err))
		return
	}

	// Send final complete event with the report
	finalData, _ := json.Marshal(map[string]any{
		"type":   "complete",
		"report": report,
	})
	fmt.Fprintf(w, "data: %s\n\n", finalData)
	flusher.Flush()
}

func (s *Server) handleGetPosture(w http.ResponseWriter, r *http.Request) {
	report := s.postureStore.Latest()
	if report == nil {
		writeJSON(w, http.StatusOK, map[string]any{"report": nil})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleListPostureReports(w http.ResponseWriter, r *http.Request) {
	reports := s.postureStore.List()
	// Return summaries only (no full subnet/finding data)
	type reportSummary struct {
		ID        string                 `json:"id"`
		CIDR      string                 `json:"cidr"`
		ScannedAt time.Time              `json:"scanned_at"`
		Duration  string                 `json:"duration"`
		Summary   posture.PostureSummary `json:"summary"`
	}
	summaries := make([]reportSummary, len(reports))
	for i, r := range reports {
		summaries[i] = reportSummary{
			ID:        r.ID,
			CIDR:      r.CIDR,
			ScannedAt: r.ScannedAt,
			Duration:  r.Duration,
			Summary:   r.Summary,
		}
	}
	writeJSON(w, http.StatusOK, summaries)
}

func (s *Server) handleGetPostureReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	report := s.postureStore.Get(id)
	if report == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "report not found"})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
	report := s.postureStore.Latest()
	if report == nil {
		writeJSON(w, http.StatusOK, []posture.Finding{})
		return
	}

	severity := r.URL.Query().Get("severity")
	if severity == "" {
		writeJSON(w, http.StatusOK, report.Findings)
		return
	}

	var filtered []posture.Finding
	for _, f := range report.Findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleGetControlMappings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, posture.AllControlMappings())
}

type hostPostureDetail struct {
	Host     posture.ClassifiedHost  `json:"host"`
	Findings []posture.Finding       `json:"findings"`
	Subnet   *posture.SubnetAnalysis `json:"subnet"`
}

func (s *Server) handleGetPostureHost(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	report := s.postureStore.Latest()
	if report == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no posture report available"})
		return
	}

	// Find host across all subnets
	var foundHost *posture.ClassifiedHost
	var foundSubnet *posture.SubnetAnalysis
	for i := range report.Subnets {
		for j := range report.Subnets[i].Hosts {
			if report.Subnets[i].Hosts[j].IP == ip {
				h := report.Subnets[i].Hosts[j]
				foundHost = &h
				sa := report.Subnets[i]
				foundSubnet = &sa
				break
			}
		}
		if foundHost != nil {
			break
		}
	}

	if foundHost == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "host not found in latest posture report"})
		return
	}

	// Collect findings that reference this host's IP
	var hostFindings []posture.Finding
	for _, f := range report.Findings {
		if f.Subnet != foundSubnet.Subnet {
			continue
		}
		// Check if evidence mentions this IP
		for _, e := range f.Evidence {
			if strings.Contains(e, ip) {
				hostFindings = append(hostFindings, f)
				break
			}
		}
	}
	// Also include subnet-scope findings for this subnet (they affect all hosts)
	for _, f := range report.Findings {
		if f.Subnet != foundSubnet.Subnet {
			continue
		}
		// Subnet-scoped findings like mixed_subnet, no_segmentation apply to all hosts
		alreadyAdded := false
		for _, hf := range hostFindings {
			if hf.ID == f.ID {
				alreadyAdded = true
				break
			}
		}
		if !alreadyAdded {
			hostFindings = append(hostFindings, f)
		}
	}

	writeJSON(w, http.StatusOK, hostPostureDetail{
		Host:     *foundHost,
		Findings: hostFindings,
		Subnet:   foundSubnet,
	})
}

// --- Control state + risk simulation handlers ---

func (s *Server) handleGetControlStates(w http.ResponseWriter, r *http.Request) {
	states := s.controlStateStore.GetStates()
	if states == nil {
		states = []posture.ControlState{}
	}
	writeJSON(w, http.StatusOK, states)
}

type setControlStateRequest struct {
	FindingType string `json:"finding_type"`
	ControlID   string `json:"control_id"`
	Status      string `json:"status"`
	Notes       string `json:"notes"`
}

func (s *Server) handleSetControlState(w http.ResponseWriter, r *http.Request) {
	var req setControlStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.FindingType == "" || req.ControlID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "finding_type and control_id are required"})
		return
	}
	validStatuses := map[string]bool{"applied": true, "planned": true, "not_applicable": true, "": true}
	if !validStatuses[req.Status] {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "status must be applied, planned, or not_applicable"})
		return
	}

	// Empty status means remove
	if req.Status == "" {
		s.controlStateStore.DeleteState(req.FindingType, req.ControlID)
	} else {
		s.controlStateStore.SetState(req.FindingType, req.ControlID, req.Status, req.Notes)
	}

	if err := s.controlStateStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving control state: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, s.controlStateStore.GetStates())
}

type riskSimRequest struct {
	Subnet string `json:"subnet"` // optional — if empty uses overall score
}

func (s *Server) handleRiskSimulation(w http.ResponseWriter, r *http.Request) {
	var req riskSimRequest
	json.NewDecoder(r.Body).Decode(&req)

	report := s.postureStore.Latest()
	if report == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no posture report available"})
		return
	}

	states := s.controlStateStore.GetStates()

	if req.Subnet != "" {
		// Simulate for a specific subnet
		for _, sa := range report.Subnets {
			if sa.Subnet == req.Subnet {
				// Collect findings for this subnet
				var subFindings []posture.Finding
				for _, f := range report.Findings {
					if f.Subnet == sa.Subnet {
						subFindings = append(subFindings, f)
					}
				}
				result := posture.WhatIf(sa.RiskScore, subFindings, states)
				writeJSON(w, http.StatusOK, result)
				return
			}
		}
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "subnet not found in latest report"})
		return
	}

	// Simulate for overall score
	result := posture.WhatIf(report.Summary.OverallScore, report.Findings, states)
	writeJSON(w, http.StatusOK, result)
}

// --- ACL Policy handlers ---

func (s *Server) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.aclStore.List()
	if policies == nil {
		policies = []acl.Policy{}
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleUpsertPolicy(w http.ResponseWriter, r *http.Request) {
	var p acl.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if p.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "name is required"})
		return
	}
	if p.SiteID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "site_id is required"})
		return
	}

	now := time.Now().UTC()
	if p.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		p.ID = hex.EncodeToString(b)
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	if p.DefaultAction == "" {
		p.DefaultAction = "deny"
	}

	result := s.aclStore.Upsert(p)
	if err := s.aclStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving policy: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.aclStore.Delete(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "policy not found"})
		return
	}
	if err := s.aclStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving policies: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type generatePolicyRequest struct {
	SiteID string `json:"site_id"`
}

func (s *Server) handleGenerateDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	var req generatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.SiteID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "site_id is required"})
		return
	}

	st := s.siteStore.Get(req.SiteID)
	if st == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}
	if len(st.Zones) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "site has no zones defined"})
		return
	}

	policy := acl.GenerateDefaultPolicy(*st)
	result := s.aclStore.Upsert(policy)
	if err := s.aclStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: fmt.Sprintf("saving policy: %v", err)})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAnalyzeGaps(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	policy := s.aclStore.Get(id)
	if policy == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "policy not found"})
		return
	}

	report := s.postureStore.Latest()
	if report == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no posture report available for gap analysis"})
		return
	}

	st := s.siteStore.Get(policy.SiteID)
	if st == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}

	var gapOpts []acl.GapOpts

	if r.URL.Query().Get("include_flows") == "true" && s.sentinelStore != nil {
		if snap := s.sentinelStore.GetLatest(policy.SiteID); snap != nil && len(snap.Flows) > 0 {
			gapOpts = append(gapOpts, acl.GapOpts{Flows: snap.Flows})
		}
	}

	violations := acl.AnalyzeGaps(*policy, *report, st.Zones, gapOpts...)
	if violations == nil {
		violations = []acl.Violation{}
	}
	writeJSON(w, http.StatusOK, violations)
}

func (s *Server) handleSimulatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SiteID          string     `json:"site_id"`
		PolicyID        string     `json:"policy_id"`
		PlannedPolicy   acl.Policy `json:"planned_policy"`
		FlowWindow      string     `json:"flow_window"`
		IncludeObserved *bool      `json:"include_observed,omitempty"`
		IncludeImplied  *bool      `json:"include_implied,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.SiteID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "site_id is required"})
		return
	}

	current := s.aclStore.Get(req.PolicyID)
	if current == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "current policy not found"})
		return
	}
	st := s.siteStore.Get(req.SiteID)
	if st == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "site not found"})
		return
	}

	includeObserved := true
	if req.IncludeObserved != nil {
		includeObserved = *req.IncludeObserved
	}
	includeImplied := true
	if req.IncludeImplied != nil {
		includeImplied = *req.IncludeImplied
	}

	window := parseFlowWindow(req.FlowWindow)

	var flows []flow.FlowRecord

	if includeObserved && s.sentinelStore != nil {
		if snap := s.sentinelStore.GetLatest(req.SiteID); snap != nil {
			cutoff := time.Now().Add(-window)
			for _, f := range snap.Flows {
				if f.ObservedAt.IsZero() || f.ObservedAt.After(cutoff) {
					flows = append(flows, f)
				}
			}
		}
	}

	if includeImplied && s.postureStore != nil {
		report := s.postureStore.Latest()
		if report != nil {
			rules := make([]flow.PolicyRuleAdapter, 0, len(req.PlannedPolicy.Rules))
			for _, r := range req.PlannedPolicy.Rules {
				if r.Action != "allow" {
					continue
				}
				rules = append(rules, flow.PolicyRuleAdapter{
					ID:         r.ID,
					SourceZone: r.SourceZone,
					DestZone:   r.DestZone,
					Ports:      r.Ports,
				})
			}
			implied := flow.SynthesizeImplied(rules, *report, st.Zones)
			flows = append(flows, implied...)
		}
	}

	currentVerdicts := simulate.Evaluate(*current, flows, st.Zones)
	plannedVerdicts := simulate.Evaluate(req.PlannedPolicy, flows, st.Zones)
	diff := simulate.Diff(currentVerdicts, plannedVerdicts)

	resp := simulate.SimulationResponse{
		Current: simulate.Summarize(currentVerdicts),
		Planned: simulate.Summarize(plannedVerdicts),
		Diff:    diff,
	}
	if resp.Diff.NewlyDenied == nil {
		resp.Diff.NewlyDenied = []simulate.FlowVerdict{}
	}
	if resp.Diff.NewlyAllowed == nil {
		resp.Diff.NewlyAllowed = []simulate.FlowVerdict{}
	}
	if resp.Diff.Unchanged.ByZone == nil {
		resp.Diff.Unchanged.ByZone = []simulate.ZoneCount{}
	}
	writeJSON(w, http.StatusOK, resp)
}

func parseFlowWindow(s string) time.Duration {
	switch s {
	case "24h":
		return 24 * time.Hour
	case "7d", "":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return 7 * 24 * time.Hour
}

// --- Integration config handlers ---

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) handleGetSentinelConfigs(w http.ResponseWriter, r *http.Request) {
	configs := s.integrationStore.ListSentinel()
	if configs == nil {
		configs = []integration.SentinelConfig{}
	}
	writeJSON(w, http.StatusOK, configs)
}

func (s *Server) handleUpsertSentinelConfig(w http.ResponseWriter, r *http.Request) {
	var cfg integration.SentinelConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.WorkspaceID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "tenant_id, client_id, client_secret, and workspace_id are required"})
		return
	}
	if cfg.ID == "" {
		cfg.ID = newID()
	}
	cfg = s.integrationStore.UpsertSentinel(cfg)
	if err := s.integrationStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleDeleteSentinelConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.integrationStore.DeleteSentinel(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "sentinel config not found"})
		return
	}
	s.integrationStore.Save()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTestSentinelConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cfg := s.integrationStore.GetSentinel(id)
	if cfg == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "sentinel config not found"})
		return
	}

	// Test by acquiring an OAuth2 token
	client := sentinelClientFromConfig(*cfg)
	if err := client.TestConnection(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetASAConfigs(w http.ResponseWriter, r *http.Request) {
	configs := s.integrationStore.ListASA()
	if configs == nil {
		configs = []integration.ASAConfig{}
	}
	writeJSON(w, http.StatusOK, configs)
}

func (s *Server) handleUpsertASAConfig(w http.ResponseWriter, r *http.Request) {
	var cfg integration.ASAConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if cfg.Host == "" || cfg.Username == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "host and username are required"})
		return
	}
	if cfg.ID == "" {
		cfg.ID = newID()
	}
	cfg = s.integrationStore.UpsertASA(cfg)
	if err := s.integrationStore.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleDeleteASAConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.integrationStore.DeleteASA(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "asa config not found"})
		return
	}
	s.integrationStore.Save()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTestASAConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cfg := s.integrationStore.GetASA(id)
	if cfg == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "asa config not found"})
		return
	}

	// Test by opening SSH connection and reading prompt
	client := asaClientFromConfig(*cfg)
	if err := client.TestConnection(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

