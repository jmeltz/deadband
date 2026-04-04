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
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/diff"
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
	ID     string   `json:"id"`
	CVEs   []string `json:"cves"`
	CVSSv3 float64  `json:"cvss_v3"`
	Title  string   `json:"title"`
	URL    string   `json:"url"`
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

	// Sort
	switch sortField {
	case "cvss":
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].CVSSv3Max > filtered[j].CVSSv3Max })
	case "published":
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Published > filtered[j].Published })
	case "id":
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].ID > filtered[j].ID })
	default:
		// Default: most recently published first
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

func (s *Server) handleAdvisory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, a := range s.db.Advisories {
		if strings.EqualFold(a.ID, id) {
			writeJSON(w, http.StatusOK, a)
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
			dr.Advisories = append(dr.Advisories, checkAdvisory{
				ID:     m.Advisory.ID,
				CVEs:   m.Advisory.CVEs,
				CVSSv3: m.Advisory.CVSSv3Max,
				Title:  strings.TrimSpace(m.Advisory.Title),
				URL:    m.Advisory.URL,
			})
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

