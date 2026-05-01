package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/compliance"
	"github.com/jmeltz/deadband/pkg/enrichment"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
	"github.com/jmeltz/deadband/pkg/output"
)

type exportReportRequest struct {
	SiteName   string   `json:"site_name"`
	Site       string   `json:"site"`
	Zone       string   `json:"zone"`
	IDs        []string `json:"ids"`
	Compliance []string `json:"compliance"`
}

// handleExportReport produces a self-contained HTML report from the current
// asset inventory, optionally filtered by site/zone/ids. The report is
// streamed as an attachment download.
func (s *Server) handleExportReport(w http.ResponseWriter, r *http.Request) {
	var req exportReportRequest
	// Body is optional — empty body means "all assets, no site name".
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}
	}

	store := asset.LoadOrEmpty(asset.DefaultPath())
	if len(store.Assets) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no assets in inventory"})
		return
	}

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
		targets = store.Filter(asset.FilterOpts{Site: req.Site, Zone: req.Zone})
	}
	if len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "no assets match the filters"})
		return
	}

	devices := make([]inventory.Device, len(targets))
	for i, a := range targets {
		devices[i] = inventory.Device{IP: a.IP, Vendor: a.Vendor, Model: a.Model, Firmware: a.Firmware}
	}

	results := matcher.MatchAll(devices, s.db, matcher.FilterOpts{})
	enrichServerResults(results, s.edb)

	siteName := strings.TrimSpace(req.SiteName)
	if siteName == "" && req.Site != "" {
		if st := s.siteStore.Get(req.Site); st != nil {
			siteName = st.Name
		}
	}

	filename := fmt.Sprintf("deadband-report-%s-%s.html",
		safeFilenameSegment(siteName), time.Now().UTC().Format("2006-01-02"))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	opts := output.WriterOpts{SiteName: siteName}
	if len(req.Compliance) > 0 {
		opts.Compliance = compliance.ForFrameworks(req.Compliance)
	}

	writer, err := output.NewWriterWithOpts(w, "html", opts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	dbCopy := *s.db
	if err := writer.WriteHeader(dbCopy, len(devices)); err != nil {
		return
	}

	summary := output.Summary{}
	for _, res := range results {
		switch strings.ToUpper(res.Status) {
		case "VULNERABLE":
			summary.Vulnerable++
		case "POTENTIAL":
			summary.Potential++
		case "OK":
			summary.OK++
		}
		if err := writer.WriteResult(res); err != nil {
			return
		}
	}
	summary.NoMatch = len(devices) - len(results)
	_ = writer.WriteSummary(summary, len(devices))
	_ = writer.Flush()
}

// enrichServerResults fills KEV/EPSS/RiskScore from the enrichment DB. Mirrors
// the CLI enrichResults helper so reports include risk signals when available.
func enrichServerResults(results []matcher.Result, edb *enrichment.DB) {
	if edb == nil || !edb.Loaded() {
		return
	}
	for i := range results {
		for j := range results[i].Matches {
			m := &results[i].Matches[j]
			ae := edb.EnrichAdvisory(m.Advisory.CVEs, m.Advisory.CVSSv3Max)
			m.KEV = ae.KEV
			m.KEVRansomware = ae.KEVRansomware
			m.EPSSScore = ae.MaxEPSS
			m.EPSSPercentile = ae.MaxEPSSPercent
			m.RiskScore = ae.RiskScore
		}
	}
}

// safeFilenameSegment converts a string into something safe for a downloaded
// filename: lowercased, alphanumerics + hyphens, falls back to "report" for
// empty/unsafe input.
func safeFilenameSegment(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "report"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "report"
	}
	return out
}

