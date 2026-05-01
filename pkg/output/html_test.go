package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

// TestHTMLReportIsSelfContained asserts the rendered HTML report has zero
// external resource references. The report ships to clients who may open it
// from disk on an air-gapped machine — any CDN, font URL, or remote stylesheet
// would silently break the deliverable.
func TestHTMLReportIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriterWithOpts(&buf, "html", WriterOpts{SiteName: "Test Site"})
	if err != nil {
		t.Fatalf("NewWriterWithOpts: %v", err)
	}

	db := advisory.Database{
		Updated: time.Now().UTC(),
		Source:  "test",
		Advisories: []advisory.Advisory{
			{ID: "ICSA-99-001", Title: "Test Advisory", CVSSv3Max: 7.5, CVEs: []string{"CVE-2099-0001"}},
		},
	}
	if err := w.WriteHeader(db, 1); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	res := matcher.Result{
		Device: inventory.Device{IP: "10.0.0.1", Vendor: "Test", Model: "TestPLC", Firmware: "1.0"},
		Status: "VULNERABLE",
		Matches: []matcher.Match{
			{Advisory: db.Advisories[0], Confidence: matcher.ConfidenceHigh},
		},
	}
	if err := w.WriteResult(res); err != nil {
		t.Fatalf("WriteResult: %v", err)
	}
	if err := w.WriteSummary(Summary{Vulnerable: 1}, 1); err != nil {
		t.Fatalf("WriteSummary: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	out := buf.String()

	// External-reference probes. Each must NOT appear in the rendered output.
	// The advisory CSS variables `var(--font-sans)` and `var(--font-mono)` reference
	// "Inter" / "JetBrains Mono" by name only — no fetch, system fallback applies —
	// so they're allowed.
	bannedSubstrings := []string{
		"<link rel=\"stylesheet\"",
		"<link rel='stylesheet'",
		"<script src=\"http",
		"<script src='http",
		"@import url",
		"https://fonts.googleapis",
		"https://cdn.",
		"https://cdnjs.",
	}
	for _, ban := range bannedSubstrings {
		if strings.Contains(out, ban) {
			t.Errorf("HTML report contains banned external reference: %q", ban)
		}
	}

	// Site name must render in the cover header when set.
	if !strings.Contains(out, "Test Site") {
		t.Error("rendered report missing SiteName cover line")
	}

	// Print stylesheet must be present so client print/PDF works.
	if !strings.Contains(out, "@media print") {
		t.Error("rendered report missing @media print block")
	}
}
