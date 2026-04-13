package output

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/compliance"
	"github.com/jmeltz/deadband/pkg/matcher"
)

type jsonOutput struct {
	CheckedAt      string                       `json:"checked_at"`
	DBUpdated      string                       `json:"db_updated"`
	DevicesChecked int                          `json:"devices_checked"`
	Results        []jsonDeviceResult           `json:"results"`
	Summary        *jsonSummary                 `json:"summary,omitempty"`
	Compliance     []compliance.ControlMapping  `json:"compliance,omitempty"`
}

type jsonDeviceResult struct {
	IP         string         `json:"ip"`
	DeviceName string         `json:"device_name"`
	Firmware   string         `json:"firmware"`
	Status     string         `json:"status"`
	Confidence string         `json:"confidence"`
	Advisories []jsonAdvisory `json:"advisories,omitempty"`
}

type jsonAdvisory struct {
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

type jsonSummary struct {
	Vulnerable int `json:"vulnerable"`
	Potential  int `json:"potential"`
	OK         int `json:"ok"`
	NoMatch    int `json:"no_match"`
}

type jsonWriter struct {
	w          io.Writer
	output     jsonOutput
	compliance []compliance.ControlMapping
}

func newJSONWriter(w io.Writer) *jsonWriter {
	return &jsonWriter{
		w: w,
		output: jsonOutput{
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
			Results:   []jsonDeviceResult{},
		},
	}
}

func (jw *jsonWriter) WriteHeader(db advisory.Database, deviceCount int) error {
	jw.output.DBUpdated = db.Updated.Format(time.RFC3339)
	jw.output.DevicesChecked = deviceCount
	return nil
}

func (jw *jsonWriter) WriteResult(r matcher.Result) error {
	conf := ""
	if len(r.Matches) > 0 {
		conf = string(r.Matches[0].Confidence)
	}

	dr := jsonDeviceResult{
		IP:         r.Device.IP,
		DeviceName: r.Device.Model,
		Firmware:   r.Device.Firmware,
		Status:     r.Status,
		Confidence: conf,
	}

	for _, m := range r.Matches {
		dr.Advisories = append(dr.Advisories, jsonAdvisory{
			ID:             m.Advisory.ID,
			CVEs:           m.Advisory.CVEs,
			CVSSv3:         m.Advisory.CVSSv3Max,
			Title:          strings.TrimSpace(m.Advisory.Title),
			URL:            m.Advisory.URL,
			KEV:            m.KEV,
			KEVRansomware:  m.KEVRansomware,
			EPSSScore:      m.EPSSScore,
			EPSSPercentile: m.EPSSPercentile,
			RiskScore:      m.RiskScore,
		})
	}

	jw.output.Results = append(jw.output.Results, dr)
	return nil
}

func (jw *jsonWriter) WriteSummary(s Summary, _ int) error {
	jw.output.Summary = &jsonSummary{
		Vulnerable: s.Vulnerable,
		Potential:  s.Potential,
		OK:         s.OK,
		NoMatch:    s.NoMatch,
	}
	return nil
}

func (jw *jsonWriter) Flush() error {
	if len(jw.compliance) > 0 {
		jw.output.Compliance = jw.compliance
	}
	enc := json.NewEncoder(jw.w)
	enc.SetIndent("", "  ")
	return enc.Encode(jw.output)
}
