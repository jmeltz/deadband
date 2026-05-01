package output

import (
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/compliance"
	"github.com/jmeltz/deadband/pkg/matcher"
)

type htmlWriter struct {
	w          io.Writer
	db         advisory.Database
	count      int
	results    []matcher.Result
	summary    Summary
	compliance []compliance.ControlMapping
	siteName   string
}

func newHTMLWriter(w io.Writer) *htmlWriter {
	return &htmlWriter{w: w}
}

func (hw *htmlWriter) WriteHeader(db advisory.Database, deviceCount int) error {
	hw.db = db
	hw.count = deviceCount
	return nil
}

func (hw *htmlWriter) WriteResult(r matcher.Result) error {
	hw.results = append(hw.results, r)
	return nil
}

func (hw *htmlWriter) WriteSummary(s Summary, _ int) error {
	hw.summary = s
	return nil
}

func (hw *htmlWriter) Flush() error {
	funcMap := template.FuncMap{
		"lower":      strings.ToLower,
		"joinCVEs":   func(cves []string) string { return strings.Join(cves, ", ") },
		"cvssClass":  cvssClass,
		"riskClass":  riskClass,
		"riskLabel":  riskLabel,
		"pct":        func(n, total int) float64 { if total == 0 { return 0 }; return float64(n) / float64(total) * 100 },
		"barWidth":   func(n, total int) string { if total == 0 { return "0" }; return fmt.Sprintf("%.1f", float64(n)/float64(total)*100) },
		"maxRisk":    htmlMaxRisk,
		"printf":     fmt.Sprintf,
		"epssPercent": func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	data := htmlData{
		CheckedAt:      time.Now().UTC().Format(time.RFC3339),
		DBUpdated:      hw.db.Updated.Format("2006-01-02"),
		DBSource:       hw.db.Source,
		AdvisoryCount:  len(hw.db.Advisories),
		DevicesChecked: hw.count,
		Results:        hw.results,
		Summary:        hw.summary,
		Version:        cli.Version,
		Compliance:     hw.compliance,
		SiteName:       hw.siteName,
	}

	// Compute top risk items
	for _, r := range hw.results {
		for _, m := range r.Matches {
			if m.RiskScore > 0 || m.KEV {
				data.TopRisks = append(data.TopRisks, topRisk{
					IP:        r.Device.IP,
					Model:     r.Device.Model,
					Advisory:  m.Advisory.ID,
					CVSS:      m.Advisory.CVSSv3Max,
					KEV:       m.KEV,
					RiskScore: m.RiskScore,
				})
			}
		}
	}
	// Sort top risks by score desc, take top 5
	for i := 0; i < len(data.TopRisks); i++ {
		for j := i + 1; j < len(data.TopRisks); j++ {
			if data.TopRisks[j].RiskScore > data.TopRisks[i].RiskScore {
				data.TopRisks[i], data.TopRisks[j] = data.TopRisks[j], data.TopRisks[i]
			}
		}
	}
	if len(data.TopRisks) > 5 {
		data.TopRisks = data.TopRisks[:5]
	}

	return tmpl.Execute(hw.w, data)
}

type htmlData struct {
	CheckedAt      string
	DBUpdated      string
	DBSource       string
	AdvisoryCount  int
	DevicesChecked int
	Results        []matcher.Result
	Summary        Summary
	TopRisks       []topRisk
	Version        string
	Compliance     []compliance.ControlMapping
	SiteName       string
}

type topRisk struct {
	IP        string
	Model     string
	Advisory  string
	CVSS      float64
	KEV       bool
	RiskScore float64
}

func cvssClass(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func riskClass(score float64) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

func riskLabel(score float64) string {
	switch {
	case score >= 90:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 30:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "—"
	}
}

func htmlMaxRisk(matches []matcher.Match) float64 {
	max := 0.0
	for _, m := range matches {
		if m.RiskScore > max {
			max = m.RiskScore
		}
	}
	return math.Round(max)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>deadband Vulnerability Report</title>
<style>
:root {
  --bg: #0a0f14;
  --surface: #111820;
  --border: #1e2a36;
  --text: #c8d6e0;
  --muted: #5a7080;
  --teal: #1abc9c;
  --teal-light: #2ee6c0;
  --critical: #e74c3c;
  --high: #e67e22;
  --medium: #f39c12;
  --low: #27ae60;
  --ok: #27ae60;
  --info: #3498db;
  --font-sans: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: "JetBrains Mono", "Fira Code", monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: var(--font-sans); font-size: 14px; line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto; }
h1 { font-size: 1.5rem; color: var(--teal-light); margin-bottom: 0.25rem; }
h2 { font-size: 1.1rem; color: var(--text); margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
h3 { font-size: 0.95rem; color: var(--text); margin-bottom: 0.5rem; }
.site-name { font-size: 1.05rem; color: var(--text); font-family: var(--font-sans); margin-bottom: 0.25rem; letter-spacing: 0.02em; }
.meta { font-size: 0.75rem; color: var(--muted); font-family: var(--font-mono); margin-bottom: 2rem; }
section { background: var(--surface); border: 1px solid var(--border); padding: 1.5rem; margin-bottom: 1.5rem; }
.stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
.stat { text-align: center; padding: 1rem; background: var(--bg); border: 1px solid var(--border); }
.stat .value { font-size: 2rem; font-weight: 700; font-family: var(--font-mono); }
.stat .label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.stat.critical .value { color: var(--critical); }
.stat.high .value { color: var(--high); }
.stat.medium .value { color: var(--medium); }
.stat.ok .value { color: var(--ok); }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { text-align: left; padding: 0.5rem 0.75rem; font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); font-family: var(--font-mono); font-size: 0.8rem; }
tr:hover { background: rgba(26, 188, 156, 0.03); }
.badge { display: inline-block; padding: 0.15rem 0.5rem; font-size: 0.65rem; font-weight: 600; font-family: var(--font-mono); letter-spacing: 0.05em; }
.badge-vulnerable { background: rgba(231,76,60,0.15); color: var(--critical); border: 1px solid rgba(231,76,60,0.3); }
.badge-potential { background: rgba(243,156,18,0.15); color: var(--medium); border: 1px solid rgba(243,156,18,0.3); }
.badge-ok { background: rgba(39,174,96,0.15); color: var(--ok); border: 1px solid rgba(39,174,96,0.3); }
.badge-kev { background: rgba(231,76,60,0.15); color: var(--critical); border: 1px solid rgba(231,76,60,0.3); }
.badge-risk-critical { background: rgba(231,76,60,0.15); color: var(--critical); border: 1px solid rgba(231,76,60,0.3); }
.badge-risk-high { background: rgba(230,126,34,0.15); color: var(--high); border: 1px solid rgba(230,126,34,0.3); }
.badge-risk-medium { background: rgba(243,156,18,0.15); color: var(--medium); border: 1px solid rgba(243,156,18,0.3); }
.badge-risk-low { background: rgba(39,174,96,0.15); color: var(--low); border: 1px solid rgba(39,174,96,0.3); }
.cvss { font-weight: 700; font-family: var(--font-mono); }
.cvss-critical { color: var(--critical); }
.cvss-high { color: var(--high); }
.cvss-medium { color: var(--medium); }
.cvss-low { color: var(--low); }
.bar { display: flex; height: 8px; overflow: hidden; background: var(--bg); margin-bottom: 0.5rem; }
.bar-segment { transition: width 0.3s; }
.bar-critical { background: var(--critical); }
.bar-medium { background: var(--medium); }
.bar-ok { background: var(--ok); }
.bar-none { background: var(--border); }
.device-finding { margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
.device-finding:last-child { border-bottom: none; margin-bottom: 0; }
.advisory-row { padding: 0.75rem; background: var(--bg); border: 1px solid var(--border); margin-bottom: 0.5rem; }
.advisory-header { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.25rem; }
.advisory-title { font-size: 0.8rem; color: var(--text); font-family: var(--font-sans); }
.advisory-cves { font-size: 0.75rem; color: var(--muted); }
.advisory-url { font-size: 0.75rem; color: var(--info); text-decoration: none; }
.advisory-url:hover { color: var(--teal-light); }
.remediation { margin-top: 0.5rem; padding: 0.5rem; background: rgba(26,188,156,0.05); border-left: 2px solid var(--teal); font-size: 0.8rem; font-family: var(--font-sans); }
.top-risks { display: grid; gap: 0.5rem; }
.top-risk-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0.75rem; background: var(--bg); border: 1px solid var(--border); font-size: 0.8rem; }
footer { text-align: center; font-size: 0.7rem; color: var(--muted); padding: 2rem 0 1rem; border-top: 1px solid var(--border); margin-top: 2rem; }
a { color: var(--info); text-decoration: none; }
a:hover { color: var(--teal-light); }
@media print {
  @page { margin: 0.6in; }
  body { background: #fff; color: #111; padding: 0; max-width: none; font-size: 11pt; }
  h1 { color: #0a6051; }
  h2 { color: #111; border-bottom-color: #999; page-break-after: avoid; }
  h3 { color: #111; page-break-after: avoid; }
  section { background: #fff; border-color: #999; padding: 0.75rem 0; margin-bottom: 1rem; page-break-inside: avoid; }
  .meta { color: #555; }
  .site-name { color: #111; }
  .stat { background: #fff; border-color: #999; }
  .stat .value { color: #111; }
  .stat.critical .value { color: #c0392b; }
  .stat.high .value { color: #b35418; }
  .stat.medium .value { color: #b87708; }
  .stat.ok .value { color: #1e7a44; }
  td { border-bottom-color: #ccc; color: #111; }
  th { color: #555; border-bottom-color: #999; }
  tr:hover { background: transparent; }
  .badge { border-color: #999 !important; }
  .badge-vulnerable, .badge-kev, .badge-risk-critical { color: #c0392b; background: #fff; }
  .badge-potential, .badge-risk-medium { color: #b87708; background: #fff; }
  .badge-ok, .badge-risk-low { color: #1e7a44; background: #fff; }
  .badge-risk-high { color: #b35418; background: #fff; }
  .advisory-row { background: #fff; border-color: #999; page-break-inside: avoid; }
  .advisory-title { color: #111; }
  .advisory-cves { color: #555; }
  .advisory-url, a { color: #1456a3; text-decoration: underline; }
  .advisory-url[href]:after { content: " (" attr(href) ")"; font-size: 0.7em; color: #555; }
  .remediation { background: #f5f5f5; border-left-color: #0a6051; }
  .top-risk-item { background: #fff; border-color: #999; page-break-inside: avoid; }
  .device-finding { page-break-inside: avoid; border-bottom-color: #ccc; }
  .bar-critical { background: #c0392b; }
  .bar-medium { background: #b87708; }
  .bar-ok { background: #1e7a44; }
  .bar-none { background: #ddd; }
  footer { border-top-color: #999; color: #555; }
}
</style>
</head>
<body>

<h1>deadband Vulnerability Report</h1>
{{if .SiteName}}<div class="site-name">{{.SiteName}}</div>{{end}}
<div class="meta">Generated: {{.CheckedAt}} &middot; Advisory DB: {{.DBSource}} ({{.AdvisoryCount}} advisories, updated {{.DBUpdated}}) &middot; {{.DevicesChecked}} devices checked</div>

<section>
<h2>Executive Summary</h2>
<div class="stat-grid">
  <div class="stat critical"><div class="value">{{.Summary.Vulnerable}}</div><div class="label">Vulnerable</div></div>
  <div class="stat medium"><div class="value">{{.Summary.Potential}}</div><div class="label">Potential</div></div>
  <div class="stat ok"><div class="value">{{.Summary.OK}}</div><div class="label">OK</div></div>
  <div class="stat"><div class="value">{{.Summary.NoMatch}}</div><div class="label">No Match</div></div>
</div>
<div class="bar">
  <div class="bar-segment bar-critical" style="width:{{barWidth .Summary.Vulnerable .DevicesChecked}}%"></div>
  <div class="bar-segment bar-medium" style="width:{{barWidth .Summary.Potential .DevicesChecked}}%"></div>
  <div class="bar-segment bar-ok" style="width:{{barWidth .Summary.OK .DevicesChecked}}%"></div>
  <div class="bar-segment bar-none" style="width:{{barWidth .Summary.NoMatch .DevicesChecked}}%"></div>
</div>
{{if .TopRisks}}
<h3>Top Risk Items</h3>
<div class="top-risks">
{{range .TopRisks}}
  <div class="top-risk-item">
    <span class="badge badge-risk-{{riskClass .RiskScore}}">{{riskLabel .RiskScore}}</span>
    <span style="font-family:var(--font-mono)">{{.IP}}</span>
    <span style="color:var(--muted)">{{.Model}}</span>
    <span style="font-family:var(--font-mono);color:var(--info)">{{.Advisory}}</span>
    <span class="cvss cvss-{{cvssClass .CVSS}}">CVSS {{printf "%.1f" .CVSS}}</span>
    {{if .KEV}}<span class="badge badge-kev">KEV</span>{{end}}
    <span style="margin-left:auto;font-family:var(--font-mono);color:var(--muted)">Risk: {{printf "%.0f" .RiskScore}}</span>
  </div>
{{end}}
</div>
{{end}}
</section>

<section>
<h2>Device Assessment</h2>
<table>
<thead><tr>
  <th>IP Address</th><th>Model</th><th>Firmware</th><th>Status</th><th>Confidence</th><th>Risk</th><th>Advisories</th>
</tr></thead>
<tbody>
{{range .Results}}
<tr>
  <td>{{.Device.IP}}</td>
  <td>{{.Device.Model}}</td>
  <td>{{.Device.Firmware}}</td>
  <td><span class="badge badge-{{lower .Status}}">{{.Status}}</span></td>
  <td>{{with .Matches}}{{(index . 0).Confidence}}{{end}}</td>
  <td>{{if .Matches}}<span class="badge badge-risk-{{riskClass (maxRisk .Matches)}}">{{printf "%.0f" (maxRisk .Matches)}}</span>{{else}}&mdash;{{end}}</td>
  <td style="font-family:var(--font-mono)">{{len .Matches}}</td>
</tr>
{{end}}
</tbody>
</table>
</section>

<section>
<h2>Vulnerability Details</h2>
{{range .Results}}{{if .Matches}}
<div class="device-finding">
<h3>{{.Device.IP}} &mdash; {{.Device.Model}} (fw {{.Device.Firmware}})</h3>
{{range .Matches}}
<div class="advisory-row">
  <div class="advisory-header">
    <span style="font-family:var(--font-mono);color:var(--info)">{{.Advisory.ID}}</span>
    <span class="cvss cvss-{{cvssClass .Advisory.CVSSv3Max}}">CVSS {{printf "%.1f" .Advisory.CVSSv3Max}}</span>
    {{if .KEV}}<span class="badge badge-kev">KEV{{if .KEVRansomware}} + Ransomware{{end}}</span>{{end}}
    {{if gt .RiskScore 0.0}}<span class="badge badge-risk-{{riskClass .RiskScore}}">Risk: {{printf "%.0f" .RiskScore}}</span>{{end}}
    {{if gt .EPSSScore 0.0}}<span style="font-size:0.75rem;color:var(--muted)">EPSS: {{epssPercent .EPSSScore}}</span>{{end}}
  </div>
  <div class="advisory-title">{{.Advisory.Title}}</div>
  <div class="advisory-cves">{{joinCVEs .Advisory.CVEs}}</div>
  {{if .Advisory.URL}}<a class="advisory-url" href="{{.Advisory.URL}}" target="_blank">{{.Advisory.URL}}</a>{{end}}
  {{if .Advisory.Remediations}}
  <div class="remediation">
    <strong>Remediation:</strong>
    {{range .Advisory.Remediations}}<div>{{.Details}}{{if .URL}} &mdash; <a href="{{.URL}}" target="_blank">{{.URL}}</a>{{end}}</div>{{end}}
  </div>
  {{end}}
</div>
{{end}}
</div>
{{end}}{{end}}
</section>

{{if .Compliance}}
<section>
<h2>Compliance Mapping</h2>
<p style="font-size:0.8rem;color:var(--muted);margin-bottom:1rem">Controls addressed by this assessment across applicable frameworks.</p>
<table>
<thead><tr>
  <th>Framework</th><th>Control ID</th><th>Control Name</th><th>Capability</th><th>Rationale</th>
</tr></thead>
<tbody>
{{range .Compliance}}
<tr>
  <td style="font-family:var(--font-sans)">{{.Framework}}</td>
  <td>{{.ControlID}}</td>
  <td style="font-family:var(--font-sans)">{{.ControlName}}</td>
  <td><span class="badge" style="background:rgba(26,188,156,0.15);color:var(--teal);border:1px solid rgba(26,188,156,0.3)">{{.Capability}}</span></td>
  <td style="font-family:var(--font-sans);font-size:0.75rem;color:var(--muted)">{{.Rationale}}</td>
</tr>
{{end}}
</tbody>
</table>
</section>
{{end}}

<footer>
Generated by deadband v{{.Version}} &middot; Read-only ICS firmware vulnerability gap detector &middot; No write operations performed on OT devices
</footer>

</body>
</html>`
