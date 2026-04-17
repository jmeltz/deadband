package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/posture"
	"github.com/jmeltz/deadband/pkg/site"
)

// WriteAssetsCSV writes assets as CSV.
func WriteAssetsCSV(w io.Writer, assets []asset.Asset) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"ID", "IP", "Vendor", "Model", "Firmware",
		"Name", "Site", "Zone", "Criticality", "Status",
		"Serial", "MAC", "Hostname", "Protocol", "Port",
		"Tags", "First Seen", "Last Seen", "Source",
		"Vuln Status", "Risk Score", "CVE Count", "KEV Count",
		"Advisories",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, a := range assets {
		vulnStatus := ""
		riskScore := ""
		cveCount := ""
		kevCount := ""
		advisories := ""

		if a.VulnState != nil {
			vulnStatus = a.VulnState.Status
			riskScore = strconv.FormatFloat(a.VulnState.RiskScore, 'f', 1, 64)
			cveCount = strconv.Itoa(a.VulnState.CVECount)
			kevCount = strconv.Itoa(a.VulnState.KEVCount)
			ids := make([]string, len(a.VulnState.Advisories))
			for i, adv := range a.VulnState.Advisories {
				ids[i] = adv.ID
			}
			advisories = strings.Join(ids, "; ")
		}

		row := []string{
			a.ID, a.IP, a.Vendor, a.Model, a.Firmware,
			a.Name, a.Site, a.Zone, a.Criticality, a.Status,
			a.Serial, a.MAC, a.Hostname, a.Protocol, intStr(a.Port),
			strings.Join(a.Tags, ", "),
			fmtTime(a.FirstSeen), fmtTime(a.LastSeen), a.Source,
			vulnStatus, riskScore, cveCount, kevCount,
			advisories,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// WriteAssetsJSON writes assets as JSON.
func WriteAssetsJSON(w io.Writer, assets []asset.Asset) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(assets)
}

func intStr(v int) string {
	if v == 0 {
		return ""
	}
	return strconv.Itoa(v)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// WriteDBD writes assets in .dbd format (CSV with site metadata header comments).
func WriteDBD(w io.Writer, assets []asset.Asset, sites []site.Site, postureReports []posture.PostureReport) error {
	// Write header comments
	fmt.Fprintln(w, "# deadband export v2")
	fmt.Fprintf(w, "# exported: %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, s := range sites {
		// Format: # site: Name|CIDRs|Description|Location|Contact
		cidrs := strings.Join(s.CIDRs, ",")
		fmt.Fprintf(w, "# site: %s|%s|%s|%s|%s\n", s.Name, cidrs, s.Description, s.Location, s.Contact)
	}
	for _, r := range postureReports {
		data, err := json.Marshal(r)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "# posture: %s\n", data)
	}

	// Write CSV data (same columns as WriteAssetsCSV)
	return WriteAssetsCSV(w, assets)
}

// DBDData holds all data parsed from a .dbd file.
type DBDData struct {
	Assets         []asset.Asset
	Sites          []site.Site
	PostureReports []posture.PostureReport
}

// ReadDBD parses a .dbd file (CSV with site/posture metadata header comments).
func ReadDBD(r io.Reader) ([]asset.Asset, []site.Site, error) {
	d, err := ReadDBDFull(r)
	if err != nil {
		return nil, nil, err
	}
	return d.Assets, d.Sites, nil
}

// ReadDBDFull parses a .dbd file returning all sections including posture.
func ReadDBDFull(r io.Reader) (*DBDData, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // allow large posture JSON lines
	var sites []site.Site
	var postureReports []posture.PostureReport
	var csvLines []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# site: ") {
			s := parseSiteComment(line)
			if s.Name != "" {
				sites = append(sites, s)
			}
		} else if strings.HasPrefix(line, "# posture: ") {
			data := strings.TrimPrefix(line, "# posture: ")
			var rpt posture.PostureReport
			if err := json.Unmarshal([]byte(data), &rpt); err == nil {
				postureReports = append(postureReports, rpt)
			}
		} else if strings.HasPrefix(line, "#") {
			continue // skip other comments
		} else {
			csvLines = append(csvLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading .dbd: %w", err)
	}

	d := &DBDData{
		Sites:          sites,
		PostureReports: postureReports,
	}

	if len(csvLines) == 0 {
		return d, nil
	}

	// Parse CSV from remaining lines
	csvReader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing CSV: %w", err)
	}

	if len(records) < 2 {
		return d, nil // header only, no data rows
	}

	// Build column index from header row
	header := records[0]
	colIdx := make(map[string]int, len(header))
	for i, h := range header {
		colIdx[h] = i
	}

	assets := make([]asset.Asset, 0, len(records)-1)
	for _, row := range records[1:] {
		a := asset.Asset{
			ID:          colVal(row, colIdx, "ID"),
			IP:          colVal(row, colIdx, "IP"),
			Vendor:      colVal(row, colIdx, "Vendor"),
			Model:       colVal(row, colIdx, "Model"),
			Firmware:    colVal(row, colIdx, "Firmware"),
			Name:        colVal(row, colIdx, "Name"),
			Site:        colVal(row, colIdx, "Site"),
			Zone:        colVal(row, colIdx, "Zone"),
			Criticality: colVal(row, colIdx, "Criticality"),
			Status:      colVal(row, colIdx, "Status"),
			Serial:      colVal(row, colIdx, "Serial"),
			MAC:         colVal(row, colIdx, "MAC"),
			Hostname:    colVal(row, colIdx, "Hostname"),
			Protocol:    colVal(row, colIdx, "Protocol"),
			Source:      colVal(row, colIdx, "Source"),
		}

		if v := colVal(row, colIdx, "Port"); v != "" {
			a.Port, _ = strconv.Atoi(v)
		}
		if v := colVal(row, colIdx, "Tags"); v != "" {
			a.Tags = strings.Split(v, ", ")
		} else {
			a.Tags = []string{}
		}
		if v := colVal(row, colIdx, "First Seen"); v != "" {
			a.FirstSeen, _ = time.Parse(time.RFC3339, v)
		}
		if v := colVal(row, colIdx, "Last Seen"); v != "" {
			a.LastSeen, _ = time.Parse(time.RFC3339, v)
		}

		// Reconstruct vuln state if present
		vulnStatus := colVal(row, colIdx, "Vuln Status")
		if vulnStatus != "" {
			vs := &asset.VulnState{Status: vulnStatus}
			if v := colVal(row, colIdx, "Risk Score"); v != "" {
				vs.RiskScore, _ = strconv.ParseFloat(v, 64)
			}
			if v := colVal(row, colIdx, "CVE Count"); v != "" {
				vs.CVECount, _ = strconv.Atoi(v)
			}
			if v := colVal(row, colIdx, "KEV Count"); v != "" {
				vs.KEVCount, _ = strconv.Atoi(v)
			}
			a.VulnState = vs
		}

		assets = append(assets, a)
	}

	d.Assets = assets
	return d, nil
}

// parseSiteComment parses "# site: Name|CIDRs|Description|Location|Contact"
func parseSiteComment(line string) site.Site {
	data := strings.TrimPrefix(line, "# site: ")
	parts := strings.SplitN(data, "|", 5)
	s := site.Site{
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if len(parts) >= 1 {
		s.Name = parts[0]
	}
	if len(parts) >= 2 && parts[1] != "" {
		s.CIDRs = strings.Split(parts[1], ",")
	}
	if len(parts) >= 3 {
		s.Description = parts[2]
	}
	if len(parts) >= 4 {
		s.Location = parts[3]
	}
	if len(parts) >= 5 {
		s.Contact = parts[4]
	}
	return s
}

// colVal returns the value at the given column name, or "" if not found.
func colVal(row []string, colIdx map[string]int, col string) string {
	i, ok := colIdx[col]
	if !ok || i >= len(row) {
		return ""
	}
	return row[i]
}
