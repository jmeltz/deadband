package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
)

const (
	defaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdHTTPTimeout    = 15 * time.Second
	nvdMaxBodySize    = 8 * 1024 * 1024 // 8 MiB
)

// NVDTarget specifies a targeted OEM keyword search against the NVD 2.0 CVE API
// for intralogistics, regulated cold-chain EMS, and HVAC OEMs without public CSAF feeds.
type NVDTarget struct {
	Vendor        string
	Keyword       string
	VendorTokens  []string
	FallbackModel string
}

// DefaultNVDTargets covers ASRS/WCS, cold-chain EMS, and BMS OEMs absent from CISA/ROLIE CSAF feeds.
var DefaultNVDTargets = []NVDTarget{
	{Vendor: "KNAPP", Keyword: "KNAPP KiSoft", VendorTokens: []string{"knapp"}, FallbackModel: "KiSoft"},
	{Vendor: "Dematic", Keyword: "Dematic", VendorTokens: []string{"dematic"}, FallbackModel: "Dematic WCS"},
	{Vendor: "Swisslog", Keyword: "Swisslog", VendorTokens: []string{"swisslog"}, FallbackModel: "SynQ / Translogic"},
	{Vendor: "Vaisala", Keyword: "Vaisala viewLinc", VendorTokens: []string{"vaisala"}, FallbackModel: "viewLinc"},
	{Vendor: "Testo", Keyword: "Testo Saveris", VendorTokens: []string{"testo"}, FallbackModel: "Saveris"},
	{Vendor: "ELPRO", Keyword: "ELPRO LIBERO", VendorTokens: []string{"elpro"}, FallbackModel: "elproMONITOR / LIBERO"},
	{Vendor: "Sensaphone", Keyword: "Sensaphone", VendorTokens: []string{"sensaphone"}, FallbackModel: "Web600"},
	{Vendor: "Distech Controls", Keyword: "Distech Controls", VendorTokens: []string{"distech"}, FallbackModel: "ECLYPSE / EC-BOS"},
	{Vendor: "Belimo", Keyword: "Belimo", VendorTokens: []string{"belimo"}, FallbackModel: "Belimo Actuator / Energy Valve"},
}

type nvdResponse struct {
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	Descriptions   []nvdLangString `json:"descriptions"`
	Metrics        nvdMetrics      `json:"metrics"`
	Weaknesses     []nvdWeakness   `json:"weaknesses"`
	Configurations []nvdConfig     `json:"configurations"`
}

type nvdLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV40 []nvdCVSSMetric `json:"cvssMetricV40"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore float64 `json:"baseScore"`
}

type nvdWeakness struct {
	Description []nvdLangString `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

func fetchNVDAdvisories(client *http.Client, since time.Time, progress func(string)) []advisory.Advisory {
	apiKey := strings.TrimSpace(os.Getenv("DEADBAND_NVD_API_KEY"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}
	delay := 700 * time.Millisecond
	if apiKey != "" {
		delay = 120 * time.Millisecond
	}
	return fetchNVDAdvisoriesWithConfig(client, defaultNVDBaseURL, DefaultNVDTargets, apiKey, delay, since, progress)
}

func fetchNVDAdvisoriesWithConfig(
	client *http.Client,
	baseURL string,
	targets []NVDTarget,
	apiKey string,
	requestDelay time.Duration,
	since time.Time,
	progress func(string),
) []advisory.Advisory {
	if len(targets) == 0 || baseURL == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: nvdHTTPTimeout}
	}

	byID := make(map[string]advisory.Advisory)
	var orderedIDs []string

	for idx, target := range targets {
		if idx > 0 && requestDelay > 0 {
			time.Sleep(requestDelay)
		}
		advs, err := queryNVDTarget(client, baseURL, target, apiKey, since)
		if err != nil {
			if progress != nil {
				progress(fmt.Sprintf("Warning: NVD lookup for %s unavailable: %v", target.Vendor, err))
			}
			continue
		}
		for _, a := range advs {
			if _, exists := byID[a.ID]; !exists {
				orderedIDs = append(orderedIDs, a.ID)
				byID[a.ID] = a
			}
		}
	}

	out := make([]advisory.Advisory, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		out = append(out, byID[id])
	}
	if progress != nil && len(out) > 0 {
		progress(fmt.Sprintf("Ingested %d targeted OEM CVE advisories from NVD", len(out)))
	}
	return out
}

func queryNVDTarget(client *http.Client, baseURL string, target NVDTarget, apiKey string, since time.Time) ([]advisory.Advisory, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("keywordSearch", target.Keyword)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Deadband-OT-Updater/1.0")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var parsed nvdResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, nvdMaxBodySize)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding NVD response: %w", err)
	}

	var out []advisory.Advisory
	for _, w := range parsed.Vulnerabilities {
		adv, ok := nvdCVEToAdvisory(w.CVE, target, since)
		if ok {
			out = append(out, adv)
		}
	}
	return out, nil
}

func nvdCVEToAdvisory(cve nvdCVE, target NVDTarget, since time.Time) (advisory.Advisory, bool) {
	if cve.ID == "" {
		return advisory.Advisory{}, false
	}

	if !since.IsZero() && !nvdEntryAfterOrEqual(cve, since) {
		return advisory.Advisory{}, false
	}

	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = strings.TrimSpace(d.Value)
			break
		}
	}
	if desc == "" && len(cve.Descriptions) > 0 {
		desc = strings.TrimSpace(cve.Descriptions[0].Value)
	}

	var (
		products    []string
		prodSeen    = make(map[string]bool)
		versions    []string
		verSeen     = make(map[string]bool)
		matchedVendor bool
	)

	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, cm := range node.CPEMatch {
				if !cm.Vulnerable {
					continue
				}
				cpeVendor, cpeProduct, cpeVer, ok := parseCPE23(cm.Criteria)
				if !ok {
					continue
				}
				if !matchesTargetVendorToken(cpeVendor, target.VendorTokens) {
					continue
				}
				matchedVendor = true
				humanProd := humanizeCPEIdentifier(cpeProduct)
				if humanProd != "" && !prodSeen[strings.ToLower(humanProd)] {
					prodSeen[strings.ToLower(humanProd)] = true
					products = append(products, humanProd)
				}
				verExpr := buildCPERangeExpression(cm, cpeVer)
				if verExpr != "" && !verSeen[verExpr] {
					verSeen[verExpr] = true
					versions = append(versions, verExpr)
				}
			}
		}
	}

	// If NVD has not yet attached CPE configurations (awaiting analysis), accept only
	// when the English CVE description explicitly names the target keyword phrase.
	if !matchedVendor {
		hasAnyCPE := false
		for _, cfg := range cve.Configurations {
			if len(cfg.Nodes) > 0 {
				hasAnyCPE = true
				break
			}
		}
		if hasAnyCPE || !strings.Contains(strings.ToLower(desc), strings.ToLower(target.Keyword)) {
			return advisory.Advisory{}, false
		}
		if target.FallbackModel != "" {
			products = append(products, target.FallbackModel)
		}
	}

	maxCVSS := 0.0
	for _, m := range cve.Metrics.CVSSMetricV31 {
		maxCVSS = math.Max(maxCVSS, m.CVSSData.BaseScore)
	}
	for _, m := range cve.Metrics.CVSSMetricV30 {
		maxCVSS = math.Max(maxCVSS, m.CVSSData.BaseScore)
	}
	if maxCVSS == 0 {
		for _, m := range cve.Metrics.CVSSMetricV40 {
			maxCVSS = math.Max(maxCVSS, m.CVSSData.BaseScore)
		}
	}

	cweSeen := make(map[string]bool)
	var weaknesses []advisory.Weakness
	for _, w := range cve.Weaknesses {
		for _, wd := range w.Description {
			val := strings.TrimSpace(wd.Value)
			if strings.HasPrefix(val, "CWE-") && val != "CWE-noinfo" && val != "CWE-Other" && !cweSeen[val] {
				cweSeen[val] = true
				weaknesses = append(weaknesses, advisory.Weakness{ID: val})
			}
		}
	}

	published := cve.Published
	if len(published) > 10 {
		published = published[:10]
	}

	title := fmt.Sprintf("%s %s (%s)", target.Vendor, strings.Join(products, ", "), cve.ID)
	if len(products) == 0 {
		title = fmt.Sprintf("%s (%s)", target.Vendor, cve.ID)
	}

	return advisory.Advisory{
		ID:               cve.ID,
		Title:            title,
		Vendor:           target.Vendor,
		Products:         products,
		AffectedVersions: versions,
		CVSSv3Max:        maxCVSS,
		CVEs:             []string{cve.ID},
		URL:              "https://nvd.nist.gov/vuln/detail/" + cve.ID,
		Published:        published,
		Summary:          desc,
		Weaknesses:       weaknesses,
	}, true
}

func nvdEntryAfterOrEqual(cve nvdCVE, since time.Time) bool {
	for _, raw := range []string{cve.LastModified, cve.Published} {
		raw = strings.TrimSpace(raw)
		if len(raw) >= 10 {
			if ts, err := time.Parse("2006-01-02", raw[:10]); err == nil {
				return !ts.Before(since)
			}
		}
	}
	return true
}

func parseCPE23(criteria string) (vendor, product, version string, ok bool) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", "", "", false
	}
	return strings.ToLower(parts[3]), parts[4], parts[5], true
}

func matchesTargetVendorToken(cpeVendor string, tokens []string) bool {
	for _, tok := range tokens {
		if strings.Contains(cpeVendor, strings.ToLower(tok)) {
			return true
		}
	}
	return false
}

func humanizeCPEIdentifier(s string) string {
	s = strings.ReplaceAll(s, `\:`, ":")
	s = strings.ReplaceAll(s, "_", " ")
	return strings.TrimSpace(s)
}

func buildCPERangeExpression(cm nvdCPEMatch, cpeVer string) string {
	var startPart, endPart string
	if cm.VersionStartIncluding != "" {
		startPart = ">=" + cm.VersionStartIncluding
	} else if cm.VersionStartExcluding != "" {
		startPart = ">" + cm.VersionStartExcluding
	}
	if cm.VersionEndIncluding != "" {
		endPart = "<=" + cm.VersionEndIncluding
	} else if cm.VersionEndExcluding != "" {
		endPart = "<" + cm.VersionEndExcluding
	}

	switch {
	case startPart != "" && endPart != "":
		return startPart + "|" + endPart
	case startPart != "":
		return startPart
	case endPart != "":
		return endPart
	case cpeVer != "" && cpeVer != "*" && cpeVer != "-":
		return cpeVer
	case cpeVer == "*":
		return "*"
	default:
		return ""
	}
}
