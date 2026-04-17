package asset

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// Asset represents a managed ICS asset with metadata for tracking and classification.
type Asset struct {
	ID          string    `json:"id"`
	IP          string    `json:"ip"`
	Vendor      string    `json:"vendor"`
	Model       string    `json:"model"`
	Firmware    string    `json:"firmware"`
	Name        string    `json:"name"`
	Site        string    `json:"site"`
	Zone        string    `json:"zone"`
	Criticality string    `json:"criticality"` // critical, high, medium, low
	Tags        []string  `json:"tags"`
	Notes       string    `json:"notes"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"` // discovery, upload, manual
	// Hardware identity (populated by protocol scanners)
	Serial   string `json:"serial,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OrderNum string `json:"order_number,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Port     int               `json:"port,omitempty"`
	Slot     int               `json:"slot,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
	// Lifecycle
	Status string `json:"status"` // active, retired, quarantined, unknown
	// Vulnerability state (populated by asset checks)
	VulnState *VulnState `json:"vuln_state,omitempty"`
}

// Store holds the persisted asset inventory.
type Store struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Assets    []Asset   `json:"assets"`
}

// DefaultPath returns the default asset store location (~/.deadband/assets.json).
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "assets.json"
	}
	return filepath.Join(home, ".deadband", "assets.json")
}

// Load reads the asset store from disk.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading assets: %w", err)
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing assets: %w", err)
	}
	return &s, nil
}

// LoadOrEmpty loads the store from disk, returning an empty store if the file doesn't exist.
func LoadOrEmpty(path string) *Store {
	s, err := Load(path)
	if err != nil {
		return &Store{Version: 1}
	}
	return s
}

// Save writes the asset store to disk.
func Save(path string, s *Store) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating asset directory: %w", err)
	}
	s.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding assets: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// ImportResult summarizes what happened during an import.
type ImportResult struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Total   int `json:"total"`
}

// Import merges devices into the store. Existing assets are matched first by
// IP+Vendor+Model, then by Serial number (handles DHCP re-addressing).
// New devices are added as new assets.
func (s *Store) Import(devices []inventory.Device, source string) ImportResult {
	now := time.Now().UTC()
	result := ImportResult{}

	// Index existing assets by dedup key and serial
	idx := make(map[string]int, len(s.Assets))
	serialIdx := make(map[string]int, len(s.Assets))
	for i, a := range s.Assets {
		idx[dedupKey(a.IP, a.Vendor, a.Model)] = i
		if a.Serial != "" {
			serialIdx[strings.ToLower(a.Serial)] = i
		}
	}

	for _, d := range devices {
		key := dedupKey(d.IP, d.Vendor, d.Model)
		i, ok := idx[key]
		// Fallback: match by serial (handles DHCP re-addressing)
		if !ok && d.Serial != "" {
			if si, sok := serialIdx[strings.ToLower(d.Serial)]; sok {
				i, ok = si, true
				// Track IP change
				if s.Assets[i].IP != d.IP {
					if s.Assets[i].Extra == nil {
						s.Assets[i].Extra = map[string]string{}
					}
					s.Assets[i].Extra["previous_ip"] = s.Assets[i].IP
					s.Assets[i].IP = d.IP
					// Update primary index
					delete(idx, dedupKey(s.Assets[i].IP, s.Assets[i].Vendor, s.Assets[i].Model))
					idx[key] = i
				}
			}
		}
		if ok {
			// Update existing — refresh firmware, hardware fields, and last seen
			s.Assets[i].Firmware = d.Firmware
			s.Assets[i].LastSeen = now
			if d.Serial != "" {
				s.Assets[i].Serial = d.Serial
			}
			if d.MAC != "" {
				s.Assets[i].MAC = d.MAC
			}
			if d.Hostname != "" {
				s.Assets[i].Hostname = d.Hostname
			}
			if d.OrderNum != "" {
				s.Assets[i].OrderNum = d.OrderNum
			}
			if d.Protocol != "" {
				s.Assets[i].Protocol = d.Protocol
			}
			if d.Port != 0 {
				s.Assets[i].Port = d.Port
			}
			if d.Slot != 0 {
				s.Assets[i].Slot = d.Slot
			}
			result.Updated++
		} else {
			// New asset
			a := Asset{
				ID:        newID(),
				IP:        d.IP,
				Vendor:    d.Vendor,
				Model:     d.Model,
				Firmware:  d.Firmware,
				Serial:    d.Serial,
				MAC:       d.MAC,
				Hostname:  d.Hostname,
				OrderNum:  d.OrderNum,
				Protocol:  d.Protocol,
				Port:      d.Port,
				Slot:      d.Slot,
				FirstSeen: now,
				LastSeen:  now,
				Source:    source,
				Status:    "active",
				Tags:      []string{},
			}
			idx[key] = len(s.Assets)
			s.Assets = append(s.Assets, a)
			result.Added++
		}
	}

	result.Total = len(s.Assets)
	return result
}

// Get returns the asset with the given ID, or nil if not found.
func (s *Store) Get(id string) *Asset {
	for i := range s.Assets {
		if s.Assets[i].ID == id {
			return &s.Assets[i]
		}
	}
	return nil
}

// Update applies changes to an existing asset. Only non-zero fields in the
// patch are applied. Returns false if the asset was not found.
func (s *Store) Update(id string, patch AssetPatch) bool {
	a := s.Get(id)
	if a == nil {
		return false
	}
	if patch.Name != nil {
		a.Name = *patch.Name
	}
	if patch.Site != nil {
		a.Site = *patch.Site
	}
	if patch.Zone != nil {
		a.Zone = *patch.Zone
	}
	if patch.Criticality != nil {
		a.Criticality = *patch.Criticality
	}
	if patch.Tags != nil {
		a.Tags = patch.Tags
	}
	if patch.Notes != nil {
		a.Notes = *patch.Notes
	}
	if patch.Status != nil {
		a.Status = *patch.Status
	}
	if patch.Hostname != nil {
		a.Hostname = *patch.Hostname
	}
	return true
}

// Delete removes an asset by ID. Returns false if not found.
func (s *Store) Delete(id string) bool {
	for i, a := range s.Assets {
		if a.ID == id {
			s.Assets = append(s.Assets[:i], s.Assets[i+1:]...)
			return true
		}
	}
	return false
}

// AssetPatch represents a partial update to an asset.
type AssetPatch struct {
	Name        *string  `json:"name,omitempty"`
	Site        *string  `json:"site,omitempty"`
	Zone        *string  `json:"zone,omitempty"`
	Criticality *string  `json:"criticality,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Notes       *string  `json:"notes,omitempty"`
	Status      *string  `json:"status,omitempty"`
	Hostname    *string  `json:"hostname,omitempty"`
}

// FilterOpts controls asset list filtering and sorting.
type FilterOpts struct {
	Vendor      string
	Site        string
	Zone        string
	Criticality string
	Tag         string
	Search      string
	SortField   string // ip, vendor, model, firmware, name, site, zone, criticality, first_seen, last_seen
	SortAsc     bool
	// Phase 1 additions
	Status     string // active, retired, quarantined
	VulnStatus string // VULNERABLE, POTENTIAL, OK, UNCHECKED
	CVE        string // filter assets affected by a specific CVE
}

// Filter returns assets matching the given options.
func (s *Store) Filter(opts FilterOpts) []Asset {
	var out []Asset
	for _, a := range s.Assets {
		if opts.Vendor != "" && !strings.Contains(strings.ToLower(a.Vendor), strings.ToLower(opts.Vendor)) {
			continue
		}
		if opts.Site != "" && !strings.EqualFold(a.Site, opts.Site) {
			continue
		}
		if opts.Zone != "" && !strings.EqualFold(a.Zone, opts.Zone) {
			continue
		}
		if opts.Criticality != "" && !strings.EqualFold(a.Criticality, opts.Criticality) {
			continue
		}
		if opts.Tag != "" && !hasTag(a.Tags, opts.Tag) {
			continue
		}
		if opts.Status != "" && !strings.EqualFold(a.Status, opts.Status) {
			continue
		}
		if opts.VulnStatus != "" {
			if a.VulnState == nil && !strings.EqualFold(opts.VulnStatus, "UNCHECKED") {
				continue
			}
			if a.VulnState != nil && !strings.EqualFold(a.VulnState.Status, opts.VulnStatus) {
				continue
			}
		}
		if opts.CVE != "" && !assetHasCVE(a, opts.CVE) {
			continue
		}
		if opts.Search != "" {
			q := strings.ToLower(opts.Search)
			if !strings.Contains(strings.ToLower(a.IP), q) &&
				!strings.Contains(strings.ToLower(a.Vendor), q) &&
				!strings.Contains(strings.ToLower(a.Model), q) &&
				!strings.Contains(strings.ToLower(a.Name), q) &&
				!strings.Contains(strings.ToLower(a.Notes), q) &&
				!strings.Contains(strings.ToLower(a.Serial), q) &&
				!strings.Contains(strings.ToLower(a.Hostname), q) &&
				!anyTagContains(a.Tags, q) {
				continue
			}
		}
		out = append(out, a)
	}

	sortAssets(out, opts.SortField, opts.SortAsc)
	return out
}

// DistinctValues returns distinct non-empty values for a metadata field across all assets.
func (s *Store) DistinctValues() (sites, zones, tags []string) {
	siteSet := map[string]bool{}
	zoneSet := map[string]bool{}
	tagSet := map[string]bool{}
	for _, a := range s.Assets {
		if a.Site != "" {
			siteSet[a.Site] = true
		}
		if a.Zone != "" {
			zoneSet[a.Zone] = true
		}
		for _, t := range a.Tags {
			tagSet[t] = true
		}
	}
	for v := range siteSet {
		sites = append(sites, v)
	}
	for v := range zoneSet {
		zones = append(zones, v)
	}
	for v := range tagSet {
		tags = append(tags, v)
	}
	sort.Strings(sites)
	sort.Strings(zones)
	sort.Strings(tags)
	return
}

func sortAssets(assets []Asset, field string, asc bool) {
	sort.Slice(assets, func(i, j int) bool {
		var less bool
		switch field {
		case "ip":
			less = assets[i].IP < assets[j].IP
		case "vendor":
			less = strings.ToLower(assets[i].Vendor) < strings.ToLower(assets[j].Vendor)
		case "model":
			less = strings.ToLower(assets[i].Model) < strings.ToLower(assets[j].Model)
		case "firmware":
			less = assets[i].Firmware < assets[j].Firmware
		case "name":
			less = strings.ToLower(assets[i].Name) < strings.ToLower(assets[j].Name)
		case "site":
			less = strings.ToLower(assets[i].Site) < strings.ToLower(assets[j].Site)
		case "zone":
			less = strings.ToLower(assets[i].Zone) < strings.ToLower(assets[j].Zone)
		case "criticality":
			less = critOrd(assets[i].Criticality) < critOrd(assets[j].Criticality)
		case "last_seen":
			less = assets[i].LastSeen.Before(assets[j].LastSeen)
		case "first_seen":
			less = assets[i].FirstSeen.Before(assets[j].FirstSeen)
		default:
			less = assets[i].LastSeen.After(assets[j].LastSeen) // newest first by default
		}
		if asc {
			return less
		}
		return !less
	})
}

func critOrd(c string) int {
	switch strings.ToLower(c) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func hasTag(tags []string, tag string) bool {
	t := strings.ToLower(tag)
	for _, tt := range tags {
		if strings.EqualFold(tt, t) {
			return true
		}
	}
	return false
}

func anyTagContains(tags []string, q string) bool {
	for _, t := range tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// Summary computes aggregate statistics across all assets.
type Summary struct {
	TotalAssets    int                       `json:"total_assets"`
	ByStatus       map[string]int            `json:"by_status"`
	ByCriticality  map[string]int            `json:"by_criticality"`
	ByVulnStatus   map[string]int            `json:"by_vuln_status"`
	BySite         map[string]SiteSummary    `json:"by_site"`
	TopCVEs        []CVECount                `json:"top_cves"`
	KEVAffected    int                       `json:"kev_affected_assets"`
	StaleAssets    int                       `json:"stale_assets"`
	LastCheck      string                    `json:"last_check,omitempty"`
}

// SiteSummary holds per-site rollup.
type SiteSummary struct {
	Total      int `json:"total"`
	Vulnerable int `json:"vulnerable"`
}

// CVECount tracks how many assets are affected by a CVE.
type CVECount struct {
	CVE            string `json:"cve"`
	AffectedAssets int    `json:"affected_assets"`
}

// ComputeSummary returns aggregate stats for the asset store.
func (s *Store) ComputeSummary() Summary {
	sum := Summary{
		TotalAssets:   len(s.Assets),
		ByStatus:      map[string]int{},
		ByCriticality: map[string]int{},
		ByVulnStatus:  map[string]int{},
		BySite:        map[string]SiteSummary{},
	}

	staleThreshold := time.Now().UTC().Add(-7 * 24 * time.Hour)
	cveMap := map[string]int{}
	var latestCheck time.Time

	for _, a := range s.Assets {
		// Status
		status := a.Status
		if status == "" {
			status = "unknown"
		}
		sum.ByStatus[status]++

		// Criticality
		crit := a.Criticality
		if crit == "" {
			crit = "unassigned"
		}
		sum.ByCriticality[crit]++

		// Vuln status
		vs := "UNCHECKED"
		isVuln := false
		if a.VulnState != nil {
			vs = a.VulnState.Status
			if a.VulnState.Status == "VULNERABLE" {
				isVuln = true
			}
			if a.VulnState.KEVCount > 0 {
				sum.KEVAffected++
			}
			if a.VulnState.CheckedAt.After(latestCheck) {
				latestCheck = a.VulnState.CheckedAt
			}
			for _, adv := range a.VulnState.Advisories {
				for _, cve := range adv.CVEs {
					cveMap[cve]++
				}
			}
		}
		sum.ByVulnStatus[vs]++

		// Site
		site := a.Site
		if site == "" {
			site = "(unassigned)"
		}
		ss := sum.BySite[site]
		ss.Total++
		if isVuln {
			ss.Vulnerable++
		}
		sum.BySite[site] = ss

		// Stale
		if !a.LastSeen.IsZero() && a.LastSeen.Before(staleThreshold) {
			sum.StaleAssets++
		}
	}

	if !latestCheck.IsZero() {
		sum.LastCheck = latestCheck.Format(time.RFC3339)
	}

	// Top CVEs (up to 10)
	type kv struct {
		k string
		v int
	}
	var cvePairs []kv
	for k, v := range cveMap {
		cvePairs = append(cvePairs, kv{k, v})
	}
	sort.Slice(cvePairs, func(i, j int) bool { return cvePairs[i].v > cvePairs[j].v })
	if len(cvePairs) > 10 {
		cvePairs = cvePairs[:10]
	}
	for _, p := range cvePairs {
		sum.TopCVEs = append(sum.TopCVEs, CVECount{CVE: p.k, AffectedAssets: p.v})
	}

	return sum
}

func dedupKey(ip, vendor, model string) string {
	return strings.ToLower(ip + "|" + vendor + "|" + model)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
