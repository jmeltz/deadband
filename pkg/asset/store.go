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

// Import merges devices into the store. Existing assets (matched by IP+Vendor+Model)
// get their firmware and last_seen updated. New devices are added as new assets.
func (s *Store) Import(devices []inventory.Device, source string) ImportResult {
	now := time.Now().UTC()
	result := ImportResult{}

	// Index existing assets by dedup key
	idx := make(map[string]int, len(s.Assets))
	for i, a := range s.Assets {
		idx[dedupKey(a.IP, a.Vendor, a.Model)] = i
	}

	for _, d := range devices {
		key := dedupKey(d.IP, d.Vendor, d.Model)
		if i, ok := idx[key]; ok {
			// Update existing
			s.Assets[i].Firmware = d.Firmware
			s.Assets[i].LastSeen = now
			result.Updated++
		} else {
			// New asset
			a := Asset{
				ID:        newID(),
				IP:        d.IP,
				Vendor:    d.Vendor,
				Model:     d.Model,
				Firmware:  d.Firmware,
				FirstSeen: now,
				LastSeen:  now,
				Source:    source,
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
		if opts.Search != "" {
			q := strings.ToLower(opts.Search)
			if !strings.Contains(strings.ToLower(a.IP), q) &&
				!strings.Contains(strings.ToLower(a.Vendor), q) &&
				!strings.Contains(strings.ToLower(a.Model), q) &&
				!strings.Contains(strings.ToLower(a.Name), q) &&
				!strings.Contains(strings.ToLower(a.Notes), q) &&
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

func dedupKey(ip, vendor, model string) string {
	return strings.ToLower(ip + "|" + vendor + "|" + model)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
