package site

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/asset"
)

// Zone represents a logical network zone within a site.
type Zone struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	CIDRs         []string `json:"cidrs"`
	Purpose       string   `json:"purpose"`         // "ot", "it", "dmz", "corporate", "safety"
	SecurityLevel int      `json:"security_level"`   // IEC 62443 SL-T: 0-4
	Description   string   `json:"description,omitempty"`
}

// Site defines a named network site with one or more CIDR subnets.
type Site struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	CIDRs       []string  `json:"cidrs"`
	Zones       []Zone    `json:"zones,omitempty"`
	Description string    `json:"description,omitempty"`
	Location    string    `json:"location,omitempty"`
	Contact     string    `json:"contact,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store persists sites to disk.
type Store struct {
	mu      sync.Mutex
	path    string
	Version int    `json:"version"`
	Sites   []Site `json:"sites"`
}

// DefaultStorePath returns ~/.deadband/sites.json.
func DefaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "sites.json"
	}
	return filepath.Join(home, ".deadband", "sites.json")
}

// LoadStore loads from disk or returns an empty store.
// Sites with CIDRs but no zones are auto-migrated to have a default zone.
func LoadStore(path string) *Store {
	s := &Store{path: path, Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] site store %s: parse failed, starting empty: %v", path, err)
		return &Store{path: path, Version: 1}
	}
	s.path = path

	// Migrate: sites with CIDRs but no zones get a default zone.
	for i := range s.Sites {
		if len(s.Sites[i].CIDRs) > 0 && len(s.Sites[i].Zones) == 0 {
			s.Sites[i].Zones = []Zone{{
				ID:      "default",
				Name:    "Default",
				CIDRs:   s.Sites[i].CIDRs,
				Purpose: "ot",
			}}
		}
	}

	return s
}

// Save writes the store to disk.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

// Upsert creates or updates a site. Returns the updated site.
func (s *Store) Upsert(st Site) Site {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Sites {
		if s.Sites[i].ID == st.ID {
			s.Sites[i] = st
			return st
		}
	}
	s.Sites = append(s.Sites, st)
	return st
}

// Delete removes a site by ID. Returns false if not found.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Sites {
		if s.Sites[i].ID == id {
			s.Sites = append(s.Sites[:i], s.Sites[i+1:]...)
			return true
		}
	}
	return false
}

// Get returns a site by ID.
func (s *Store) Get(id string) *Site {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Sites {
		if s.Sites[i].ID == id {
			return &s.Sites[i]
		}
	}
	return nil
}

// List returns all sites.
func (s *Store) List() []Site {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Site, len(s.Sites))
	copy(out, s.Sites)
	return out
}

// MatchIP returns the first site whose CIDRs contain the given IP, or nil.
func (s *Store) MatchIP(ip string) *Site {
	s.mu.Lock()
	defer s.mu.Unlock()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	for i := range s.Sites {
		for _, cidr := range s.Sites[i].CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if network.Contains(parsed) {
				cp := s.Sites[i]
				return &cp
			}
		}
	}
	return nil
}

// UpsertZone adds or updates a zone within a site.
func (s *Store) UpsertZone(siteID string, z Zone) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Sites {
		if s.Sites[i].ID != siteID {
			continue
		}
		for j := range s.Sites[i].Zones {
			if s.Sites[i].Zones[j].ID == z.ID {
				s.Sites[i].Zones[j] = z
				return nil
			}
		}
		s.Sites[i].Zones = append(s.Sites[i].Zones, z)
		return nil
	}
	return fmt.Errorf("site %q not found", siteID)
}

// DeleteZone removes a zone from a site.
func (s *Store) DeleteZone(siteID, zoneID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Sites {
		if s.Sites[i].ID != siteID {
			continue
		}
		for j := range s.Sites[i].Zones {
			if s.Sites[i].Zones[j].ID == zoneID {
				s.Sites[i].Zones = append(s.Sites[i].Zones[:j], s.Sites[i].Zones[j+1:]...)
				return nil
			}
		}
		return fmt.Errorf("zone %q not found in site %q", zoneID, siteID)
	}
	return fmt.Errorf("site %q not found", siteID)
}

// MatchIPToZone returns the site and zone whose CIDRs contain the given IP.
func (s *Store) MatchIPToZone(ip string) (*Site, *Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, nil
	}
	for i := range s.Sites {
		for j := range s.Sites[i].Zones {
			for _, cidr := range s.Sites[i].Zones[j].CIDRs {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}
				if network.Contains(parsed) {
					si := s.Sites[i]
					zi := s.Sites[i].Zones[j]
					return &si, &zi
				}
			}
		}
	}
	return nil, nil
}

// AllZones returns a flat list of all zones across all sites.
func (s *Store) AllZones() []Zone {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zones []Zone
	for _, st := range s.Sites {
		zones = append(zones, st.Zones...)
	}
	return zones
}

// AssignAll sets the Site field on assets whose IP matches a site CIDR.
// Only overwrites assets with an empty Site field. Returns the count changed.
func (s *Store) AssignAll(assets []asset.Asset) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pre-parse all CIDRs for efficiency.
	type parsed struct {
		siteIdx int
		network *net.IPNet
	}
	var nets []parsed
	for i, st := range s.Sites {
		for _, cidr := range st.CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			nets = append(nets, parsed{siteIdx: i, network: network})
		}
	}
	if len(nets) == 0 {
		return 0
	}

	count := 0
	for j := range assets {
		if assets[j].Site != "" {
			continue
		}
		ip := net.ParseIP(assets[j].IP)
		if ip == nil {
			continue
		}
		for _, n := range nets {
			if n.network.Contains(ip) {
				assets[j].Site = s.Sites[n.siteIdx].Name
				count++
				break
			}
		}
	}
	return count
}
