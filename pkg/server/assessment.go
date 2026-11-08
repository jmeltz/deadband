package server

import (
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

// Serialize local API inventory read/modify/write transactions. Network queries
// run outside this lock and revalidate stable target IDs before applying results.
var assetStoreMu sync.Mutex

func deviceForAsset(a asset.Asset) inventory.Device {
	d := inventory.Device{IP: a.IP, Vendor: a.Vendor, Model: a.Model, Firmware: a.Firmware, Serial: a.Serial, MAC: a.MAC, Protocol: a.Protocol, Port: a.Port, Slot: a.Slot, Extra: a.Extra}
	for field, value := range a.Overrides {
		switch field {
		case "vendor":
			d.Vendor = value
		case "model":
			d.Model = value
		case "firmware":
			d.Firmware = value
		case "serial":
			d.Serial = value
		}
	}
	return d
}

// Assess one component at a time so identical models in separate chassis slots
// never borrow each other's result. Every assessment supersedes the old state.
func (s *Server) assessDevice(d inventory.Device) *asset.VulnState {
	state := &asset.VulnState{CheckedAt: time.Now().UTC(), Status: "UNKNOWN"}
	if s.db == nil || len(s.db.Advisories) == 0 {
		state.Reason = "No advisory database is loaded"
		return state
	}
	state.DBUpdated = s.db.Updated
	if strings.TrimSpace(d.Vendor) == "" || strings.TrimSpace(d.Model) == "" || strings.TrimSpace(d.Firmware) == "" {
		state.Reason = "Identity or component version is incomplete"
		return state
	}
	results := matcher.MatchAll([]inventory.Device{d}, s.db, matcher.FilterOpts{})
	if len(results) == 0 {
		state.Status = "NO_MATCH"
		state.Reason = "No applicable advisory in the current database; this does not establish that the device is patched"
		return state
	}
	r := results[0]
	state.Status = strings.ToUpper(r.Status)
	for _, m := range r.Matches {
		conf := strings.ToUpper(string(m.Confidence))
		if state.Confidence == "" || conf == "HIGH" || (conf == "MEDIUM" && state.Confidence == "LOW") {
			state.Confidence = conf
		}
		v := asset.VulnAdvisory{ID: m.Advisory.ID, Title: strings.TrimSpace(m.Advisory.Title), CVEs: m.Advisory.CVEs, CVSSv3: m.Advisory.CVSSv3Max, KEV: m.KEV, RiskScore: m.RiskScore}
		if s.edb != nil && s.edb.Loaded() {
			e := s.edb.EnrichAdvisory(v.CVEs, v.CVSSv3)
			v.KEV = e.KEV
			v.RiskScore = e.RiskScore
		}
		state.Advisories = append(state.Advisories, v)
		state.CVECount += len(v.CVEs)
		if v.KEV {
			state.KEVCount++
		}
		if v.RiskScore > state.RiskScore {
			state.RiskScore = v.RiskScore
		}
	}
	return state
}

func (s *Server) assetStorePath() string {
	if s.assetPath != "" {
		return s.assetPath
	}
	return asset.DefaultPath()
}
