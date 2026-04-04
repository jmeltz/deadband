package diff

import (
	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

// DeviceKey uniquely identifies a device across snapshots.
type DeviceKey struct {
	IP    string
	Model string
}

func keyFor(d inventory.Device) DeviceKey {
	return DeviceKey{IP: d.IP, Model: d.Model}
}

// DiffReport holds the delta between two inventory snapshots.
type DiffReport struct {
	BaseFile           string
	CompareFile        string
	NewDevices         []inventory.Device
	RemovedDevices     []inventory.Device
	FirmwareChanges    []FirmwareChange
	NewVulnerabilities []NewVulnerability
}

// FirmwareChange records a device whose firmware version changed between snapshots.
type FirmwareChange struct {
	Device      inventory.Device
	OldFirmware string
	NewFirmware string
}

// NewVulnerability records a device that gained advisory matches in the compare snapshot.
type NewVulnerability struct {
	Device     inventory.Device
	NewMatches []matcher.Match
}

// Compute compares a base and compare inventory against the advisory database
// and produces a DiffReport covering device changes and new vulnerability exposure.
func Compute(base, compare []inventory.Device, db *advisory.Database, opts matcher.FilterOpts) *DiffReport {
	baseMap := make(map[DeviceKey]inventory.Device, len(base))
	for _, d := range base {
		baseMap[keyFor(d)] = d
	}
	compareMap := make(map[DeviceKey]inventory.Device, len(compare))
	for _, d := range compare {
		compareMap[keyFor(d)] = d
	}

	report := &DiffReport{}

	// New and removed devices
	for key, d := range compareMap {
		if _, ok := baseMap[key]; !ok {
			report.NewDevices = append(report.NewDevices, d)
		}
	}
	for key, d := range baseMap {
		if _, ok := compareMap[key]; !ok {
			report.RemovedDevices = append(report.RemovedDevices, d)
		}
	}

	// Firmware changes
	for key, cd := range compareMap {
		if bd, ok := baseMap[key]; ok && bd.Firmware != cd.Firmware {
			report.FirmwareChanges = append(report.FirmwareChanges, FirmwareChange{
				Device:      cd,
				OldFirmware: bd.Firmware,
				NewFirmware: cd.Firmware,
			})
		}
	}

	// New vulnerabilities: advisory matches in compare that weren't in base
	baseResults := matcher.MatchAll(base, db, opts)
	compareResults := matcher.MatchAll(compare, db, opts)

	baseAdvIDs := make(map[DeviceKey]map[string]bool)
	for _, r := range baseResults {
		key := keyFor(r.Device)
		if baseAdvIDs[key] == nil {
			baseAdvIDs[key] = make(map[string]bool)
		}
		for _, m := range r.Matches {
			baseAdvIDs[key][m.Advisory.ID] = true
		}
	}

	for _, r := range compareResults {
		key := keyFor(r.Device)
		var newMatches []matcher.Match
		for _, m := range r.Matches {
			if baseAdvIDs[key] == nil || !baseAdvIDs[key][m.Advisory.ID] {
				newMatches = append(newMatches, m)
			}
		}
		if len(newMatches) > 0 {
			report.NewVulnerabilities = append(report.NewVulnerabilities, NewVulnerability{
				Device:     r.Device,
				NewMatches: newMatches,
			})
		}
	}

	return report
}
