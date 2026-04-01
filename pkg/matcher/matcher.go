package matcher

import (
	"strings"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/inventory"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

func ParseConfidence(s string) Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return ConfidenceHigh
	case "medium":
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

type Match struct {
	Advisory   advisory.Advisory
	Confidence Confidence
	Note       string
}

type Result struct {
	Device  inventory.Device
	Matches []Match
	Status  string // VULNERABLE, POTENTIAL, OK
}

type FilterOpts struct {
	MinConfidence Confidence
	MinCVSS       float64
	Vendor        string
}

func MatchAll(devices []inventory.Device, db *advisory.Database, opts FilterOpts) []Result {
	var results []Result
	for _, dev := range devices {
		matches := matchDevice(dev, db, opts)
		if len(matches) == 0 {
			continue
		}

		status := "OK"
		for _, m := range matches {
			switch m.Confidence {
			case ConfidenceHigh:
				status = "VULNERABLE"
			case ConfidenceMedium:
				if status != "VULNERABLE" {
					status = "POTENTIAL"
				}
			case ConfidenceLow:
				if status == "OK" {
					status = "POTENTIAL"
				}
			}
		}

		results = append(results, Result{
			Device:  dev,
			Matches: matches,
			Status:  status,
		})
	}
	return results
}

func matchDevice(dev inventory.Device, db *advisory.Database, opts FilterOpts) []Match {
	var matches []Match
	minRank := confidenceRank(opts.MinConfidence)

	for _, adv := range db.Advisories {
		// Vendor filter from CLI
		if opts.Vendor != "" && !VendorMatches(opts.Vendor, adv.Vendor) {
			continue
		}

		// CVSS filter
		if opts.MinCVSS > 0 && adv.CVSSv3Max < opts.MinCVSS {
			continue
		}

		// Vendor match
		if dev.Vendor != "" && !VendorMatches(dev.Vendor, adv.Vendor) {
			continue
		}

		// Model match
		modelMatch, modelConf := ModelMatches(dev.Model, adv.Products)
		if !modelMatch {
			continue
		}

		// Version match
		versionAffected, versionConf := VersionAffected(dev.Firmware, adv.AffectedVersions)
		if !versionAffected {
			continue
		}

		// Overall confidence is the minimum of model and version confidence
		conf := modelConf
		if confidenceRank(versionConf) < confidenceRank(conf) {
			conf = versionConf
		}

		if confidenceRank(conf) < minRank {
			continue
		}

		note := ""
		if versionConf == ConfidenceMedium {
			note = "Version range comparison ambiguous"
		} else if versionConf == ConfidenceLow {
			note = "Version comparison inconclusive"
		}

		matches = append(matches, Match{
			Advisory:   adv,
			Confidence: conf,
			Note:       note,
		})
	}
	return matches
}
