package posture

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"

	"github.com/jmeltz/deadband/pkg/site"
)

// SubnetAnalysis aggregates host classification data for a /24 subnet or zone.
type SubnetAnalysis struct {
	Subnet       string           `json:"subnet"`
	TotalHosts   int              `json:"total_hosts"`
	OTCount      int              `json:"ot_count"`
	ITCount      int              `json:"it_count"`
	NetworkCount int              `json:"network_count"`
	UnknownCount int              `json:"unknown_count"`
	Hosts        []ClassifiedHost `json:"hosts"`
	IsPureOT     bool             `json:"is_pure_ot"`
	IsMixed      bool             `json:"is_mixed"`
	RiskScore    float64          `json:"risk_score"`
	Zone         string           `json:"zone,omitempty"`
	ZonePurpose  string           `json:"zone_purpose,omitempty"`
}

// Finding represents a security concern identified during posture analysis.
type Finding struct {
	ID          string               `json:"id"`
	Type        string               `json:"type"`
	Severity    string               `json:"severity"`
	Subnet      string               `json:"subnet"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Evidence    []string             `json:"evidence"`
	Controls    []RecommendedControl `json:"controls"`
}

// AnalyzeSubnets groups classified hosts by /24 subnet and computes risk.
func AnalyzeSubnets(hosts []ClassifiedHost) []SubnetAnalysis {
	buckets := make(map[string][]ClassifiedHost)
	for _, h := range hosts {
		subnet := toSlash24(h.IP)
		buckets[subnet] = append(buckets[subnet], h)
	}

	results := make([]SubnetAnalysis, 0, len(buckets))
	for subnet, hlist := range buckets {
		sa := SubnetAnalysis{
			Subnet: subnet,
			Hosts:  hlist,
		}
		for _, h := range hlist {
			sa.TotalHosts++
			switch h.DeviceClass {
			case ClassOT:
				sa.OTCount++
			case ClassIT:
				sa.ITCount++
			case ClassNetwork:
				sa.NetworkCount++
			default:
				sa.UnknownCount++
			}
		}

		sa.IsPureOT = sa.OTCount > 0 && sa.ITCount == 0 && sa.UnknownCount == 0
		sa.IsMixed = sa.OTCount > 0 && (sa.ITCount > 0 || sa.UnknownCount > 0)
		sa.RiskScore = subnetRisk(sa)

		results = append(results, sa)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})

	return results
}

// AnalyzeWithZones groups classified hosts by zone instead of /24 subnet.
// Hosts not matching any zone go into an "Unzoned" group.
func AnalyzeWithZones(hosts []ClassifiedHost, zones []site.Zone) []SubnetAnalysis {
	// Pre-parse zone CIDRs
	type parsedZone struct {
		zone    site.Zone
		network *net.IPNet
	}
	var pz []parsedZone
	for _, z := range zones {
		for _, cidr := range z.CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			pz = append(pz, parsedZone{zone: z, network: network})
		}
	}

	// Group hosts by zone
	buckets := make(map[string][]ClassifiedHost)
	zoneInfo := make(map[string]site.Zone)
	for _, h := range hosts {
		ip := net.ParseIP(h.IP)
		matched := false
		if ip != nil {
			for _, p := range pz {
				if p.network.Contains(ip) {
					key := p.zone.ID
					buckets[key] = append(buckets[key], h)
					zoneInfo[key] = p.zone
					matched = true
					break
				}
			}
		}
		if !matched {
			buckets["_unzoned"] = append(buckets["_unzoned"], h)
		}
	}

	results := make([]SubnetAnalysis, 0, len(buckets))
	for key, hlist := range buckets {
		sa := SubnetAnalysis{Hosts: hlist}
		if z, ok := zoneInfo[key]; ok {
			// Build a label like "Process Control (10.0.1.0/24)"
			cidrLabel := ""
			if len(z.CIDRs) > 0 {
				cidrLabel = z.CIDRs[0]
				if len(z.CIDRs) > 1 {
					cidrLabel += fmt.Sprintf(" +%d", len(z.CIDRs)-1)
				}
			}
			sa.Subnet = fmt.Sprintf("%s (%s)", z.Name, cidrLabel)
			sa.Zone = z.Name
			sa.ZonePurpose = z.Purpose
		} else {
			sa.Subnet = "Unzoned"
		}

		for _, h := range hlist {
			sa.TotalHosts++
			switch h.DeviceClass {
			case ClassOT:
				sa.OTCount++
			case ClassIT:
				sa.ITCount++
			case ClassNetwork:
				sa.NetworkCount++
			default:
				sa.UnknownCount++
			}
		}

		sa.IsPureOT = sa.OTCount > 0 && sa.ITCount == 0 && sa.UnknownCount == 0
		sa.IsMixed = sa.OTCount > 0 && (sa.ITCount > 0 || sa.UnknownCount > 0)
		sa.RiskScore = zoneRisk(sa)

		results = append(results, sa)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})

	return results
}

// zoneRisk extends subnetRisk with purpose-mismatch penalties.
func zoneRisk(sa SubnetAnalysis) float64 {
	score := subnetRisk(sa)

	// Purpose-mismatch penalty: IT hosts in an OT-purpose zone are extra risky
	if sa.ZonePurpose == "ot" && sa.ITCount > 0 {
		score += 2.0
	}
	// Safety zones with any non-OT hosts are critical
	if sa.ZonePurpose == "safety" && (sa.ITCount > 0 || sa.UnknownCount > 0) {
		score += 3.0
	}

	if score > 10.0 {
		score = 10.0
	}
	return score
}

// GenerateFindings evaluates the default ruleset against the analysed subnets.
func GenerateFindings(subnets []SubnetAnalysis) []Finding {
	findings := EvalRules(DefaultRules, subnets)

	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(findings, func(i, j int) bool {
		return sevOrder[findings[i].Severity] < sevOrder[findings[j].Severity]
	})

	return findings
}

// subnetRisk computes a 0-10 risk score for a subnet.
func subnetRisk(sa SubnetAnalysis) float64 {
	score := 0.0

	if sa.IsMixed {
		score += 4.0
	}
	if sa.OTCount > 0 && sa.ITCount > 0 {
		ratio := float64(sa.ITCount) / float64(sa.TotalHosts)
		score += ratio * 3.0
	}
	if sa.OTCount > 0 && sa.UnknownCount > 0 {
		score += float64(sa.UnknownCount) * 0.5
	}
	if sa.TotalHosts > 20 && sa.IsMixed {
		score += 2.0
	}
	for _, h := range sa.Hosts {
		if sa.OTCount > 0 {
			if portIn(h.OpenPorts, 3389) {
				score += 1.5
			}
			if portIn(h.OpenPorts, 445) {
				score += 1.0
			}
		}
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

func toSlash24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip + "/24"
	}
	parsed = parsed.To4()
	if parsed == nil {
		return ip + "/24"
	}
	return fmt.Sprintf("%d.%d.%d.0/24", parsed[0], parsed[1], parsed[2])
}

func portIn(ports []int, target int) bool {
	for _, p := range ports {
		if p == target {
			return true
		}
	}
	return false
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
