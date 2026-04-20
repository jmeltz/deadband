package acl

import (
	"fmt"
	"net"
	"slices"

	"github.com/jmeltz/deadband/pkg/flow"
	"github.com/jmeltz/deadband/pkg/site"
)

const subnetBinThreshold = 10

// ScopingRecommendation suggests narrower rules to replace a broad allow rule.
type ScopingRecommendation struct {
	OriginalRule     PolicyRule      `json:"original_rule"`
	SuggestedRules   []SuggestedRule `json:"suggested_rules"`
	ReductionPercent float64         `json:"reduction_percent"`
	ActiveImpact     bool            `json:"active_impact"`
}

// SuggestedRule is a tighter replacement rule based on observed flows.
type SuggestedRule struct {
	SourceCIDR  string `json:"source_cidr"`
	DestCIDR    string `json:"dest_cidr"`
	Ports       []int  `json:"ports"`
	FlowCount   int    `json:"flow_count"`
	Description string `json:"description"`
}

// BuildScopingRecommendations matches observed flows against broad allow rules
// and proposes narrower replacements. A rule is "broad" if it has no port
// restrictions or specifies more than three ports.
func BuildScopingRecommendations(policy Policy, flows []flow.FlowRecord, zones []site.Zone) []ScopingRecommendation {
	if len(flows) == 0 {
		return nil
	}

	idx := flow.BuildZoneIndex(zones)

	var recs []ScopingRecommendation

	for _, rule := range policy.Rules {
		if rule.Action != "allow" {
			continue
		}
		if len(rule.Ports) > 0 && len(rule.Ports) <= 3 {
			continue
		}

		var matched []flow.FlowRecord
		srcIPs := make(map[string]bool)
		dstIPs := make(map[string]bool)

		for _, f := range flows {
			srcZone := f.SourceZone
			if srcZone == "" {
				srcZone = idx.Resolve(f.SourceAddr)
			}
			dstZone := f.DestZone
			if dstZone == "" {
				dstZone = idx.Resolve(f.DestAddr)
			}

			if srcZone != rule.SourceZone || dstZone != rule.DestZone {
				continue
			}

			if len(rule.Ports) > 0 && !slices.Contains(rule.Ports, f.DestPort) {
				continue
			}

			matched = append(matched, f)
			srcIPs[f.SourceAddr] = true
			dstIPs[f.DestAddr] = true
		}

		if len(matched) == 0 {
			continue
		}

		rec := ScopingRecommendation{
			OriginalRule:     rule,
			ReductionPercent: estimateReduction(idx, rule, srcIPs, dstIPs),
			ActiveImpact:     true,
			SuggestedRules:   generateSuggestions(matched),
		}
		recs = append(recs, rec)
	}

	return recs
}

func estimateReduction(idx flow.ZoneIndex, rule PolicyRule, srcIPs, dstIPs map[string]bool) float64 {
	zoneSize := idx.ZoneSize(rule.SourceZone)
	observed := float64(len(srcIPs))
	if observed == 0 || zoneSize <= observed {
		zoneSize = idx.ZoneSize(rule.DestZone)
		observed = float64(len(dstIPs))
	}
	if observed == 0 || zoneSize <= observed {
		return 0
	}
	return (1 - observed/zoneSize) * 100
}

func generateSuggestions(flows []flow.FlowRecord) []SuggestedRule {
	portSrcs := make(map[int]map[string]bool)
	portDsts := make(map[int]map[string]bool)
	for _, f := range flows {
		if portSrcs[f.DestPort] == nil {
			portSrcs[f.DestPort] = make(map[string]bool)
		}
		if portDsts[f.DestPort] == nil {
			portDsts[f.DestPort] = make(map[string]bool)
		}
		portSrcs[f.DestPort][f.SourceAddr] = true
		portDsts[f.DestPort][f.DestAddr] = true
	}

	type flowKey struct {
		src  string
		dst  string
		port int
	}
	aggregated := make(map[flowKey]int)

	for _, f := range flows {
		var srcStr, dstStr string

		if len(portSrcs[f.DestPort]) > subnetBinThreshold {
			srcStr = ipToSubnet24(f.SourceAddr)
		} else {
			srcStr = f.SourceAddr + "/32"
		}

		if len(portDsts[f.DestPort]) > subnetBinThreshold {
			dstStr = ipToSubnet24(f.DestAddr)
		} else {
			dstStr = f.DestAddr + "/32"
		}

		k := flowKey{src: srcStr, dst: dstStr, port: f.DestPort}
		aggregated[k] += f.ConnectionCount
	}

	var suggestions []SuggestedRule
	for k, count := range aggregated {
		sr := SuggestedRule{
			SourceCIDR: k.src,
			DestCIDR:   k.dst,
			FlowCount:  count,
		}
		if k.port > 0 {
			sr.Ports = []int{k.port}
			sr.Description = fmt.Sprintf("Allow %s → %s port %d (%d flows)", k.src, k.dst, k.port, count)
		} else {
			sr.Description = fmt.Sprintf("Allow %s → %s all ports (%d flows)", k.src, k.dst, count)
		}
		suggestions = append(suggestions, sr)
	}

	return suggestions
}

func ipToSubnet24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip + "/32"
	}
	p := parsed.To4()
	if p == nil {
		return ip + "/32"
	}
	return fmt.Sprintf("%d.%d.%d.0/24", p[0], p[1], p[2])
}
