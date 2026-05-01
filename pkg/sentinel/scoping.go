package sentinel

import (
	"fmt"
	"net"
	"sort"

	"github.com/jmeltz/deadband/pkg/acl"
	"github.com/jmeltz/deadband/pkg/site"
)

const subnetBinThreshold = 10

// ScopingRecommendation suggests narrower rules to replace a broad allow rule.
type ScopingRecommendation struct {
	OriginalRule     acl.PolicyRule `json:"original_rule"`
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

// BuildScopingRecommendations matches Sentinel flows against broad policy allow
// rules and generates specific replacement suggestions.
func BuildScopingRecommendations(policy acl.Policy, flows []SentinelFlow, zones []site.Zone) []ScopingRecommendation {
	if len(flows) == 0 {
		return nil
	}

	// Build zone CIDR lookup
	zoneCIDRs := buildZoneCIDRs(zones)

	var recs []ScopingRecommendation

	for _, rule := range policy.Rules {
		if rule.Action != "allow" {
			continue
		}

		// Only scope rules that are "broad" — no port restrictions or wide port lists
		if len(rule.Ports) > 0 && len(rule.Ports) <= 3 {
			continue // already narrow
		}

		// Match flows to this rule's zone pair
		var matched []SentinelFlow
		srcIPs := make(map[string]bool)
		dstIPs := make(map[string]bool)
		portSet := make(map[int]bool)

		for _, f := range flows {
			srcZone := matchFlowToZone(f.SourceAddr, zoneCIDRs)
			dstZone := matchFlowToZone(f.DestAddr, zoneCIDRs)

			// Use flow's own zone labels if available, fall back to CIDR match
			if f.SourceZone != "" {
				srcZone = f.SourceZone
			}
			if f.DestZone != "" {
				dstZone = f.DestZone
			}

			if srcZone != rule.SourceZone || dstZone != rule.DestZone {
				continue
			}

			// Port match — if rule specifies ports, flow must match
			if len(rule.Ports) > 0 {
				portMatch := false
				for _, p := range rule.Ports {
					if p == f.DestPort {
						portMatch = true
						break
					}
				}
				if !portMatch {
					continue
				}
			}

			matched = append(matched, f)
			srcIPs[f.SourceAddr] = true
			dstIPs[f.DestAddr] = true
			if f.DestPort > 0 {
				portSet[f.DestPort] = true
			}
		}

		if len(matched) == 0 {
			continue
		}

		rec := ScopingRecommendation{
			OriginalRule:     rule,
			ReductionPercent: estimateReduction(zoneCIDRs, rule, srcIPs, dstIPs),
			ActiveImpact:     len(matched) > 0,
		}

		rec.SuggestedRules = generateSuggestions(matched)
		recs = append(recs, rec)
	}

	return recs
}

// ComputeTrafficSummary aggregates flows by zone pair for the zone matrix overlay.
func ComputeTrafficSummary(flows []SentinelFlow, zones []site.Zone) []ZoneTrafficSummary {
	zoneCIDRs := buildZoneCIDRs(zones)

	type key struct{ src, dst string }
	type stats struct {
		flowCount   int
		ips         map[string]bool
		ports       map[int]int
		hasIdentity bool
	}

	agg := make(map[key]*stats)

	for _, f := range flows {
		srcZone := f.SourceZone
		if srcZone == "" {
			srcZone = matchFlowToZone(f.SourceAddr, zoneCIDRs)
		}
		dstZone := f.DestZone
		if dstZone == "" {
			dstZone = matchFlowToZone(f.DestAddr, zoneCIDRs)
		}
		if srcZone == "" || dstZone == "" {
			continue
		}

		k := key{srcZone, dstZone}
		s, ok := agg[k]
		if !ok {
			s = &stats{ips: make(map[string]bool), ports: make(map[int]int)}
			agg[k] = s
		}
		s.flowCount += f.ConnectionCount
		s.ips[f.SourceAddr] = true
		s.ips[f.DestAddr] = true
		if f.DestPort > 0 {
			s.ports[f.DestPort] += f.ConnectionCount
		}
		if f.UserName != "" || f.Department != "" {
			s.hasIdentity = true
		}
	}

	var summaries []ZoneTrafficSummary
	for k, s := range agg {
		ts := ZoneTrafficSummary{
			SourceZone:  k.src,
			DestZone:    k.dst,
			FlowCount:   s.flowCount,
			UniqueIPs:   len(s.ips),
			HasIdentity: s.hasIdentity,
		}

		// Top 5 ports by flow count
		type portCount struct {
			port  int
			count int
		}
		var pcs []portCount
		for p, c := range s.ports {
			pcs = append(pcs, portCount{p, c})
		}
		sort.Slice(pcs, func(i, j int) bool { return pcs[i].count > pcs[j].count })
		for i, pc := range pcs {
			if i >= 5 {
				break
			}
			ts.TopPorts = append(ts.TopPorts, pc.port)
		}

		summaries = append(summaries, ts)
	}

	return summaries
}

// --- helpers ---

type zoneCIDR struct {
	name string
	nets []*net.IPNet
}

func buildZoneCIDRs(zones []site.Zone) []zoneCIDR {
	var zcs []zoneCIDR
	for _, z := range zones {
		var nets []*net.IPNet
		for _, cidr := range z.CIDRs {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			nets = append(nets, n)
		}
		zcs = append(zcs, zoneCIDR{name: z.Name, nets: nets})
	}
	return zcs
}

func matchFlowToZone(ipStr string, zones []zoneCIDR) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, z := range zones {
		for _, n := range z.nets {
			if n.Contains(ip) {
				return z.name
			}
		}
	}
	return ""
}

func estimateReduction(zoneCIDRs []zoneCIDR, rule acl.PolicyRule, srcIPs, dstIPs map[string]bool) float64 {
	// Estimate zone address space
	var zoneSize float64
	for _, zc := range zoneCIDRs {
		if zc.name == rule.SourceZone {
			for _, n := range zc.nets {
				ones, bits := n.Mask.Size()
				zoneSize += float64(int(1) << (bits - ones))
			}
		}
	}

	observed := float64(len(srcIPs))
	if observed == 0 || zoneSize <= observed {
		// Try destination zone
		zoneSize = 0
		for _, zc := range zoneCIDRs {
			if zc.name == rule.DestZone {
				for _, n := range zc.nets {
					ones, bits := n.Mask.Size()
					zoneSize += float64(int(1) << (bits - ones))
				}
			}
		}
		observed = float64(len(dstIPs))
	}

	if observed == 0 || zoneSize <= observed {
		return 0
	}
	return (1 - observed/zoneSize) * 100
}

func generateSuggestions(flows []SentinelFlow) []SuggestedRule {
	// Count unique src/dst IPs per port
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

	// Bin and aggregate
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

		key := flowKey{src: srcStr, dst: dstStr, port: f.DestPort}
		aggregated[key] += f.ConnectionCount
	}

	var suggestions []SuggestedRule
	for key, count := range aggregated {
		sr := SuggestedRule{
			SourceCIDR: key.src,
			DestCIDR:   key.dst,
			FlowCount:  count,
		}
		if key.port > 0 {
			sr.Ports = []int{key.port}
			sr.Description = fmt.Sprintf("Allow %s → %s port %d (%d flows)", key.src, key.dst, key.port, count)
		} else {
			sr.Description = fmt.Sprintf("Allow %s → %s all ports (%d flows)", key.src, key.dst, count)
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
