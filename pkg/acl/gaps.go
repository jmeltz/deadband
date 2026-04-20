package acl

import (
	"fmt"
	"net"

	"github.com/jmeltz/deadband/pkg/flow"
	"github.com/jmeltz/deadband/pkg/posture"
	"github.com/jmeltz/deadband/pkg/site"
)

// Violation represents a gap between policy and reality.
type Violation struct {
	Rule           PolicyRule     `json:"rule"`
	Violators      []ViolatorHost `json:"violators"`
	Severity       string         `json:"severity"`
	Description    string         `json:"description"`
	ActiveFlows    int            `json:"active_flows,omitempty"`
	FlowIdentities []FlowIdentity `json:"flow_identities,omitempty"`
}

// FlowIdentity represents identity info from observed flows on a violation path.
type FlowIdentity struct {
	UserName   string `json:"user_name"`
	Department string `json:"department"`
	FlowCount  int    `json:"flow_count"`
}

// ViolatorHost is a host that violates a policy rule.
type ViolatorHost struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname,omitempty"`
	Port       int    `json:"port"`
	SourceZone string `json:"source_zone"`
	DestZone   string `json:"dest_zone"`
}

// GapOpts carries optional enrichment data for gap analysis. Flows are
// bucketed internally by zone pair; callers just hand over the raw slice.
type GapOpts struct {
	Flows []flow.FlowRecord
}

// AnalyzeGaps compares a policy's deny rules against the actual posture scan
// results. For each "deny" rule, it checks if hosts in the dest zone expose
// ports the rule denies. Optional GapOpts enrich violations with observed
// traffic and identity metadata.
func AnalyzeGaps(policy Policy, report posture.PostureReport, zones []site.Zone, opts ...GapOpts) []Violation {
	type parsedZone struct {
		name    string
		purpose string
		nets    []*net.IPNet
	}
	var pz []parsedZone
	for _, z := range zones {
		var nets []*net.IPNet
		for _, cidr := range z.CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			nets = append(nets, network)
		}
		pz = append(pz, parsedZone{name: z.Name, purpose: z.Purpose, nets: nets})
	}

	ipToZone := func(ipStr string) string {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return ""
		}
		for _, z := range pz {
			for _, n := range z.nets {
				if n.Contains(ip) {
					return z.name
				}
			}
		}
		return ""
	}

	type hostInfo struct {
		host posture.ClassifiedHost
		zone string
	}
	var allHosts []hostInfo
	for _, sa := range report.Subnets {
		for _, h := range sa.Hosts {
			zone := ipToZone(h.IP)
			if zone == "" && sa.Zone != "" {
				zone = sa.Zone
			}
			allHosts = append(allHosts, hostInfo{host: h, zone: zone})
		}
	}

	hostsByZone := make(map[string][]hostInfo)
	for _, hi := range allHosts {
		if hi.zone != "" {
			hostsByZone[hi.zone] = append(hostsByZone[hi.zone], hi)
		}
	}

	var violations []Violation

	for _, rule := range policy.Rules {
		if rule.Action != "deny" {
			continue
		}

		srcHosts := hostsByZone[rule.SourceZone]
		destHosts := hostsByZone[rule.DestZone]
		if len(srcHosts) == 0 || len(destHosts) == 0 {
			continue
		}

		denyPorts := make(map[int]bool, len(rule.Ports))
		denyAll := len(rule.Ports) == 0
		for _, p := range rule.Ports {
			denyPorts[p] = true
		}

		var violators []ViolatorHost

		for _, dh := range destHosts {
			for _, port := range dh.host.OpenPorts {
				if denyAll || denyPorts[port] {
					violators = append(violators, ViolatorHost{
						IP:         dh.host.IP,
						Hostname:   dh.host.Hostname,
						Port:       port,
						SourceZone: rule.SourceZone,
						DestZone:   rule.DestZone,
					})
				}
			}
		}

		if len(violators) > 0 {
			sev := "medium"
			for _, z := range pz {
				if z.name == rule.DestZone && (z.purpose == "safety" || z.purpose == "ot") {
					sev = "high"
					break
				}
			}
			for _, z := range pz {
				if (z.name == rule.SourceZone || z.name == rule.DestZone) && z.purpose == "safety" {
					sev = "critical"
					break
				}
			}

			violations = append(violations, Violation{
				Rule:      rule,
				Violators: violators,
				Severity:  sev,
				Description: fmt.Sprintf("Policy denies %s → %s traffic, but %d host/port combinations have open paths",
					rule.SourceZone, rule.DestZone, len(violators)),
			})
		}
	}

	if len(opts) > 0 && len(opts[0].Flows) > 0 {
		flowPorts, flowIdentities := indexFlows(opts[0].Flows, zones)
		for i := range violations {
			v := &violations[i]
			totalFlows := 0
			for _, vh := range v.Violators {
				key := fmt.Sprintf("%s|%s|%d", v.Rule.SourceZone, v.Rule.DestZone, vh.Port)
				totalFlows += flowPorts[key]
			}
			if totalFlows > 0 {
				v.ActiveFlows = totalFlows
				switch v.Severity {
				case "medium":
					v.Severity = "high"
				case "high":
					v.Severity = "critical"
				}
			}
			zoneKey := fmt.Sprintf("%s|%s", v.Rule.SourceZone, v.Rule.DestZone)
			if ids, ok := flowIdentities[zoneKey]; ok {
				v.FlowIdentities = ids
			}
		}
	}

	return violations
}

// indexFlows buckets flow records into two maps that AnalyzeGaps uses for
// enrichment: (srcZone|dstZone|port) → total connection count, and
// (srcZone|dstZone) → identity info collected from flow enrichment.
func indexFlows(flows []flow.FlowRecord, zones []site.Zone) (map[string]int, map[string][]FlowIdentity) {
	idx := flow.BuildZoneIndex(zones)
	ports := make(map[string]int)
	identities := make(map[string][]FlowIdentity)

	for _, f := range flows {
		srcZone := f.SourceZone
		if srcZone == "" {
			srcZone = idx.Resolve(f.SourceAddr)
		}
		dstZone := f.DestZone
		if dstZone == "" {
			dstZone = idx.Resolve(f.DestAddr)
		}
		if srcZone == "" || dstZone == "" {
			continue
		}

		ports[fmt.Sprintf("%s|%s|%d", srcZone, dstZone, f.DestPort)] += f.ConnectionCount

		userName := f.Enrichment["UserName"]
		department := f.Enrichment["Department"]
		if userName == "" && department == "" {
			continue
		}
		zoneKey := fmt.Sprintf("%s|%s", srcZone, dstZone)
		identities[zoneKey] = append(identities[zoneKey], FlowIdentity{
			UserName:   userName,
			Department: department,
			FlowCount:  f.ConnectionCount,
		})
	}

	return ports, identities
}
