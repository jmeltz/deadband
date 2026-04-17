package acl

import (
	"fmt"
	"net"

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

// FlowIdentity represents identity info from Sentinel flows on a violation path.
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

// GapOpts provides optional enrichment data for gap analysis.
type GapOpts struct {
	// FlowZonePorts maps "srcZone|dstZone|port" to flow count
	FlowZonePorts map[string]int
	// FlowIdentities maps "srcZone|dstZone" to identity info
	FlowZoneIdentities map[string][]FlowIdentity
}

// AnalyzeGaps compares a policy's deny rules against the actual posture scan results.
// For each "deny" rule, it checks if hosts in the source zone have open ports
// that could reach hosts in the dest zone. Optional GapOpts enrich violations
// with Sentinel flow data.
func AnalyzeGaps(policy Policy, report posture.PostureReport, zones []site.Zone, opts ...GapOpts) []Violation {
	// Build zone-to-CIDR mapping
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

	// Map IPs to zone names
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

	// Collect all hosts from the report with their zone assignments
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

	// Group hosts by zone
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

		// Check deny ports — if empty, any open port is a violation
		denyPorts := make(map[int]bool, len(rule.Ports))
		denyAll := len(rule.Ports) == 0
		for _, p := range rule.Ports {
			denyPorts[p] = true
		}

		var violators []ViolatorHost

		// For each dest host, check if it has open ports that match denied ports
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
			// Higher severity for safety zone violations or OT zone violations
			for _, z := range pz {
				if z.name == rule.DestZone && (z.purpose == "safety" || z.purpose == "ot") {
					sev = "high"
					break
				}
			}
			// Safety violations are always critical
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

	// Enrich with Sentinel flow data if provided
	if len(opts) > 0 && opts[0].FlowZonePorts != nil {
		o := opts[0]
		for i := range violations {
			v := &violations[i]
			// Count active flows matching this violation's zone pair and ports
			totalFlows := 0
			for _, vh := range v.Violators {
				key := fmt.Sprintf("%s|%s|%d", v.Rule.SourceZone, v.Rule.DestZone, vh.Port)
				totalFlows += o.FlowZonePorts[key]
			}
			if totalFlows > 0 {
				v.ActiveFlows = totalFlows
				// Severity escalation: active traffic on denied paths is worse
				if v.Severity == "medium" {
					v.Severity = "high"
				} else if v.Severity == "high" {
					v.Severity = "critical"
				}
			}
			// Add identity info
			zoneKey := fmt.Sprintf("%s|%s", v.Rule.SourceZone, v.Rule.DestZone)
			if ids, ok := o.FlowZoneIdentities[zoneKey]; ok {
				v.FlowIdentities = ids
			}
		}
	}

	return violations
}
