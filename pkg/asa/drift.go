package asa

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/jmeltz/deadband/pkg/acl"
	"github.com/jmeltz/deadband/pkg/site"
)

// PolicyDrift represents a discrepancy between modeled policy and ASA config.
type PolicyDrift struct {
	PolicyRule  acl.PolicyRule `json:"policy_rule"`
	ASARules    []ACLRule      `json:"asa_rules"`
	DriftType   string         `json:"drift_type"` // "missing", "extra", "mismatch"
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
}

// ComparePolicyToASA finds drift between a deadband ACL policy and actual ASA rules.
func ComparePolicyToASA(policy acl.Policy, result CollectionResult, zones []site.Zone) []PolicyDrift {
	// Map ASA nameif -> interface IP
	nameifToIP := make(map[string]string)
	for _, iface := range result.Interfaces {
		if iface.Nameif != "" && iface.IP != "" {
			nameifToIP[iface.Nameif] = iface.IP
		}
	}

	// Map zone name -> parsed CIDRs
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

	// Map ASA nameif to zone name via interface IP overlap with zone CIDRs
	nameifToZone := make(map[string]string)
	for nameif, ipStr := range nameifToIP {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, z := range pz {
			for _, n := range z.nets {
				if n.Contains(ip) {
					nameifToZone[nameif] = z.name
					break
				}
			}
			if nameifToZone[nameif] != "" {
				break
			}
		}
	}

	// Also try exact name matching as fallback
	zoneNameSet := make(map[string]bool, len(zones))
	for _, z := range zones {
		zoneNameSet[strings.ToLower(z.Name)] = true
	}
	for _, iface := range result.Interfaces {
		if iface.Nameif == "" {
			continue
		}
		if _, ok := nameifToZone[iface.Nameif]; ok {
			continue // already mapped via IP
		}
		if zoneNameSet[strings.ToLower(iface.Nameif)] {
			// Find the zone with matching name (case-insensitive)
			for _, z := range zones {
				if strings.EqualFold(z.Name, iface.Nameif) {
					nameifToZone[iface.Nameif] = z.Name
					break
				}
			}
		}
	}

	// Index which ASA ACLs are bound to which interfaces (and direction)
	type aclBinding struct {
		aclName   string
		nameif    string
		direction string
	}
	var bindings []aclBinding
	for _, ag := range result.AccessGroups {
		bindings = append(bindings, aclBinding{
			aclName:   ag.ACLName,
			nameif:    ag.Interface,
			direction: ag.Direction,
		})
	}

	// Group ACL rules by ACL name
	rulesByACL := make(map[string][]ACLRule)
	for _, rule := range result.ACLRules {
		rulesByACL[rule.Name] = append(rulesByACL[rule.Name], rule)
	}

	// Helper: determine severity based on zone purposes
	severity := func(srcZone, dstZone string) string {
		sev := "medium"
		for _, z := range pz {
			if z.name == dstZone && (z.purpose == "safety" || z.purpose == "ot") {
				sev = "high"
				break
			}
		}
		for _, z := range pz {
			if (z.name == srcZone || z.name == dstZone) && z.purpose == "safety" {
				sev = "critical"
				break
			}
		}
		return sev
	}

	// Helper: check if an ASA rule matches a port set
	asaRuleMatchesPort := func(rule ACLRule, port int) bool {
		if rule.DestPort == "" {
			return true // no port restriction means all ports
		}
		rulePort, err := strconv.Atoi(rule.DestPort)
		if err != nil {
			return false
		}
		switch rule.PortOp {
		case "eq":
			return rulePort == port
		case "range":
			endPort, err := strconv.Atoi(rule.PortEnd)
			if err != nil {
				return false
			}
			return port >= rulePort && port <= endPort
		case "gt":
			return port > rulePort
		case "lt":
			return port < rulePort
		case "neq":
			return port != rulePort
		default:
			return rulePort == port
		}
	}

	// For each policy rule, find relevant ASA ACL rules and detect drift
	var drifts []PolicyDrift
	matchedPolicyRules := make(map[string]bool) // policy rule ID -> had ASA coverage

	for _, pr := range policy.Rules {
		// Find ASA ACLs bound to interfaces in the source or dest zone
		var relevantASARules []ACLRule
		for _, b := range bindings {
			zone := nameifToZone[b.nameif]
			if zone == "" {
				continue
			}
			// For inbound ACLs on the dest zone's interface, or outbound on source
			isRelevant := (b.direction == "in" && zone == pr.DestZone) ||
				(b.direction == "out" && zone == pr.SourceZone)
			if !isRelevant {
				continue
			}
			relevantASARules = append(relevantASARules, rulesByACL[b.aclName]...)
		}

		if len(relevantASARules) == 0 {
			// No ASA ACLs cover this zone pair at all
			drifts = append(drifts, PolicyDrift{
				PolicyRule:  pr,
				DriftType:   "missing",
				Description: fmt.Sprintf("No ASA ACL rules found covering %s -> %s", pr.SourceZone, pr.DestZone),
				Severity:    severity(pr.SourceZone, pr.DestZone),
			})
			matchedPolicyRules[pr.ID] = true
			continue
		}

		if pr.Action == "deny" {
			// Check if ASA has permit rules that would allow the denied traffic
			var conflicting []ACLRule
			for _, ar := range relevantASARules {
				if ar.Action != "permit" {
					continue
				}
				// Check port overlap
				if len(pr.Ports) == 0 {
					// Policy denies all ports; any permit is a conflict
					conflicting = append(conflicting, ar)
				} else {
					for _, p := range pr.Ports {
						if asaRuleMatchesPort(ar, p) {
							conflicting = append(conflicting, ar)
							break
						}
					}
				}
			}
			if len(conflicting) > 0 {
				portDesc := "all ports"
				if len(pr.Ports) > 0 {
					portStrs := make([]string, len(pr.Ports))
					for i, p := range pr.Ports {
						portStrs[i] = strconv.Itoa(p)
					}
					portDesc = "ports " + strings.Join(portStrs, ", ")
				}
				drifts = append(drifts, PolicyDrift{
					PolicyRule:  pr,
					ASARules:    conflicting,
					DriftType:   "mismatch",
					Description: fmt.Sprintf("Policy denies %s -> %s (%s), but ASA has %d permit rule(s) allowing this traffic", pr.SourceZone, pr.DestZone, portDesc, len(conflicting)),
					Severity:    severity(pr.SourceZone, pr.DestZone),
				})
			}
		} else if pr.Action == "allow" {
			// Check if ASA has matching permit rules for the allowed traffic
			hasPermit := false
			for _, ar := range relevantASARules {
				if ar.Action != "permit" {
					continue
				}
				if len(pr.Ports) == 0 {
					hasPermit = true
					break
				}
				for _, p := range pr.Ports {
					if asaRuleMatchesPort(ar, p) {
						hasPermit = true
						break
					}
				}
				if hasPermit {
					break
				}
			}
			if !hasPermit {
				portDesc := "all ports"
				if len(pr.Ports) > 0 {
					portStrs := make([]string, len(pr.Ports))
					for i, p := range pr.Ports {
						portStrs[i] = strconv.Itoa(p)
					}
					portDesc = "ports " + strings.Join(portStrs, ", ")
				}
				drifts = append(drifts, PolicyDrift{
					PolicyRule:  pr,
					DriftType:   "missing",
					Description: fmt.Sprintf("Policy allows %s -> %s (%s), but no matching ASA permit rule found", pr.SourceZone, pr.DestZone, portDesc),
					Severity:    "medium",
				})
			}
		}
		matchedPolicyRules[pr.ID] = true
	}

	// Find "extra" ASA rules with no corresponding policy entry
	// Only flag permits on interfaces mapped to known zones
	for _, b := range bindings {
		srcZone := ""
		dstZone := ""
		bZone := nameifToZone[b.nameif]
		if bZone == "" {
			continue
		}
		if b.direction == "in" {
			dstZone = bZone
		} else {
			srcZone = bZone
		}

		for _, ar := range rulesByACL[b.aclName] {
			if ar.Action != "permit" {
				continue
			}
			// Check if any policy rule covers this zone pair
			hasPolicyRule := false
			for _, pr := range policy.Rules {
				srcMatch := srcZone == "" || pr.SourceZone == srcZone
				dstMatch := dstZone == "" || pr.DestZone == dstZone
				if srcMatch && dstMatch && pr.Action == "allow" {
					hasPolicyRule = true
					break
				}
			}
			if !hasPolicyRule {
				desc := fmt.Sprintf("ASA permit rule in ACL %q (line %d) has no corresponding policy allow rule", ar.Name, ar.Line)
				if srcZone != "" {
					desc += fmt.Sprintf(" (source zone: %s)", srcZone)
				}
				if dstZone != "" {
					desc += fmt.Sprintf(" (dest zone: %s)", dstZone)
				}
				drifts = append(drifts, PolicyDrift{
					ASARules:    []ACLRule{ar},
					DriftType:   "extra",
					Description: desc,
					Severity:    "low",
				})
			}
		}
	}

	return drifts
}
