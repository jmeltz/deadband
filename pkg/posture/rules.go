package posture

import (
	"fmt"
	"strings"
)

// ---------- Rule definition types ----------

// Rule defines a posture finding with declarative match conditions.
// Subnet-scoped rules fire once per matching subnet.
// Host-scoped rules fire once per matching host within matching subnets.
type Rule struct {
	ID         string   // unique key, doubles as the control-set lookup
	Title      string   // human-readable short title
	Severity   string   // critical | high | medium | low
	Scope      string   // "subnet" or "host"
	When       []Cond   // ALL must be true on the subnet for the rule to apply
	Host       HostCond // only evaluated when Scope == "host"
	Desc       string   // fmt template — subnet-scoped gets (subnet, counts…), host-scoped gets (ip, subnet, svcList)
	ControlSet string   // key into controlMappings; defaults to ID if empty
}

// Cond is a single predicate evaluated against a SubnetAnalysis.
//
//	Field: ot_count | it_count | network_count | unknown_count | total_hosts
//	Op:    gt | gte | lt | lte | eq
//	Value: integer threshold
type Cond struct {
	Field string
	Op    string
	Value int
}

// HostCond selects which hosts within a qualifying subnet trigger a finding.
type HostCond struct {
	Class   DeviceClass // only match hosts of this class ("" = any)
	AnyPort []int       // host must have at least one of these ports open
	HasITPorts bool     // host must have any port from ITPorts (used for critical_ot_exposed)
}

// ---------- Default ruleset ----------

// DefaultRules is the built-in ruleset shipped with deadband.
// Add new rules here — no other code changes required.
var DefaultRules = []Rule{
	{
		ID:       "mixed_subnet",
		Title:    "Mixed OT/IT Subnet",
		Severity: "high",
		Scope:    "subnet",
		When: []Cond{
			{Field: "ot_count", Op: "gt", Value: 0},
			{Field: "it_count", Op: "gt", Value: 0},
		},
		Desc: "Subnet %s contains %d OT and %d IT devices on the same network segment. " +
			"IT endpoints sharing a broadcast domain with OT controllers increases lateral movement risk.",
	},
	{
		ID:       "no_segmentation",
		Title:    "No Network Segmentation",
		Severity: "critical",
		Scope:    "subnet",
		When: []Cond{
			{Field: "total_hosts", Op: "gte", Value: 10},
			{Field: "ot_count", Op: "gt", Value: 0},
			{Field: "it_count", Op: "gt", Value: 0},
			{Field: "unknown_count", Op: "gt", Value: 0},
		},
		Desc: "Subnet %s has %d hosts (%d OT, %d IT, %d unknown) with no apparent segmentation. " +
			"A flat network allows any compromised host direct L2 access to OT controllers.",
	},
	{
		ID:       "it_remote_access_in_ot",
		Title:    "Remote Access Service on OT Subnet",
		Severity: "critical",
		Scope:    "host",
		When: []Cond{
			{Field: "ot_count", Op: "gt", Value: 0},
		},
		Host: HostCond{AnyPort: []int{3389, 22}},
		Desc: "Host %s on OT subnet %s has remote access service(s) %s open. " +
			"Direct remote access to OT segments bypasses perimeter controls.",
	},
	{
		ID:       "smb_in_ot",
		Title:    "SMB Service on OT Subnet",
		Severity: "high",
		Scope:    "host",
		When: []Cond{
			{Field: "ot_count", Op: "gt", Value: 0},
		},
		Host: HostCond{AnyPort: []int{445}},
		Desc: "Host %s on OT subnet %s has SMB (port 445) open. " +
			"SMB is a common lateral movement vector (EternalBlue, WannaCry) and should not be present on OT segments.",
	},
	{
		ID:       "critical_ot_exposed",
		Title:    "OT Device Exposing IT Services",
		Severity: "high",
		Scope:    "host",
		When: []Cond{
			{Field: "ot_count", Op: "gt", Value: 0},
		},
		Host: HostCond{Class: ClassOT, HasITPorts: true},
		Desc: "OT device %s (%s) on subnet %s has IT service(s) %s open. " +
			"Web servers, SSH, and other IT services on OT controllers expand the attack surface.",
	},
	{
		ID:       "unknown_device_in_ot",
		Title:    "Unidentified Devices on OT Subnet",
		Severity: "medium",
		Scope:    "subnet",
		When: []Cond{
			{Field: "ot_count", Op: "gt", Value: 0},
			{Field: "unknown_count", Op: "gt", Value: 0},
		},
		Desc: "%d unidentified device(s) on OT subnet %s. " +
			"Unknown devices may be unauthorized or misconfigured, posing a risk to OT operations.",
	},
	{
		ID:         "purpose_mismatch",
		Title:      "Device-Zone Purpose Mismatch",
		Severity:   "high",
		Scope:      "subnet",
		When:       nil, // Custom evaluation in evalSubnetRule
		ControlSet: "purpose_mismatch",
		Desc: "%d %s device(s) detected in %s-purpose zone %s. " +
			"Devices must be placed in zones matching their function to maintain segmentation integrity.",
	},
}

// ---------- Evaluation engine ----------

// EvalRules evaluates a ruleset against analysed subnets and returns findings.
func EvalRules(rules []Rule, subnets []SubnetAnalysis) []Finding {
	var findings []Finding

	for _, rule := range rules {
		controlSet := rule.ControlSet
		if controlSet == "" {
			controlSet = rule.ID
		}

		// purpose_mismatch uses custom zone-aware logic
		if rule.ID == "purpose_mismatch" {
			findings = append(findings, evalPurposeMismatch(rule, subnets, controlSet)...)
			continue
		}

		for _, sa := range subnets {
			if !matchAllConds(rule.When, sa) {
				continue
			}

			switch rule.Scope {
			case "host":
				findings = append(findings, evalHostRule(rule, sa, controlSet)...)
			default: // "subnet"
				findings = append(findings, evalSubnetRule(rule, sa, controlSet))
			}
		}
	}

	return findings
}

func evalSubnetRule(rule Rule, sa SubnetAnalysis, controlSet string) Finding {
	var desc string
	var evidence []string

	switch rule.ID {
	case "mixed_subnet":
		desc = fmt.Sprintf(rule.Desc, sa.Subnet, sa.OTCount, sa.ITCount)
		for _, h := range sa.Hosts {
			if h.DeviceClass == ClassIT {
				evidence = append(evidence, fmt.Sprintf("%s (%s)", hostLabel(h), strings.Join(h.Services, ", ")))
			}
		}
	case "no_segmentation":
		desc = fmt.Sprintf(rule.Desc, sa.Subnet, sa.TotalHosts, sa.OTCount, sa.ITCount, sa.UnknownCount)
		evidence = []string{fmt.Sprintf("%d total hosts on %s", sa.TotalHosts, sa.Subnet)}
	case "unknown_device_in_ot":
		var unknownIPs []string
		for _, h := range sa.Hosts {
			if h.DeviceClass == ClassUnknown {
				unknownIPs = append(unknownIPs, hostLabel(h))
			}
		}
		desc = fmt.Sprintf(rule.Desc, len(unknownIPs), sa.Subnet)
		evidence = unknownIPs
	default:
		desc = fmt.Sprintf(rule.Desc, sa.Subnet)
	}

	return Finding{
		ID:          randID(),
		Type:        rule.ID,
		Severity:    rule.Severity,
		Subnet:      sa.Subnet,
		Title:       rule.Title,
		Description: desc,
		Evidence:    evidence,
		Controls:    ControlsForFinding(controlSet),
	}
}

func evalHostRule(rule Rule, sa SubnetAnalysis, controlSet string) []Finding {
	var findings []Finding

	for _, h := range sa.Hosts {
		if !matchHostCond(rule.Host, h) {
			continue
		}

		var desc string
		var evidence []string

		matched := matchedPortNames(h, rule)
		label := hostLabel(h)

		switch rule.ID {
		case "it_remote_access_in_ot":
			svcList := strings.Join(matched, ", ")
			desc = fmt.Sprintf(rule.Desc, h.IP, sa.Subnet, svcList)
			evidence = []string{fmt.Sprintf("%s: %s", label, svcList)}
		case "smb_in_ot":
			desc = fmt.Sprintf(rule.Desc, h.IP, sa.Subnet)
			evidence = []string{fmt.Sprintf("%s: SMB:445", label)}
		case "critical_ot_exposed":
			svcList := strings.Join(matched, ", ")
			identity := strings.TrimSpace(h.Vendor + " " + h.Model)
			if identity == "" {
				identity = h.IP
			}
			desc = fmt.Sprintf(rule.Desc, h.IP, identity, sa.Subnet, svcList)
			evidence = []string{fmt.Sprintf("%s: %s", label, svcList)}
		default:
			desc = fmt.Sprintf(rule.Desc, h.IP, sa.Subnet)
			evidence = []string{label}
		}

		findings = append(findings, Finding{
			ID:          randID(),
			Type:        rule.ID,
			Severity:    rule.Severity,
			Subnet:      sa.Subnet,
			Title:       rule.Title,
			Description: desc,
			Evidence:    evidence,
			Controls:    ControlsForFinding(controlSet),
		})
	}

	return findings
}

// ---------- Condition matching ----------

func matchAllConds(conds []Cond, sa SubnetAnalysis) bool {
	for _, c := range conds {
		if !evalCond(c, sa) {
			return false
		}
	}
	return true
}

func evalCond(c Cond, sa SubnetAnalysis) bool {
	val := fieldValue(c.Field, sa)
	switch c.Op {
	case "gt":
		return val > c.Value
	case "gte":
		return val >= c.Value
	case "lt":
		return val < c.Value
	case "lte":
		return val <= c.Value
	case "eq":
		return val == c.Value
	default:
		return false
	}
}

func fieldValue(field string, sa SubnetAnalysis) int {
	switch field {
	case "ot_count":
		return sa.OTCount
	case "it_count":
		return sa.ITCount
	case "network_count":
		return sa.NetworkCount
	case "unknown_count":
		return sa.UnknownCount
	case "total_hosts":
		return sa.TotalHosts
	default:
		return 0
	}
}

func matchHostCond(hc HostCond, h ClassifiedHost) bool {
	// Class filter
	if hc.Class != "" && h.DeviceClass != hc.Class {
		return false
	}
	// AnyPort: host must have at least one of the listed ports
	if len(hc.AnyPort) > 0 {
		found := false
		for _, target := range hc.AnyPort {
			if portIn(h.OpenPorts, target) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// HasITPorts: host must have any IT-class port open
	if hc.HasITPorts {
		itSet := portSet(ITPorts)
		found := false
		for _, p := range h.OpenPorts {
			if itSet[p] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// evalPurposeMismatch generates findings when devices don't match their zone's purpose.
// E.g. IT devices in an OT-purpose zone, or OT devices in a corporate zone.
func evalPurposeMismatch(rule Rule, subnets []SubnetAnalysis, controlSet string) []Finding {
	var findings []Finding

	for _, sa := range subnets {
		if sa.ZonePurpose == "" {
			continue // no zone info — skip
		}

		var mismatchClass string
		var mismatchCount int
		var evidence []string

		switch sa.ZonePurpose {
		case "ot", "safety":
			// IT devices in OT/safety zones
			if sa.ITCount > 0 {
				mismatchClass = "IT"
				mismatchCount = sa.ITCount
				for _, h := range sa.Hosts {
					if h.DeviceClass == ClassIT {
						evidence = append(evidence, fmt.Sprintf("%s: %s", hostLabel(h), strings.Join(h.Services, ", ")))
					}
				}
			}
		case "it", "corporate":
			// OT devices in IT/corporate zones
			if sa.OTCount > 0 {
				mismatchClass = "OT"
				mismatchCount = sa.OTCount
				for _, h := range sa.Hosts {
					if h.DeviceClass == ClassOT {
						evidence = append(evidence, fmt.Sprintf("%s: %s", hostLabel(h), strings.Join(h.Services, ", ")))
					}
				}
			}
		}

		if mismatchCount == 0 {
			continue
		}

		desc := fmt.Sprintf(rule.Desc, mismatchCount, mismatchClass, sa.ZonePurpose, sa.Subnet)
		findings = append(findings, Finding{
			ID:          randID(),
			Type:        rule.ID,
			Severity:    rule.Severity,
			Subnet:      sa.Subnet,
			Title:       rule.Title,
			Description: desc,
			Evidence:    evidence,
			Controls:    ControlsForFinding(controlSet),
		})
	}

	return findings
}

// hostLabel returns "HOSTNAME (IP)" if a hostname is known, otherwise just "IP".
func hostLabel(h ClassifiedHost) string {
	if h.Hostname != "" {
		return h.Hostname + " (" + h.IP + ")"
	}
	return h.IP
}

// matchedPortNames returns human-readable names of ports that triggered a rule.
func matchedPortNames(h ClassifiedHost, rule Rule) []string {
	var names []string
	if len(rule.Host.AnyPort) > 0 {
		for _, p := range rule.Host.AnyPort {
			if portIn(h.OpenPorts, p) {
				if name, ok := PortServiceName[p]; ok {
					names = append(names, fmt.Sprintf("%s:%d", name, p))
				} else {
					names = append(names, fmt.Sprintf("%d", p))
				}
			}
		}
	}
	if rule.Host.HasITPorts {
		itSet := portSet(ITPorts)
		for _, p := range h.OpenPorts {
			if itSet[p] {
				if name, ok := PortServiceName[p]; ok {
					names = append(names, fmt.Sprintf("%s:%d", name, p))
				}
			}
		}
	}
	return names
}
