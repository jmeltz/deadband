package compliance

import "strings"

// Framework identifies a compliance framework.
type Framework string

const (
	IEC62443 Framework = "IEC 62443"
	NISTCSF2 Framework = "NIST CSF 2.0"
	NERCCIP  Framework = "NERC CIP"
)

// ControlMapping maps a deadband capability to a compliance control.
type ControlMapping struct {
	Framework   Framework `json:"framework"`
	ControlID   string    `json:"control_id"`
	ControlName string    `json:"control_name"`
	Capability  string    `json:"capability"`
	Rationale   string    `json:"rationale"`
}

var allMappings = []ControlMapping{
	// IEC 62443
	{IEC62443, "62443-2-1:2024 5.5", "Asset Inventory", "discovery", "Active protocol-based device enumeration identifies networked ICS assets"},
	{IEC62443, "62443-2-3:2015 4.2.3.1", "Patch Evaluation", "matching", "Advisory matching identifies applicable patches for discovered firmware"},
	{IEC62443, "62443-2-3:2015 4.2.3.2", "Patch Prioritization", "enrichment", "KEV/EPSS risk scoring prioritizes patch application order"},
	{IEC62443, "62443-2-3:2015 4.2.3.7", "Patch Tracking", "diffing", "Inventory diff reports track remediation progress across snapshots"},
	{IEC62443, "62443-3-3:2013 SR 1.1", "Human User Identification", "discovery", "Device identification provides asset context for access control planning"},
	{IEC62443, "62443-3-3:2013 SR 7.6", "Network and Security Configuration Monitoring", "matching", "Identifies devices with known vulnerabilities requiring configuration review"},
	{IEC62443, "62443-4-2:2019 CR 2.4", "Software Integrity", "version_check", "Firmware version verification against advisory-defined affected ranges"},

	// NIST CSF 2.0
	{NISTCSF2, "ID.AM-01", "Asset Inventory", "discovery", "Automated device enumeration across 7+ ICS protocols (CIP, S7, Modbus, MELSEC, BACnet, FINS, SRTP)"},
	{NISTCSF2, "ID.AM-02", "Software Inventory", "version_check", "Firmware version identification from protocol-native identity responses"},
	{NISTCSF2, "ID.RA-01", "Vulnerability Identification", "matching", "Cross-reference firmware against 3,600+ CISA ICS-CERT advisories"},
	{NISTCSF2, "ID.RA-02", "Threat Intelligence", "enrichment", "CISA KEV integration identifies CVEs actively exploited in the wild"},
	{NISTCSF2, "ID.RA-03", "Risk Assessment", "enrichment", "Composite risk scoring combines KEV status, EPSS probability, and CVSS severity"},
	{NISTCSF2, "ID.IM-01", "Improvement Process", "diffing", "Delta tracking across inventory snapshots demonstrates remediation progress"},
	{NISTCSF2, "PR.PS-01", "Configuration Management", "diffing", "Firmware change detection between inventory snapshots identifies unauthorized modifications"},
	{NISTCSF2, "DE.CM-09", "Computing Hardware Monitoring", "discovery", "Network-level device presence monitoring via periodic scanning"},

	// NERC CIP
	{NERCCIP, "CIP-002-7 R1", "BES Cyber System Identification", "discovery", "Automated identification of networked ICS assets within CIDR-defined scope"},
	{NERCCIP, "CIP-007-7 R2", "Patch Management", "matching", "Advisory matching identifies security patches applicable to discovered firmware"},
	{NERCCIP, "CIP-007-7 R2.2", "Patch Evaluation", "enrichment", "Risk-based prioritization of patches using KEV and EPSS exploitation data"},
	{NERCCIP, "CIP-010-4 R1", "Configuration Change Management", "diffing", "Firmware change tracking between baseline and current inventory"},
	{NERCCIP, "CIP-010-4 R2", "Configuration Monitoring", "discovery", "Periodic network scanning detects new or changed devices"},
}

// AllMappings returns the complete set of control mappings.
func AllMappings() []ControlMapping {
	return allMappings
}

// ForFrameworks returns mappings for the specified frameworks.
func ForFrameworks(frameworks []string) []ControlMapping {
	if len(frameworks) == 0 {
		return nil
	}
	for _, f := range frameworks {
		if strings.ToLower(f) == "all" {
			return allMappings
		}
	}

	want := make(map[Framework]bool)
	for _, f := range frameworks {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "iec62443", "iec-62443", "iec":
			want[IEC62443] = true
		case "nist-csf", "nistcsf", "nist", "csf":
			want[NISTCSF2] = true
		case "nerc-cip", "nerccip", "nerc", "cip":
			want[NERCCIP] = true
		}
	}

	var result []ControlMapping
	for _, m := range allMappings {
		if want[m.Framework] {
			result = append(result, m)
		}
	}
	return result
}

// ForCapability returns mappings relevant to a specific deadband capability.
func ForCapability(capability string) []ControlMapping {
	var result []ControlMapping
	for _, m := range allMappings {
		if m.Capability == capability {
			result = append(result, m)
		}
	}
	return result
}

// Frameworks returns the list of supported framework identifiers.
func Frameworks() []string {
	return []string{"iec62443", "nist-csf", "nerc-cip"}
}
