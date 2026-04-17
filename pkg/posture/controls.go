package posture

// RecommendedControl maps a finding to a specific framework control with remediation guidance.
type RecommendedControl struct {
	Framework      string `json:"framework"`
	ControlID      string `json:"control_id"`
	ControlName    string `json:"control_name"`
	Recommendation string `json:"recommendation"`
	Priority       string `json:"priority"` // immediate, short_term, long_term
}

// controlMappings maps finding types to their recommended compensating controls.
var controlMappings = map[string][]RecommendedControl{
	"mixed_subnet": {
		// IEC 62443
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 5.1",
			ControlName:    "Network Segmentation",
			Recommendation: "Implement network segmentation to isolate OT devices from IT endpoints using VLANs, firewalls, or unmanaged switches with ACLs",
			Priority:       "immediate",
		},
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 5.2",
			ControlName:    "Zone Boundary Protection",
			Recommendation: "Deploy industrial firewalls or DMZ architecture at zone boundaries between IT and OT segments",
			Priority:       "short_term",
		},
		// NIST CSF 2.0
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "PR.IR-01",
			ControlName:    "Network Segmentation",
			Recommendation: "Deploy zone boundaries between IT and OT network segments with explicit allow-list firewall rules",
			Priority:       "immediate",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "DE.CM-01",
			ControlName:    "Network Monitoring",
			Recommendation: "Monitor traffic crossing IT/OT boundaries for anomalous communications using IDS/IPS or network TAPs",
			Priority:       "short_term",
		},
		// NERC CIP
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-005-7 R1",
			ControlName:    "Electronic Security Perimeter",
			Recommendation: "Define Electronic Security Perimeter (ESP) boundaries to separate BES Cyber Systems from corporate network segments",
			Priority:       "immediate",
		},
	},

	"no_segmentation": {
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 5.1",
			ControlName:    "Network Segmentation",
			Recommendation: "Design and implement a zone/conduit model per IEC 62443-3-2 to partition this flat network into security zones",
			Priority:       "immediate",
		},
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 5.3",
			ControlName:    "General Purpose Person-to-Person Communication Restrictions",
			Recommendation: "Restrict direct communication between IT workstations and OT controllers; route through application proxies",
			Priority:       "immediate",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "PR.IR-01",
			ControlName:    "Network Segmentation",
			Recommendation: "Implement network architecture redesign to establish IT/OT demarcation with dedicated OT VLANs and firewall enforcement",
			Priority:       "immediate",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "ID.AM-03",
			ControlName:    "Network Communication Mapping",
			Recommendation: "Map all communication flows between IT and OT devices to establish baseline for segmentation design",
			Priority:       "immediate",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-005-7 R1",
			ControlName:    "Electronic Security Perimeter",
			Recommendation: "Establish ESP with defined access points; all traffic must pass through an Electronic Access Point (EAP)",
			Priority:       "immediate",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-005-7 R1.3",
			ControlName:    "Inbound/Outbound Access Permissions",
			Recommendation: "Configure deny-by-default access at ESP boundaries; permit only required communications",
			Priority:       "immediate",
		},
	},

	"it_remote_access_in_ot": {
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 1.13",
			ControlName:    "Remote Access",
			Recommendation: "Disable direct RDP/SSH to OT endpoints; require all remote access through a hardened jump host with multi-factor authentication",
			Priority:       "immediate",
		},
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 2.6",
			ControlName:    "Remote Session Termination",
			Recommendation: "Implement automatic session timeout and logging for all remote sessions to OT network segments",
			Priority:       "short_term",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "PR.AA-06",
			ControlName:    "Remote Access Management",
			Recommendation: "Implement centralized remote access gateway with MFA, session recording, and audit logging for all OT access",
			Priority:       "immediate",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-005-7 R2",
			ControlName:    "Interactive Remote Access",
			Recommendation: "All Interactive Remote Access must use an Intermediate System so that the Cyber Asset initiating remote access does not directly access the BES Cyber System",
			Priority:       "immediate",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-005-7 R2.4",
			ControlName:    "Multi-Factor Authentication",
			Recommendation: "Implement multi-factor authentication for all Interactive Remote Access sessions to BES Cyber Systems",
			Priority:       "immediate",
		},
	},

	"smb_in_ot": {
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 3.4",
			ControlName:    "Software and Information Integrity",
			Recommendation: "Disable SMB on OT devices where not operationally required; if required, enforce SMBv3 with signing and restrict to specific authorized hosts",
			Priority:       "immediate",
		},
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 7.6",
			ControlName:    "Network and Security Configuration Monitoring",
			Recommendation: "Monitor for SMB exploitation attempts (EternalBlue, PrintNightmare) on OT segments using network IDS",
			Priority:       "short_term",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "PR.PS-01",
			ControlName:    "Configuration Management",
			Recommendation: "Disable unnecessary network services (SMB, NetBIOS) on OT devices; document exceptions with risk acceptance",
			Priority:       "immediate",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-007-7 R1",
			ControlName:    "Ports and Services",
			Recommendation: "Disable or restrict SMB ports on BES Cyber Assets; document business justification for any enabled file-sharing services",
			Priority:       "immediate",
		},
	},

	"critical_ot_exposed": {
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 7.7",
			ControlName:    "Least Functionality",
			Recommendation: "Disable non-essential IT services (HTTP, SSH) on OT controllers; if web UI is required, restrict access to management VLAN only",
			Priority:       "immediate",
		},
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-4-2 CR 2.12",
			ControlName:    "Non-Essential Functionality",
			Recommendation: "Remove or disable all non-essential functions, ports, protocols, and services on OT device firmware",
			Priority:       "short_term",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "PR.PS-01",
			ControlName:    "Configuration Management",
			Recommendation: "Harden OT device configuration by disabling unnecessary services; apply vendor security hardening guides",
			Priority:       "immediate",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-007-7 R1",
			ControlName:    "Ports and Services",
			Recommendation: "Protect against use of unnecessary physical and logical ports on BES Cyber Assets by disabling or restricting IT-facing services",
			Priority:       "immediate",
		},
	},

	"cross_zone_violation": {
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 5.1",
			ControlName:    "Network Segmentation",
			Recommendation: "Enforce zone boundaries with firewalls or VLANs; deny cross-zone traffic that violates the conduit model",
			Priority:       "immediate",
		},
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 5.2",
			ControlName:    "Zone Boundary Protection",
			Recommendation: "Deploy industrial-grade firewalls at conduit points between OT and IT zones with explicit allow-list rules",
			Priority:       "immediate",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "PR.IR-01",
			ControlName:    "Network Segmentation",
			Recommendation: "Implement zone-based network architecture with boundary enforcement between security domains",
			Priority:       "immediate",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-005-7 R1",
			ControlName:    "Electronic Security Perimeter",
			Recommendation: "All cross-zone traffic must traverse an Electronic Access Point with deny-by-default ACLs",
			Priority:       "immediate",
		},
	},

	"purpose_mismatch": {
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-2 ZCR 3.1",
			ControlName:    "Zone and Conduit Design",
			Recommendation: "Relocate misplaced devices to their correct zone or create a dedicated conduit for authorized cross-zone communication",
			Priority:       "immediate",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "ID.AM-03",
			ControlName:    "Network Communication Mapping",
			Recommendation: "Audit device placement; move IT assets out of OT zones and establish proper conduit paths",
			Priority:       "short_term",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-005-7 R1.3",
			ControlName:    "Inbound/Outbound Access Permissions",
			Recommendation: "Review ESP boundaries; devices not belonging to the BES Cyber System must be outside the ESP",
			Priority:       "immediate",
		},
	},

	"unknown_device_in_ot": {
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-2-1 5.5",
			ControlName:    "Asset Inventory",
			Recommendation: "Identify and document all devices on OT network segments; classify unknown hosts and either authorize or remove them",
			Priority:       "short_term",
		},
		{
			Framework:      "IEC 62443",
			ControlID:      "62443-3-3 SR 3.1",
			ControlName:    "Communication Integrity",
			Recommendation: "Implement port security (802.1X or MAC filtering) to prevent unauthorized devices from joining OT network segments",
			Priority:       "long_term",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "ID.AM-01",
			ControlName:    "Asset Inventory",
			Recommendation: "Inventory all devices on OT subnets; investigate unidentified endpoints and classify or quarantine",
			Priority:       "short_term",
		},
		{
			Framework:      "NIST CSF 2.0",
			ControlID:      "PR.IR-02",
			ControlName:    "Network Access Control",
			Recommendation: "Deploy network access control (NAC) on OT segments to restrict connections to authorized devices only",
			Priority:       "long_term",
		},
		{
			Framework:      "NERC CIP",
			ControlID:      "CIP-010-4 R2",
			ControlName:    "Configuration Monitoring",
			Recommendation: "Monitor for and investigate unauthorized devices connecting to BES Cyber System networks",
			Priority:       "short_term",
		},
	},
}

// ControlsForFinding returns the recommended controls for a given finding type.
func ControlsForFinding(findingType string) []RecommendedControl {
	if c, ok := controlMappings[findingType]; ok {
		return c
	}
	return nil
}

// AllControlMappings returns the complete mapping of finding types to controls.
func AllControlMappings() map[string][]RecommendedControl {
	return controlMappings
}
