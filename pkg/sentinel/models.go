package sentinel

import "time"

// SentinelFlow represents a single observed network flow from Azure Sentinel.
type SentinelFlow struct {
	DeviceHostname  string `json:"device_hostname"`
	SourceZone      string `json:"source_zone"`
	SourceAddr      string `json:"source_addr"`
	DestZone        string `json:"dest_zone"`
	DestAddr        string `json:"dest_addr"`
	DestPort        int    `json:"dest_port"`
	DestNATAddr     string `json:"dest_nat_addr,omitempty"`
	DestNATPort     int    `json:"dest_nat_port,omitempty"`
	ConnectionCount int    `json:"connection_count"`
	// Identity enrichment from Intune/Entra
	ComputerName string `json:"computer_name,omitempty"`
	UserName     string `json:"user_name,omitempty"`
	FullName     string `json:"full_name,omitempty"`
	JobTitle     string `json:"job_title,omitempty"`
	Department   string `json:"department,omitempty"`
	MailAddress  string `json:"mail_address,omitempty"`
	CompanyName  string `json:"company_name,omitempty"`
	OsName       string `json:"os_name,omitempty"`
}

// SentinelSnapshot represents a point-in-time collection of flows.
type SentinelSnapshot struct {
	ID        string         `json:"id"`
	SiteID    string         `json:"site_id"`
	ConfigID  string         `json:"config_id"`
	QueriedAt time.Time      `json:"queried_at"`
	FlowCount int            `json:"flow_count"`
	Flows     []SentinelFlow `json:"flows"`
}

// ZoneTrafficSummary is a derived view for the zone matrix overlay.
type ZoneTrafficSummary struct {
	SourceZone  string `json:"source_zone"`
	DestZone    string `json:"dest_zone"`
	FlowCount   int    `json:"flow_count"`
	UniqueIPs   int    `json:"unique_ips"`
	TopPorts    []int  `json:"top_ports"`
	HasIdentity bool   `json:"has_identity"`
}
