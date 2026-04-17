package asa

import "time"

// ACLRule represents a parsed Cisco ASA access-list entry.
type ACLRule struct {
	Name        string `json:"name"`
	Line        int    `json:"line"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	SourceAddr  string `json:"source_addr"`
	SourceMask  string `json:"source_mask,omitempty"`
	DestAddr    string `json:"dest_addr"`
	DestMask    string `json:"dest_mask,omitempty"`
	DestPort    string `json:"dest_port,omitempty"`
	PortOp      string `json:"port_op,omitempty"`
	PortEnd     string `json:"port_end,omitempty"`
	ObjectGroup string `json:"object_group,omitempty"`
	HitCount    int    `json:"hit_count"`
	Logging     bool   `json:"logging"`
}

// ASAInterface represents a parsed nameif/IP mapping.
type ASAInterface struct {
	Name        string `json:"name"`
	Nameif      string `json:"nameif"`
	IP          string `json:"ip"`
	Mask        string `json:"mask"`
	SecurityLvl int    `json:"security_level"`
}

// ASAConnection represents an active connection through the ASA.
type ASAConnection struct {
	Protocol   string `json:"protocol"`
	SourceIP   string `json:"source_ip"`
	SourcePort int    `json:"source_port"`
	DestIP     string `json:"dest_ip"`
	DestPort   int    `json:"dest_port"`
	Flags      string `json:"flags,omitempty"`
	IdleTime   string `json:"idle_time,omitempty"`
}

// ASARoute represents a routing table entry.
type ASARoute struct {
	Interface   string `json:"interface"`
	Destination string `json:"destination"`
	Mask        string `json:"mask"`
	Gateway     string `json:"gateway"`
	Metric      int    `json:"metric"`
}

// ASANATRule represents a NAT translation rule.
type ASANATRule struct {
	Section      string `json:"section"`
	Interface    string `json:"interface"`
	RealSource   string `json:"real_source"`
	MappedSource string `json:"mapped_source"`
	RealDest     string `json:"real_dest,omitempty"`
	MappedDest   string `json:"mapped_dest,omitempty"`
}

// ASAObjectGroup represents a named group of objects.
type ASAObjectGroup struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// ASAAccessGroup represents the binding of an ACL to an interface.
type ASAAccessGroup struct {
	ACLName   string `json:"acl_name"`
	Interface string `json:"interface"`
	Direction string `json:"direction"`
}

// CollectionResult aggregates all parsed ASA data.
type CollectionResult struct {
	Interfaces   []ASAInterface   `json:"interfaces"`
	ACLRules     []ACLRule        `json:"acl_rules"`
	Connections  []ASAConnection  `json:"connections"`
	Routes       []ASARoute       `json:"routes"`
	NATRules     []ASANATRule     `json:"nat_rules"`
	ObjectGroups []ASAObjectGroup `json:"object_groups"`
	AccessGroups []ASAAccessGroup `json:"access_groups"`
	Version      string           `json:"version,omitempty"`
}

// ASASnapshot represents a point-in-time collection from an ASA.
type ASASnapshot struct {
	ID          string           `json:"id"`
	SiteID      string           `json:"site_id"`
	ConfigID    string           `json:"config_id"`
	CollectedAt time.Time        `json:"collected_at"`
	Duration    string           `json:"duration"`
	Result      CollectionResult `json:"result"`
}
