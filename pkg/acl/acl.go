package acl

import "time"

// PolicyRule defines an allow or deny rule between two zones.
type PolicyRule struct {
	ID          string `json:"id"`
	SourceZone  string `json:"source_zone"`
	DestZone    string `json:"dest_zone"`
	Ports       []int  `json:"ports"`       // empty means all ports
	Action      string `json:"action"`      // "allow" or "deny"
	Description string `json:"description,omitempty"`
}

// Policy is a collection of zone-to-zone traffic rules for a site.
type Policy struct {
	ID            string       `json:"id"`
	SiteID        string       `json:"site_id"`
	Name          string       `json:"name"`
	Rules         []PolicyRule `json:"rules"`
	DefaultAction string       `json:"default_action"` // "deny" or "allow"
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}
