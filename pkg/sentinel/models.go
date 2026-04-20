package sentinel

import (
	"time"

	"github.com/jmeltz/deadband/pkg/flow"
)

// SentinelSnapshot is a point-in-time collection of flows pulled from a
// Sentinel workspace via KQL.
type SentinelSnapshot struct {
	ID        string             `json:"id"`
	SiteID    string             `json:"site_id"`
	ConfigID  string             `json:"config_id"`
	QueriedAt time.Time          `json:"queried_at"`
	FlowCount int                `json:"flow_count"`
	Flows     []flow.FlowRecord  `json:"flows"`
}
