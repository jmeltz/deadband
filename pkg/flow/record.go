package flow

import (
	"strconv"
	"time"
)

// FlowRecord is the canonical shape every flow source produces. Observed flows
// come from firewall/SIEM telemetry; implied flows are synthesized from posture
// scans to answer "if this port is open and this rule would permit it, here is
// the traffic we would expect."
type FlowRecord struct {
	ObservedAt      time.Time         `json:"observed_at"`
	IngestedAt      time.Time         `json:"ingested_at"`
	SourceAddr      string            `json:"source_addr"`
	DestAddr        string            `json:"dest_addr"`
	DestPort        int               `json:"dest_port"`
	Protocol        string            `json:"protocol"`
	SourceZone      string            `json:"source_zone"`
	DestZone        string            `json:"dest_zone"`
	ConnectionCount int               `json:"connection_count"`
	Action          string            `json:"action"`
	Kind            string            `json:"kind"`
	SourceID        string            `json:"source_id"`
	SourceHash      string            `json:"source_hash"`
	Enrichment      map[string]string `json:"enrichment,omitempty"`
}

const (
	KindObserved = "observed"
	KindImplied  = "implied"

	ActionPermit = "permit"
	ActionDeny   = "deny"

	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoICMP = "icmp"
)

// Key returns a stable identity for deduping and diffing flows. Two flows with
// the same key describe the same logical traffic regardless of source.
func (r FlowRecord) Key() string {
	return r.SourceAddr + "|" + r.DestAddr + "|" + strconv.Itoa(r.DestPort) + "|" + r.Protocol
}
