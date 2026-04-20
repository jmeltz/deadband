package flow

import (
	"net"

	"github.com/jmeltz/deadband/pkg/site"
)

// ZoneIndex is a prebuilt CIDR→zone-name lookup. Built once per call, reused
// across every flow.
type ZoneIndex struct {
	entries []zoneEntry
}

type zoneEntry struct {
	name string
	nets []*net.IPNet
}

// BuildZoneIndex parses zone CIDRs once for repeated IP lookups. Invalid CIDRs
// in the config are silently dropped — the policy layer validates user input.
func BuildZoneIndex(zones []site.Zone) ZoneIndex {
	entries := make([]zoneEntry, 0, len(zones))
	for _, z := range zones {
		nets := make([]*net.IPNet, 0, len(z.CIDRs))
		for _, cidr := range z.CIDRs {
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				nets = append(nets, n)
			}
		}
		entries = append(entries, zoneEntry{name: z.Name, nets: nets})
	}
	return ZoneIndex{entries: entries}
}

// Resolve returns the name of the first zone whose CIDR list contains ipStr,
// or "" if no zone matches (or the IP is malformed).
func (z ZoneIndex) Resolve(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, e := range z.entries {
		for _, n := range e.nets {
			if n.Contains(ip) {
				return e.name
			}
		}
	}
	return ""
}

// ZoneSize returns the total number of addresses covered by the zone's CIDRs,
// which the scoping code uses to estimate how much a broad rule could shrink.
func (z ZoneIndex) ZoneSize(zoneName string) float64 {
	var size float64
	for _, e := range z.entries {
		if e.name != zoneName {
			continue
		}
		for _, n := range e.nets {
			ones, bits := n.Mask.Size()
			size += float64(int(1) << (bits - ones))
		}
	}
	return size
}

// FillZones populates SourceZone/DestZone on any record where the source left
// them empty. Callers pass flows by pointer so this mutates in place.
func FillZones(records []FlowRecord, idx ZoneIndex) {
	for i := range records {
		if records[i].SourceZone == "" {
			records[i].SourceZone = idx.Resolve(records[i].SourceAddr)
		}
		if records[i].DestZone == "" {
			records[i].DestZone = idx.Resolve(records[i].DestAddr)
		}
	}
}
