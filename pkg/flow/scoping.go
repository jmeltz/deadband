package flow

import (
	"sort"

	"github.com/jmeltz/deadband/pkg/site"
)

// ZoneTrafficSummary aggregates flows by (source_zone, dest_zone) pair for the
// zone-matrix overlay.
type ZoneTrafficSummary struct {
	SourceZone  string `json:"source_zone"`
	DestZone    string `json:"dest_zone"`
	FlowCount   int    `json:"flow_count"`
	UniqueIPs   int    `json:"unique_ips"`
	TopPorts    []int  `json:"top_ports"`
	HasIdentity bool   `json:"has_identity"`
}

// ComputeTrafficSummary reduces a flow slice to one row per zone pair. Records
// missing a zone label fall back to CIDR resolution against the site zones.
// Flows whose source or dest can't be resolved to a zone are skipped.
func ComputeTrafficSummary(flows []FlowRecord, zones []site.Zone) []ZoneTrafficSummary {
	idx := BuildZoneIndex(zones)

	type key struct{ src, dst string }
	type stats struct {
		flowCount   int
		ips         map[string]bool
		ports       map[int]int
		hasIdentity bool
	}

	agg := make(map[key]*stats)

	for _, f := range flows {
		srcZone := f.SourceZone
		if srcZone == "" {
			srcZone = idx.Resolve(f.SourceAddr)
		}
		dstZone := f.DestZone
		if dstZone == "" {
			dstZone = idx.Resolve(f.DestAddr)
		}
		if srcZone == "" || dstZone == "" {
			continue
		}

		k := key{srcZone, dstZone}
		s, ok := agg[k]
		if !ok {
			s = &stats{ips: make(map[string]bool), ports: make(map[int]int)}
			agg[k] = s
		}
		s.flowCount += f.ConnectionCount
		s.ips[f.SourceAddr] = true
		s.ips[f.DestAddr] = true
		if f.DestPort > 0 {
			s.ports[f.DestPort] += f.ConnectionCount
		}
		if f.Enrichment["UserName"] != "" || f.Enrichment["Department"] != "" {
			s.hasIdentity = true
		}
	}

	summaries := make([]ZoneTrafficSummary, 0, len(agg))
	for k, s := range agg {
		ts := ZoneTrafficSummary{
			SourceZone:  k.src,
			DestZone:    k.dst,
			FlowCount:   s.flowCount,
			UniqueIPs:   len(s.ips),
			HasIdentity: s.hasIdentity,
		}

		type portCount struct {
			port  int
			count int
		}
		pcs := make([]portCount, 0, len(s.ports))
		for p, c := range s.ports {
			pcs = append(pcs, portCount{p, c})
		}
		sort.Slice(pcs, func(i, j int) bool { return pcs[i].count > pcs[j].count })
		for i, pc := range pcs {
			if i >= 5 {
				break
			}
			ts.TopPorts = append(ts.TopPorts, pc.port)
		}

		summaries = append(summaries, ts)
	}

	return summaries
}
