package flow

import (
	"strconv"
	"time"

	"github.com/jmeltz/deadband/pkg/posture"
	"github.com/jmeltz/deadband/pkg/site"
)

// ImpliedFanoutLimit caps the number of per-host tuples we synthesize for a
// single (srcZone, dstZone, port) triple. Beyond this, we collapse to a single
// representative record so the simulator doesn't enumerate traffic that is
// already covered by the aggregate.
const ImpliedFanoutLimit = 1000

// PolicyRuleAdapter decouples this package from pkg/acl (which imports pkg/flow
// for FlowRecord). The planner builds these from acl.PolicyRule at the call
// site so implied synthesis doesn't create an import cycle.
type PolicyRuleAdapter struct {
	ID         string
	SourceZone string
	DestZone   string
	Ports      []int
}

// SynthesizeImplied produces FlowRecords that posture data implies would be
// possible under the given rules. For each rule, we enumerate
// (srcHost, dstHost, port) tuples where the dst host has the port open.
// Tuples are collapsed per-zone-triple when fan-out exceeds ImpliedFanoutLimit.
func SynthesizeImplied(rules []PolicyRuleAdapter, report posture.PostureReport, zones []site.Zone) []FlowRecord {
	idx := BuildZoneIndex(zones)

	type hostWithZone struct {
		host posture.ClassifiedHost
		zone string
	}
	byZone := make(map[string][]hostWithZone)
	for _, sa := range report.Subnets {
		fallback := sa.Zone
		for _, h := range sa.Hosts {
			z := idx.Resolve(h.IP)
			if z == "" {
				z = fallback
			}
			if z == "" {
				continue
			}
			byZone[z] = append(byZone[z], hostWithZone{host: h, zone: z})
		}
	}

	var out []FlowRecord

	for _, rule := range rules {
		srcHosts := byZone[rule.SourceZone]
		dstHosts := byZone[rule.DestZone]
		if len(srcHosts) == 0 || len(dstHosts) == 0 {
			continue
		}

		portFilter := make(map[int]bool, len(rule.Ports))
		portMatchAll := len(rule.Ports) == 0
		for _, p := range rule.Ports {
			portFilter[p] = true
		}

		perPortTuples := make(map[int]int)
		for _, dh := range dstHosts {
			for _, port := range dh.host.OpenPorts {
				if !portMatchAll && !portFilter[port] {
					continue
				}
				perPortTuples[port] += len(srcHosts)
			}
		}

		collapsedEmitted := make(map[int]bool)

		for _, dh := range dstHosts {
			for _, port := range dh.host.OpenPorts {
				if !portMatchAll && !portFilter[port] {
					continue
				}

				if perPortTuples[port] > ImpliedFanoutLimit {
					if !collapsedEmitted[port] {
						out = append(out, collapsedRecord(rule, port, perPortTuples[port], report))
						collapsedEmitted[port] = true
					}
					continue
				}

				for _, sh := range srcHosts {
					rec := FlowRecord{
						ObservedAt:      report.ScannedAt,
						IngestedAt:      report.ScannedAt,
						SourceAddr:      sh.host.IP,
						DestAddr:        dh.host.IP,
						DestPort:        port,
						Protocol:        ProtoTCP,
						SourceZone:      rule.SourceZone,
						DestZone:        rule.DestZone,
						ConnectionCount: 0,
						Kind:            KindImplied,
						SourceID:        "posture:" + report.ID,
					}
					enrich := map[string]string{"rule_id": rule.ID}
					if dh.host.Hostname != "" {
						enrich["dst_hostname"] = dh.host.Hostname
					}
					if sh.host.Hostname != "" {
						enrich["src_hostname"] = sh.host.Hostname
					}
					rec.Enrichment = enrich
					out = append(out, rec)
				}
			}
		}
	}

	return out
}

func collapsedRecord(rule PolicyRuleAdapter, port, tupleCount int, report posture.PostureReport) FlowRecord {
	return FlowRecord{
		ObservedAt:      report.ScannedAt,
		IngestedAt:      time.Now().UTC(),
		DestPort:        port,
		Protocol:        ProtoTCP,
		SourceZone:      rule.SourceZone,
		DestZone:        rule.DestZone,
		ConnectionCount: 0,
		Kind:            KindImplied,
		SourceID:        "posture:" + report.ID,
		Enrichment: map[string]string{
			"rule_id":     rule.ID,
			"collapsed":   "true",
			"tuple_count": strconv.Itoa(tupleCount),
		},
	}
}
