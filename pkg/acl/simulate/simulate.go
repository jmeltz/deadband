package simulate

import (
	"fmt"
	"slices"

	"github.com/jmeltz/deadband/pkg/acl"
	"github.com/jmeltz/deadband/pkg/flow"
	"github.com/jmeltz/deadband/pkg/site"
)

// FlowVerdict is a single flow after being evaluated against a policy.
type FlowVerdict struct {
	Flow          flow.FlowRecord `json:"flow"`
	MatchedRuleID string          `json:"matched_rule_id"`
	Action        string          `json:"action"`
	Reason        string          `json:"reason"`
}

// DiffSummary counts verdicts by action for a policy run.
type DiffSummary struct {
	Total   int `json:"total"`
	Permit  int `json:"permit"`
	Deny    int `json:"deny"`
	Implied int `json:"implied"`
}

// ZoneCount is an (srcZone, dstZone, count) tuple used in unchanged aggregates.
type ZoneCount struct {
	SourceZone string `json:"source_zone"`
	DestZone   string `json:"dest_zone"`
	Count      int    `json:"count"`
}

// UnchangedAggregate is the lightweight shape returned for the "Unchanged"
// bucket — callers only need counts, not per-flow detail.
type UnchangedAggregate struct {
	Count  int         `json:"count"`
	ByZone []ZoneCount `json:"by_zone"`
}

// DiffResult buckets flow verdicts by how the planned policy changed them.
type DiffResult struct {
	NewlyDenied  []FlowVerdict      `json:"newly_denied"`
	NewlyAllowed []FlowVerdict      `json:"newly_allowed"`
	Unchanged    UnchangedAggregate `json:"unchanged"`
}

// SimulationResponse is the full server response body.
type SimulationResponse struct {
	Current DiffSummary `json:"current"`
	Planned DiffSummary `json:"planned"`
	Diff    DiffResult  `json:"diff"`
}

// Evaluate walks policy rules top-to-bottom (first match wins) and returns a
// verdict for every flow. Flows whose source/dest zones can't be resolved fall
// through to the policy's DefaultAction.
func Evaluate(policy acl.Policy, flows []flow.FlowRecord, zones []site.Zone) []FlowVerdict {
	idx := flow.BuildZoneIndex(zones)
	defaultAction := policy.DefaultAction
	if defaultAction == "" {
		defaultAction = "deny"
	}

	verdicts := make([]FlowVerdict, 0, len(flows))
	for _, f := range flows {
		srcZone := f.SourceZone
		if srcZone == "" {
			srcZone = idx.Resolve(f.SourceAddr)
		}
		dstZone := f.DestZone
		if dstZone == "" {
			dstZone = idx.Resolve(f.DestAddr)
		}

		matched := matchRule(policy, srcZone, dstZone, f.DestPort)
		var v FlowVerdict
		v.Flow = f
		if matched == nil {
			v.MatchedRuleID = ""
			v.Action = normalizeAction(defaultAction)
			v.Reason = fmt.Sprintf("no rule matched, falling through to default (%s)", v.Action)
		} else {
			v.MatchedRuleID = matched.ID
			v.Action = normalizeAction(matched.Action)
			v.Reason = describeRule(*matched)
		}
		verdicts = append(verdicts, v)
	}
	return verdicts
}

// Diff compares two sets of verdicts for the same flows and buckets them into
// newly_denied / newly_allowed / unchanged. Current and planned must be in the
// same order; callers should only pass in results from Evaluate on the same
// flow slice.
func Diff(current, planned []FlowVerdict) DiffResult {
	if len(current) != len(planned) {
		return DiffResult{}
	}

	result := DiffResult{}
	byZone := make(map[string]int)

	for i := range current {
		c := current[i]
		p := planned[i]
		switch {
		case c.Action == flow.ActionPermit && p.Action == flow.ActionDeny:
			result.NewlyDenied = append(result.NewlyDenied, p)
		case c.Action == flow.ActionDeny && p.Action == flow.ActionPermit:
			result.NewlyAllowed = append(result.NewlyAllowed, p)
		default:
			key := p.Flow.SourceZone + "|" + p.Flow.DestZone
			byZone[key]++
			result.Unchanged.Count++
		}
	}

	for key, count := range byZone {
		src, dst := splitZoneKey(key)
		result.Unchanged.ByZone = append(result.Unchanged.ByZone, ZoneCount{
			SourceZone: src,
			DestZone:   dst,
			Count:      count,
		})
	}

	sortVerdicts(result.NewlyDenied)
	sortVerdicts(result.NewlyAllowed)
	return result
}

// Summarize counts actions across a verdict slice.
func Summarize(verdicts []FlowVerdict) DiffSummary {
	var s DiffSummary
	s.Total = len(verdicts)
	for _, v := range verdicts {
		if v.Flow.Kind == flow.KindImplied {
			s.Implied++
		}
		switch v.Action {
		case flow.ActionPermit:
			s.Permit++
		case flow.ActionDeny:
			s.Deny++
		}
	}
	return s
}

func matchRule(policy acl.Policy, srcZone, dstZone string, port int) *acl.PolicyRule {
	if srcZone == "" || dstZone == "" {
		return nil
	}
	for i := range policy.Rules {
		r := &policy.Rules[i]
		if r.SourceZone != srcZone || r.DestZone != dstZone {
			continue
		}
		if len(r.Ports) == 0 || slices.Contains(r.Ports, port) {
			return r
		}
	}
	return nil
}

func normalizeAction(a string) string {
	switch a {
	case "allow", "permit":
		return flow.ActionPermit
	case "deny", "block":
		return flow.ActionDeny
	}
	return flow.ActionDeny
}

func describeRule(r acl.PolicyRule) string {
	ports := "all ports"
	if len(r.Ports) > 0 {
		ports = fmt.Sprintf("ports=%v", r.Ports)
	}
	return fmt.Sprintf("matched rule %s (%s %s→%s %s)", r.ID, r.Action, r.SourceZone, r.DestZone, ports)
}

func splitZoneKey(k string) (string, string) {
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

func sortVerdicts(v []FlowVerdict) {
	// Observed flows first (ConnectionCount desc), then implied.
	// Simple insertion-style sort; slice is typically small.
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && lessVerdict(v[j], v[j-1]); j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func lessVerdict(a, b FlowVerdict) bool {
	aObs := a.Flow.Kind == flow.KindObserved
	bObs := b.Flow.Kind == flow.KindObserved
	if aObs != bObs {
		return aObs
	}
	return a.Flow.ConnectionCount > b.Flow.ConnectionCount
}
