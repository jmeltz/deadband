package simulate

import (
	"testing"

	"github.com/jmeltz/deadband/pkg/acl"
	"github.com/jmeltz/deadband/pkg/flow"
	"github.com/jmeltz/deadband/pkg/site"
)

var testZones = []site.Zone{
	{ID: "z1", Name: "IT", CIDRs: []string{"10.1.0.0/16"}, Purpose: "it"},
	{ID: "z2", Name: "OT", CIDRs: []string{"10.2.0.0/16"}, Purpose: "ot"},
}

func makeFlow(src, dst string, port int) flow.FlowRecord {
	return flow.FlowRecord{
		SourceAddr: src,
		DestAddr:   dst,
		DestPort:   port,
		Protocol:   flow.ProtoTCP,
		Kind:       flow.KindObserved,
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	policy := acl.Policy{
		DefaultAction: "deny",
		Rules: []acl.PolicyRule{
			{ID: "r1", SourceZone: "IT", DestZone: "OT", Ports: []int{502}, Action: "deny"},
			{ID: "r2", SourceZone: "IT", DestZone: "OT", Ports: []int{502}, Action: "allow"},
		},
	}
	flows := []flow.FlowRecord{makeFlow("10.1.0.1", "10.2.0.1", 502)}
	verdicts := Evaluate(policy, flows, testZones)
	if len(verdicts) != 1 || verdicts[0].MatchedRuleID != "r1" {
		t.Fatalf("expected first rule to match, got %+v", verdicts)
	}
	if verdicts[0].Action != flow.ActionDeny {
		t.Fatalf("expected deny, got %s", verdicts[0].Action)
	}
}

func TestEvaluate_FallsThroughToDefault(t *testing.T) {
	policy := acl.Policy{DefaultAction: "deny"}
	flows := []flow.FlowRecord{makeFlow("10.1.0.1", "10.2.0.1", 80)}
	verdicts := Evaluate(policy, flows, testZones)
	if verdicts[0].MatchedRuleID != "" {
		t.Fatalf("expected no rule match, got %s", verdicts[0].MatchedRuleID)
	}
	if verdicts[0].Action != flow.ActionDeny {
		t.Fatalf("default-action deny expected, got %s", verdicts[0].Action)
	}
}

func TestEvaluate_PortlessRuleMatchesAny(t *testing.T) {
	policy := acl.Policy{
		Rules: []acl.PolicyRule{
			{ID: "wildcard", SourceZone: "IT", DestZone: "OT", Action: "allow"},
		},
	}
	flows := []flow.FlowRecord{makeFlow("10.1.0.1", "10.2.0.1", 9999)}
	verdicts := Evaluate(policy, flows, testZones)
	if verdicts[0].MatchedRuleID != "wildcard" {
		t.Fatalf("expected wildcard match, got %+v", verdicts[0])
	}
}

func TestDiff_Buckets(t *testing.T) {
	f1 := makeFlow("10.1.0.1", "10.2.0.1", 502)
	f2 := makeFlow("10.1.0.2", "10.2.0.2", 80)
	f3 := makeFlow("10.1.0.3", "10.2.0.3", 443)

	current := []FlowVerdict{
		{Flow: f1, Action: flow.ActionPermit},
		{Flow: f2, Action: flow.ActionDeny},
		{Flow: f3, Action: flow.ActionPermit},
	}
	planned := []FlowVerdict{
		{Flow: f1, Action: flow.ActionDeny},
		{Flow: f2, Action: flow.ActionPermit},
		{Flow: f3, Action: flow.ActionPermit},
	}
	diff := Diff(current, planned)
	if len(diff.NewlyDenied) != 1 || diff.NewlyDenied[0].Flow.DestPort != 502 {
		t.Fatalf("newly denied mismatch: %+v", diff.NewlyDenied)
	}
	if len(diff.NewlyAllowed) != 1 || diff.NewlyAllowed[0].Flow.DestPort != 80 {
		t.Fatalf("newly allowed mismatch: %+v", diff.NewlyAllowed)
	}
	if diff.Unchanged.Count != 1 {
		t.Fatalf("expected 1 unchanged, got %d", diff.Unchanged.Count)
	}
}

func TestDiff_MismatchedLengthsReturnEmpty(t *testing.T) {
	diff := Diff([]FlowVerdict{{Action: flow.ActionPermit}}, nil)
	if diff.Unchanged.Count != 0 || len(diff.NewlyDenied) != 0 || len(diff.NewlyAllowed) != 0 {
		t.Fatalf("expected empty on mismatch, got %+v", diff)
	}
}

func TestSummarize_CountsByKind(t *testing.T) {
	verdicts := []FlowVerdict{
		{Flow: flow.FlowRecord{Kind: flow.KindObserved}, Action: flow.ActionPermit},
		{Flow: flow.FlowRecord{Kind: flow.KindImplied}, Action: flow.ActionDeny},
		{Flow: flow.FlowRecord{Kind: flow.KindImplied}, Action: flow.ActionPermit},
	}
	s := Summarize(verdicts)
	if s.Total != 3 || s.Permit != 2 || s.Deny != 1 || s.Implied != 2 {
		t.Fatalf("summarize mismatch: %+v", s)
	}
}
