package flow

import (
	"testing"
	"time"

	"github.com/jmeltz/deadband/pkg/posture"
	"github.com/jmeltz/deadband/pkg/site"
)

var impliedZones = []site.Zone{
	{ID: "z1", Name: "IT", CIDRs: []string{"10.1.0.0/24"}, Purpose: "it"},
	{ID: "z2", Name: "OT", CIDRs: []string{"10.2.0.0/24"}, Purpose: "ot"},
}

func host(ip string, ports ...int) posture.ClassifiedHost {
	return posture.ClassifiedHost{IP: ip, OpenPorts: ports}
}

func TestSynthesizeImplied_BasicTuples(t *testing.T) {
	report := posture.PostureReport{
		ID:        "p1",
		ScannedAt: time.Now(),
		Subnets: []posture.SubnetAnalysis{
			{Subnet: "10.1.0.0/24", Hosts: []posture.ClassifiedHost{host("10.1.0.1")}},
			{Subnet: "10.2.0.0/24", Hosts: []posture.ClassifiedHost{host("10.2.0.1", 502, 44818)}},
		},
	}
	rules := []PolicyRuleAdapter{
		{ID: "r1", SourceZone: "IT", DestZone: "OT", Ports: []int{502}},
	}
	implied := SynthesizeImplied(rules, report, impliedZones)
	if len(implied) != 1 {
		t.Fatalf("expected 1 tuple (only port 502 opens), got %d: %+v", len(implied), implied)
	}
	if implied[0].Kind != KindImplied {
		t.Fatalf("expected kind=implied, got %s", implied[0].Kind)
	}
	if implied[0].DestPort != 502 {
		t.Fatalf("expected port 502, got %d", implied[0].DestPort)
	}
}

func TestSynthesizeImplied_RuleWithoutPortsMatchesAll(t *testing.T) {
	report := posture.PostureReport{
		Subnets: []posture.SubnetAnalysis{
			{Hosts: []posture.ClassifiedHost{host("10.1.0.1")}},
			{Hosts: []posture.ClassifiedHost{host("10.2.0.1", 22, 80, 502)}},
		},
	}
	rules := []PolicyRuleAdapter{
		{ID: "wild", SourceZone: "IT", DestZone: "OT"},
	}
	implied := SynthesizeImplied(rules, report, impliedZones)
	if len(implied) != 3 {
		t.Fatalf("expected 3 tuples (port-less rule allows all open ports), got %d", len(implied))
	}
}

func TestSynthesizeImplied_CollapsesHugeFanout(t *testing.T) {
	// 100 src × 100 dst × 1 port = 10000 tuples, beyond ImpliedFanoutLimit(1000).
	srcHosts := make([]posture.ClassifiedHost, 100)
	for i := range srcHosts {
		srcHosts[i] = host("10.1.0." + itoa(i))
	}
	dstHosts := make([]posture.ClassifiedHost, 100)
	for i := range dstHosts {
		dstHosts[i] = host("10.2.0."+itoa(i), 502)
	}
	report := posture.PostureReport{
		ID: "p2",
		Subnets: []posture.SubnetAnalysis{
			{Hosts: srcHosts},
			{Hosts: dstHosts},
		},
	}
	rules := []PolicyRuleAdapter{
		{ID: "r", SourceZone: "IT", DestZone: "OT", Ports: []int{502}},
	}
	implied := SynthesizeImplied(rules, report, impliedZones)
	if len(implied) != 1 {
		t.Fatalf("expected 1 collapsed record, got %d", len(implied))
	}
	if implied[0].Enrichment["collapsed"] != "true" {
		t.Fatalf("expected collapsed=true, got %+v", implied[0].Enrichment)
	}
	if implied[0].Enrichment["tuple_count"] == "" {
		t.Fatalf("expected tuple_count to be set")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
