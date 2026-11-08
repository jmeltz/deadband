package capability

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jmeltz/deadband/pkg/query"
)

func TestExecutableRegistryMatchesActualEngine(t *testing.T) {
	r := Current()
	seen := map[string]bool{}
	executable := 0
	for _, p := range r.Profiles {
		if p.Key == "" || seen[p.Key] {
			t.Fatalf("duplicate metadata key %q", p.Key)
		}
		seen[p.Key] = true
		if !p.Executable {
			if p.WireProfileID != "" || len(p.SchemaVersions) > 0 || len(p.Transports) > 0 {
				t.Fatalf("planned capability advertises executable operations: %+v", p)
			}
			continue
		}
		executable++
		var plan query.Plan
		var err error
		if p.WireProfileID == query.ProfileModbusIdentityTCP {
			unit := 255
			plan, err = query.NewModbusLabPlan(query.Target{AssetID: "registry-check", IP: "192.0.2.1", Port: p.Transports[0].Port, UnitID: &unit, RequestedFields: p.RequestedFields})
		} else {
			plan, err = query.NewPlan([]query.Target{{AssetID: "registry-check", IP: "192.0.2.1", Port: p.Transports[0].Port, RequestedFields: p.RequestedFields}}, "enrich")
		}
		if err != nil {
			t.Fatal(err)
		}
		plan.Profile = p.WireProfileID
		plan.PlanHash, err = query.Hash(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := query.Validate(plan); err != nil {
			t.Fatalf("registry advertises unsupported profile: %v", err)
		}
	}
	if executable != 2 {
		t.Fatalf("unexpected executable profile count %d", executable)
	}
	var a, b bytes.Buffer
	if err := Write(&a); err != nil {
		t.Fatal(err)
	}
	if err := Write(&b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("nondeterministic capability artifact")
	}
	var decoded Registry
	if err := json.Unmarshal(a.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	mutated := Current()
	mutated.Profiles[0].SchemaVersions[0] = 999
	if Current().Profiles[0].SchemaVersions[0] != query.SchemaVersion {
		t.Fatal("registry data shared across callers")
	}
}
