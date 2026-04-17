package posture

// RiskReduction describes how much risk a single control mitigates.
type RiskReduction struct {
	ControlID string  `json:"control_id"`
	Factor    float64 `json:"factor"` // 0.0-1.0 fraction of risk this control mitigates
}

// WhatIfResult is the output of a risk simulation.
type WhatIfResult struct {
	OriginalScore  float64         `json:"original_score"`
	SimulatedScore float64         `json:"simulated_score"`
	Delta          float64         `json:"delta"`
	Applied        []string        `json:"applied"`
	Planned        []string        `json:"planned"`
	PlannedScore   float64         `json:"planned_score"` // score if planned controls were also applied
	PlannedDelta   float64         `json:"planned_delta"`
	Reductions     []RiskReduction `json:"reductions"`
}

// controlReductionFactors maps control IDs to their risk reduction factor.
// These are static estimates based on the relative impact each control type has.
var controlReductionFactors = map[string]float64{
	// Network segmentation controls — biggest risk reducer for mixed subnets
	"62443-3-3 SR 5.1": 0.40,
	"PR.IR-01":         0.40,
	"CIP-005-7 R1":     0.40,

	// Zone boundary protection
	"62443-3-3 SR 5.2": 0.15,

	// Zone/conduit design
	"62443-3-2 ZCR 3.1": 0.25,

	// Remote access controls
	"62443-3-3 SR 1.13": 0.25,
	"PR.AA-06":          0.25,
	"CIP-005-7 R2":      0.25,

	// MFA
	"CIP-005-7 R2.4": 0.10,

	// Session termination
	"62443-3-3 SR 2.6": 0.05,

	// Network monitoring
	"DE.CM-01": 0.10,

	// Communication restrictions
	"62443-3-3 SR 5.3": 0.20,

	// Network communication mapping
	"ID.AM-03": 0.10,

	// Deny-by-default access
	"CIP-005-7 R1.3": 0.20,

	// Asset inventory
	"62443-2-1 5.5": 0.10,
	"ID.AM-01":      0.10,

	// Least functionality / hardening
	"62443-3-3 SR 7.7": 0.20,
	"PR.PS-01":         0.20,
	"CIP-007-7 R1":     0.20,

	// SMB-specific integrity
	"62443-3-3 SR 3.4": 0.15,

	// Network/security config monitoring
	"62443-3-3 SR 7.6": 0.10,

	// Non-essential functionality
	"62443-4-2 CR 2.12": 0.15,

	// Communication integrity / port security
	"62443-3-3 SR 3.1": 0.10,

	// NAC
	"PR.IR-02": 0.15,

	// Config monitoring (NERC CIP)
	"CIP-010-4 R2": 0.10,
}

// WhatIf simulates the risk score reduction from applied/planned control states.
// It uses multiplicative reduction: 1 - (1-r1)*(1-r2)*... capped at 0.90 total.
func WhatIf(originalScore float64, findings []Finding, states []ControlState) WhatIfResult {
	result := WhatIfResult{
		OriginalScore: originalScore,
		Applied:       []string{},
		Planned:       []string{},
		Reductions:    []RiskReduction{},
	}

	// Build lookup of control states by finding_type+control_id
	stateMap := make(map[string]string) // key -> status
	for _, cs := range states {
		key := cs.FindingType + "|" + cs.ControlID
		stateMap[key] = cs.Status
	}

	// Collect reduction factors for applied and planned controls
	var appliedFactors []RiskReduction
	var plannedFactors []RiskReduction

	for _, f := range findings {
		for _, c := range f.Controls {
			key := f.Type + "|" + c.ControlID
			status, exists := stateMap[key]
			if !exists {
				continue
			}

			factor, hasFactor := controlReductionFactors[c.ControlID]
			if !hasFactor {
				factor = 0.05 // default small reduction for unknown controls
			}

			switch status {
			case "applied":
				appliedFactors = append(appliedFactors, RiskReduction{
					ControlID: c.ControlID,
					Factor:    factor,
				})
				result.Applied = append(result.Applied, c.ControlID)
			case "planned":
				plannedFactors = append(plannedFactors, RiskReduction{
					ControlID: c.ControlID,
					Factor:    factor,
				})
				result.Planned = append(result.Planned, c.ControlID)
			}
		}
	}

	// Deduplicate by control ID (same control may appear in multiple findings)
	appliedFactors = dedup(appliedFactors)
	plannedFactors = dedup(plannedFactors)
	result.Reductions = appliedFactors

	// Compute applied reduction (multiplicative)
	appliedReduction := multiplicativeReduction(appliedFactors)
	result.SimulatedScore = originalScore * (1 - appliedReduction)
	result.Delta = result.SimulatedScore - originalScore

	// Compute planned reduction (applied + planned combined)
	allFactors := append(appliedFactors, plannedFactors...)
	allFactors = dedup(allFactors)
	fullReduction := multiplicativeReduction(allFactors)
	result.PlannedScore = originalScore * (1 - fullReduction)
	result.PlannedDelta = result.PlannedScore - originalScore

	return result
}

// multiplicativeReduction computes total reduction: 1 - (1-r1)*(1-r2)*... capped at 0.90.
func multiplicativeReduction(factors []RiskReduction) float64 {
	if len(factors) == 0 {
		return 0
	}

	remaining := 1.0
	for _, f := range factors {
		remaining *= (1 - f.Factor)
	}
	reduction := 1 - remaining

	if reduction > 0.90 {
		reduction = 0.90
	}
	return reduction
}

// dedup removes duplicate control IDs, keeping the first occurrence.
func dedup(factors []RiskReduction) []RiskReduction {
	seen := make(map[string]bool)
	out := make([]RiskReduction, 0, len(factors))
	for _, f := range factors {
		if !seen[f.ControlID] {
			seen[f.ControlID] = true
			out = append(out, f)
		}
	}
	return out
}
