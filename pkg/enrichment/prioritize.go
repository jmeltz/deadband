package enrichment

// ComputeRiskScore produces a composite risk score (0–100) that prioritizes
// real-world exploitation data over raw CVSS:
//
//	KEV + ransomware = 100
//	KEV (no ransomware) = 90
//	EPSS × 80 (capped at 80)
//	CVSS × 7 (capped at 70, only when no EPSS)
//
// When both EPSS and CVSS are available, EPSS dominates.
func ComputeRiskScore(kev, kevRansomware bool, epss, cvss float64) float64 {
	if kev && kevRansomware {
		return 100
	}
	if kev {
		return 90
	}

	// EPSS-based scoring
	if epss > 0 {
		score := epss * 80
		if score > 80 {
			score = 80
		}
		return score
	}

	// CVSS fallback
	if cvss > 0 {
		score := cvss * 7
		if score > 70 {
			score = 70
		}
		return score
	}

	return 0
}
