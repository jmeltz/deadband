package matcher

import (
	"path"
	"strings"
)

func normalizeModel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	// Strip trailing revision suffix like /D, /B, /A
	if idx := strings.LastIndex(s, "/"); idx > 0 {
		suffix := s[idx+1:]
		if len(suffix) <= 2 {
			s = s[:idx]
		}
	}
	return s
}

// modelFamilyExpansions maps hardware model prefixes to broader software/product
// family strings used in CISA advisories (e.g. B&R X20CP -> Automation Runtime,
// Beckhoff CX -> TwinCAT, Schneider ACRC -> InRow / Network Management Card).
var modelFamilyExpansions = []struct {
	prefix  string
	aliases []string
}{
	{"x20cp", []string{"automationruntime", "systemdiagnosticsmanager"}},
	{"cx5", []string{"twincat"}},
	{"cx2", []string{"twincat"}},
	{"cx8", []string{"twincat"}},
	{"cx9", []string{"twincat"}},
	{"acrc", []string{"inrow", "networkmanagementcard"}},
	{"acrd", []string{"inrow", "networkmanagementcard"}},
	{"ap96", []string{"networkmanagementcard", "smart-ups"}},
	{"ak-sm8", []string{"ak-sm800a", "ak-sm8xxa"}},
	{"xweb", []string{"xwebpro", "xwebevo"}},
	{"intellislot", []string{"unity", "rdu101"}},
}

func candidateModelKeys(invNorm string) []string {
	keys := []string{invNorm}
	for _, exp := range modelFamilyExpansions {
		if strings.Contains(invNorm, exp.prefix) {
			keys = append(keys, exp.aliases...)
		}
	}
	return keys
}

func ModelMatches(inventoryModel string, advisoryProducts []string) (bool, Confidence) {
	invNorm := normalizeModel(inventoryModel)
	if invNorm == "" {
		return false, ConfidenceLow
	}

	keys := candidateModelKeys(invNorm)
	bestConfidence := ConfidenceLow
	matched := false

	for _, prod := range advisoryProducts {
		prodNorm := normalizeModel(prod)
		if prodNorm == "" {
			continue
		}

		// Exact match on primary normalized model
		if invNorm == prodNorm {
			return true, ConfidenceHigh
		}

		for _, key := range keys {
			if strings.Contains(key, prodNorm) || strings.Contains(prodNorm, key) {
				matched = true
				if bestConfidence != ConfidenceHigh {
					bestConfidence = ConfidenceMedium
				}
				break
			}
		}

		// Glob match for wildcard patterns like 1756-L8* or AK-SM 8*
		if strings.Contains(prodNorm, "*") || strings.Contains(prodNorm, "?") {
			if ok, _ := path.Match(prodNorm, invNorm); ok {
				matched = true
			}
		}
	}

	return matched, bestConfidence
}
