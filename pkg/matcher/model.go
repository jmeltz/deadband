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
	{"x20cp", []string{"automationruntime", "systemdiagnosticsmanager", "x20"}},
	{"apc9", []string{"automationpc", "automationruntime", "systemdiagnosticsmanager"}},
	{"apc2", []string{"automationpc", "automationruntime", "systemdiagnosticsmanager"}},
	{"apc3", []string{"automationpc", "automationruntime", "systemdiagnosticsmanager"}},
	{"cx1", []string{"twincat"}},
	{"cx2", []string{"twincat"}},
	{"cx5", []string{"twincat"}},
	{"cx7", []string{"twincat"}},
	{"cx8", []string{"twincat"}},
	{"cx9", []string{"twincat"}},
	{"c60", []string{"twincat"}},
	{"c69", []string{"twincat"}},
	{"cp2", []string{"twincat"}},
	{"cp6", []string{"twincat"}},
	{"acrc", []string{"inrow", "networkmanagementcard", "nmc2", "nmc3"}},
	{"acrd", []string{"inrow", "networkmanagementcard", "nmc2", "nmc3"}},
	{"ap96", []string{"networkmanagementcard", "nmc2", "nmc3", "smart-ups"}},
	{"ak-sm8", []string{"ak-sm800a", "ak-sm8xxa", "systemmanager"}},
	{"xweb", []string{"xweb", "xweb300", "xweb500", "xweb300dpro", "xweb500dpro", "xweb500bpro", "xwebpro", "xwebevo"}},
	{"intellislot", []string{"unity", "is-unity", "rdu101"}},
	{"liebert", []string{"is-unity", "rdu101"}},
	{"jace", []string{"niagara", "niagaraframework"}},
	{"niagara", []string{"niagaraframework", "jace"}},
	{"cpu15", []string{"s7-1500", "simatics7-1500", "simatics7-1500cpufamily"}},
	{"cpu12", []string{"s7-1200", "simatics7-1200", "simatics7-1200cpufamily"}},
	{"cpu31", []string{"s7-300", "simatics7-300"}},
	{"cpu41", []string{"s7-400", "simatics7-400"}},
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

		// Glob match for wildcard patterns like 1756-L8*, AK-SM 8*, or digit-x placeholders like CLV65x / AK-SM 8xxA
		if strings.Contains(prodNorm, "*") || strings.Contains(prodNorm, "?") {
			if ok, _ := path.Match(prodNorm, invNorm); ok {
				matched = true
				if bestConfidence != ConfidenceHigh {
					bestConfidence = ConfidenceMedium
				}
			}
		} else if glob, hasX := modelXWildcardToGlob(prodNorm); hasX {
			if ok, _ := path.Match(glob, invNorm); ok {
				matched = true
				if bestConfidence != ConfidenceHigh {
					bestConfidence = ConfidenceMedium
				}
			}
		}
	}

	return matched, bestConfidence
}

// modelXWildcardToGlob converts OEM series placeholders where 'x' follows a digit
// (e.g. "clv65x" -> "clv65?", "clv6xx" -> "clv6??", "ak-sm8xxa" -> "ak-sm8??a")
// without altering words like "xweb" or "metasys".
func modelXWildcardToGlob(s string) (string, bool) {
	b := []byte(s)
	changed := false
	for i := 1; i < len(b); i++ {
		if b[i] == 'x' && ((b[i-1] >= '0' && b[i-1] <= '9') || b[i-1] == '?') {
			b[i] = '?'
			changed = true
		}
	}
	return string(b), changed
}
