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

func ModelMatches(inventoryModel string, advisoryProducts []string) (bool, Confidence) {
	invNorm := normalizeModel(inventoryModel)
	if invNorm == "" {
		return false, ConfidenceLow
	}

	bestConfidence := ConfidenceLow
	matched := false

	for _, prod := range advisoryProducts {
		prodNorm := normalizeModel(prod)
		if prodNorm == "" {
			continue
		}

		// Exact match
		if invNorm == prodNorm {
			return true, ConfidenceHigh
		}

		// Substring: advisory product contained in inventory model or vice versa
		if strings.Contains(invNorm, prodNorm) || strings.Contains(prodNorm, invNorm) {
			matched = true
			if bestConfidence != ConfidenceHigh {
				bestConfidence = ConfidenceMedium
			}
			continue
		}

		// Glob match for wildcard patterns like 1756-L8*
		if strings.Contains(prodNorm, "*") || strings.Contains(prodNorm, "?") {
			if ok, _ := path.Match(prodNorm, invNorm); ok {
				matched = true
				if bestConfidence == ConfidenceLow {
					bestConfidence = ConfidenceLow
				}
			}
		}
	}

	return matched, bestConfidence
}
