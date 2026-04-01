package matcher

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	operatorVersionRe = regexp.MustCompile(`^([<>]=?)\s*[vV]?(.+)$`)
	versionExtractRe  = regexp.MustCompile(`[vV]?(\d+(?:\.\d+)*)`)
	proseLeRe         = regexp.MustCompile(`(?i)(and prior|and earlier|and before|through|or earlier|or prior)`)
)

func VersionAffected(deviceFirmware string, affectedVersions []string) (bool, Confidence) {
	if deviceFirmware == "" {
		return true, ConfidenceLow
	}

	for _, av := range affectedVersions {
		av = strings.TrimSpace(av)
		if av == "" {
			continue
		}

		// vers:all/* — all versions affected
		if strings.Contains(av, "vers:all/") || strings.EqualFold(av, "all versions") || strings.EqualFold(av, "all") {
			return true, ConfidenceHigh
		}

		// Tier 1: operator-prefixed version (e.g. <V4.0.400, <=33.011)
		if m := operatorVersionRe.FindStringSubmatch(av); m != nil {
			op := m[1]
			boundary, err := parseVersion(m[2])
			if err == nil {
				device, err := parseVersion(deviceFirmware)
				if err == nil {
					cmp := compareVersions(device, boundary)
					affected := false
					switch op {
					case "<":
						affected = cmp < 0
					case "<=":
						affected = cmp <= 0
					case ">":
						affected = cmp > 0
					case ">=":
						affected = cmp >= 0
					}
					return affected, ConfidenceHigh
				}
			}
		}

		// Tier 2: prose version extraction
		versions := versionExtractRe.FindAllStringSubmatch(av, -1)
		if len(versions) > 0 {
			// Use the last version found as the boundary
			boundaryStr := versions[len(versions)-1][1]
			boundary, err := parseVersion(boundaryStr)
			if err == nil {
				device, err := parseVersion(deviceFirmware)
				if err == nil {
					cmp := compareVersions(device, boundary)
					// Check for "and prior" / "and earlier" type language -> treat as <=
					if proseLeRe.MatchString(av) {
						return cmp <= 0, ConfidenceMedium
					}
					// Check for "before" keyword
					if strings.Contains(strings.ToLower(av), "before") {
						return cmp < 0, ConfidenceMedium
					}
					// Default: assume <= for ambiguous prose
					return cmp <= 0, ConfidenceMedium
				}
			}
		}
	}

	// No version constraints parsed — flag conservatively
	if len(affectedVersions) > 0 {
		return true, ConfidenceLow
	}
	return false, ConfidenceLow
}

func parseVersion(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "vV")
	parts := strings.Split(s, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Strip non-numeric trailing chars (e.g., "33a" -> "33")
		numStr := ""
		for _, c := range p {
			if c >= '0' && c <= '9' {
				numStr += string(c)
			} else {
				break
			}
		}
		if numStr == "" {
			continue
		}
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	if len(result) == 0 {
		return nil, strconv.ErrSyntax
	}
	return result, nil
}

func compareVersions(a, b []int) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		va, vb := 0, 0
		if i < len(a) {
			va = a[i]
		}
		if i < len(b) {
			vb = b[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}
