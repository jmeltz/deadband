package matcher

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	operatorVersionRe = regexp.MustCompile(`^([<>]=?|=)\s*(.+)$`)
	versionExtractRe  = regexp.MustCompile(`(?i)(?:fw|sw|[a-z])?\s*(\d+(?:\.\d+)*)`)
	proseLeRe         = regexp.MustCompile(`(?i)(and prior|and earlier|and before|through|or earlier|or prior)`)
	buildSeparatorRe  = regexp.MustCompile(`(?i)\s+build\s+`)
	leadingVerPrefix  = regexp.MustCompile(`(?i)^(?:fw|sw|rel\.?|rev\.?|[a-z])[\s.]*`)
	wildcardSuffixRe  = regexp.MustCompile(`(?i)\.(?:x|\*)(?:\.(?:x|\*))*$`)
)

func VersionAffected(deviceFirmware string, affectedVersions []string) (bool, Confidence) {
	if strings.TrimSpace(deviceFirmware) == "" {
		return true, ConfidenceLow
	}

	device, devErr := parseVersion(deviceFirmware)

	anyParsed := false
	bestParsedConf := ConfidenceLow
	anyMatched := false
	bestMatchedConf := ConfidenceLow

	for _, rawAV := range affectedVersions {
		av := strings.TrimSpace(rawAV)
		if av == "" {
			continue
		}

		matched, parsed, conf := evalAffectedEntry(device, devErr == nil, av)
		if !parsed {
			continue
		}
		anyParsed = true
		if confidenceRank(conf) > confidenceRank(bestParsedConf) {
			bestParsedConf = conf
		}
		if matched {
			if conf == ConfidenceHigh {
				return true, ConfidenceHigh
			}
			anyMatched = true
			if confidenceRank(conf) > confidenceRank(bestMatchedConf) {
				bestMatchedConf = conf
			}
		}
	}

	if anyMatched {
		return true, bestMatchedConf
	}
	if anyParsed {
		return false, bestParsedConf
	}

	// No version constraints parsed — flag conservatively
	if len(affectedVersions) > 0 {
		return true, ConfidenceLow
	}
	return false, ConfidenceLow
}

func evalAffectedEntry(device []int, hasDevice bool, av string) (matched bool, parsed bool, conf Confidence) {
	lowerAV := strings.ToLower(av)

	// Unbounded wildcards: "*", "all", "all versions", "vers:all/*", "vers:intdot/*"
	if av == "*" || lowerAV == "all versions" || lowerAV == "all" || strings.HasSuffix(lowerAV, "/*") {
		return true, true, ConfidenceHigh
	}

	// Strip CSAF / Package-URL version-range scheme prefix (e.g. "vers:intdot/<3.1.4024", "vers:all/<4.12")
	if strings.HasPrefix(lowerAV, "vers:") {
		if slash := strings.IndexByte(av, '/'); slash > 5 {
			av = strings.TrimSpace(av[slash+1:])
			if av == "" || av == "*" {
				return true, true, ConfidenceHigh
			}
		}
	}

	if !hasDevice {
		return false, false, ConfidenceLow
	}

	// Compound pipe-delimited constraints (CSAF vers spec & CISA ranges):
	//   - ">=5.x|<=6.5.1" -> bounded interval [5.x, 6.5.1] (AND)
	//   - ">=1.0|<1.5|>=2.0|<2.3" -> union of bounded intervals (OR of AND-pairs)
	//   - "2.10|2.11|2.12" -> discrete version list (OR)
	if strings.Contains(av, "|") {
		parts := strings.Split(av, "|")
		return evalPipeExpression(device, parts)
	}

	// Comma-separated two-sided bound (e.g. ">= 4.0, < 4.13.2")
	if strings.Contains(av, ",") {
		parts := strings.Split(av, ",")
		if len(parts) == 2 {
			m1, ok1 := evalSingleOperatorOrExact(device, strings.TrimSpace(parts[0]), false)
			m2, ok2 := evalSingleOperatorOrExact(device, strings.TrimSpace(parts[1]), false)
			if ok1 && ok2 {
				return m1 && m2, true, ConfidenceHigh
			}
		}
	}

	// Tier 1: single operator-prefixed version (e.g. <V4.0.400, <=33.011, <=3.1 Build 4022.4, <R4.2)
	if m, ok := evalSingleOperatorOrExact(device, av, false); ok {
		return m, true, ConfidenceHigh
	}

	// Tier 2: prose version extraction
	versions := versionExtractRe.FindAllStringSubmatch(av, -1)
	if len(versions) > 0 {
		boundaryStr := versions[len(versions)-1][1]
		boundary, err := parseVersion(boundaryStr)
		if err == nil {
			cmp := compareVersions(device, boundary)
			if proseLeRe.MatchString(av) {
				return cmp <= 0, true, ConfidenceMedium
			}
			if strings.Contains(strings.ToLower(av), "before") || strings.Contains(strings.ToLower(av), "prior to") {
				return cmp < 0, true, ConfidenceMedium
			}
			return cmp <= 0, true, ConfidenceMedium
		}
	}

	return false, false, ConfidenceLow
}

func isLowerBoundToken(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, ">")
}

func isUpperBoundToken(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "<")
}

func evalPipeExpression(device []int, rawParts []string) (matched bool, parsed bool, conf Confidence) {
	tokens := make([]string, 0, len(rawParts))
	for _, p := range rawParts {
		if t := strings.TrimSpace(p); t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) == 0 {
		return false, false, ConfidenceLow
	}

	anyParsed := false
	for i := 0; i < len(tokens); i++ {
		// Pair adjacent "> / >=" lower bound with "< / <=" upper bound as an AND interval
		if i+1 < len(tokens) && isLowerBoundToken(tokens[i]) && isUpperBoundToken(tokens[i+1]) {
			mLow, okLow := evalSingleOperatorOrExact(device, tokens[i], true)
			mHigh, okHigh := evalSingleOperatorOrExact(device, tokens[i+1], true)
			if okLow && okHigh {
				anyParsed = true
				if mLow && mHigh {
					return true, true, ConfidenceHigh
				}
				i++ // consumed upper bound
				continue
			}
		}

		m, ok := evalSingleOperatorOrExact(device, tokens[i], true)
		if ok {
			anyParsed = true
			if m {
				return true, true, ConfidenceHigh
			}
		}
	}

	if anyParsed {
		return false, true, ConfidenceHigh
	}
	return false, false, ConfidenceLow
}

func evalSingleOperatorOrExact(device []int, expr string, allowBareExact bool) (matched bool, ok bool) {
	expr = strings.TrimSpace(expr)
	op := ""
	verStr := expr

	if m := operatorVersionRe.FindStringSubmatch(expr); m != nil {
		op = m[1]
		verStr = strings.TrimSpace(m[2])
	} else if allowBareExact {
		// Reject prose phrases when evaluating bare tokens
		if strings.Contains(expr, " ") && !buildSeparatorRe.MatchString(expr) {
			return false, false
		}
		op = "="
	} else {
		return false, false
	}

	hasWildcardBranch := wildcardSuffixRe.MatchString(verStr)
	cleanVer := wildcardSuffixRe.ReplaceAllString(verStr, "")
	boundary, err := parseVersion(cleanVer)
	if err != nil {
		return false, false
	}

	if hasWildcardBranch {
		// e.g. "5.x" or "4.10.x": upper bound covers the entire branch (< next increment)
		upperExclusive := append([]int(nil), boundary...)
		upperExclusive[len(upperExclusive)-1]++
		switch op {
		case "=":
			return compareVersions(device, boundary) >= 0 && compareVersions(device, upperExclusive) < 0, true
		case "<=":
			return compareVersions(device, upperExclusive) < 0, true
		case ">":
			return compareVersions(device, upperExclusive) >= 0, true
		case ">=":
			return compareVersions(device, boundary) >= 0, true
		case "<":
			return compareVersions(device, boundary) < 0, true
		}
	}

	cmp := compareVersions(device, boundary)
	switch op {
	case "=":
		return cmp == 0, true
	case "<":
		return cmp < 0, true
	case "<=":
		return cmp <= 0, true
	case ">":
		return cmp > 0, true
	case ">=":
		return cmp >= 0, true
	}
	return false, false
}

func parseVersion(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, strconv.ErrSyntax
	}
	// Normalize Beckhoff/Windows style "3.1 Build 4022.4" -> "3.1.4022.4"
	s = buildSeparatorRe.ReplaceAllString(s, ".")
	// Strip leading prefixes like "V", "R", "C", "Q", "FW", "SW", "Rel."
	s = leadingVerPrefix.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)

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
