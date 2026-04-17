package asa

import (
	"regexp"
	"strconv"
	"strings"
)

// ParseVersion extracts the ASA software version from "show version" output.
func ParseVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Software Version") || strings.Contains(line, "Cisco Adaptive Security Appliance Software Version") {
			if idx := strings.LastIndex(line, " "); idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

// ParseInterfaces parses "show interface" + "show nameif" output.
func ParseInterfaces(ifaceOutput, nameifOutput string) []ASAInterface {
	// Parse nameif for security levels
	secLevels := make(map[string]int)
	nameifMap := make(map[string]string)
	for _, line := range strings.Split(nameifOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			hw := fields[0]
			name := fields[1]
			if level, err := strconv.Atoi(fields[2]); err == nil {
				secLevels[name] = level
				nameifMap[hw] = name
			}
		}
	}

	var interfaces []ASAInterface
	var current *ASAInterface

	for _, line := range strings.Split(ifaceOutput, "\n") {
		line = strings.TrimRight(line, "\r")

		if strings.HasPrefix(line, "Interface ") && !strings.HasPrefix(line, "  ") {
			if current != nil {
				interfaces = append(interfaces, *current)
			}
			hw := strings.Fields(line)[1]
			hw = strings.Trim(hw, "\"")
			current = &ASAInterface{
				Name:        hw,
				Nameif:      nameifMap[hw],
				SecurityLvl: secLevels[nameifMap[hw]],
			}
			continue
		}

		if current == nil {
			continue
		}

		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "IP address") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				current.IP = parts[2]
				current.IP = strings.TrimSuffix(current.IP, ",")
			}
			re := regexp.MustCompile(`subnet mask\s+([\d.]+)`)
			if m := re.FindStringSubmatch(trimmed); len(m) > 1 {
				current.Mask = m[1]
			}
		}

		if strings.HasPrefix(trimmed, "Nameif") || strings.HasPrefix(trimmed, "nameif") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				current.Nameif = parts[1]
			}
		}

		if strings.HasPrefix(trimmed, "Security level") || strings.HasPrefix(trimmed, "security-level") {
			re := regexp.MustCompile(`(\d+)`)
			if m := re.FindString(trimmed); m != "" {
				if level, err := strconv.Atoi(m); err == nil {
					current.SecurityLvl = level
				}
			}
		}
	}

	if current != nil {
		interfaces = append(interfaces, *current)
	}

	return interfaces
}

// ParseACLRules parses "show access-list" output.
func ParseACLRules(output string) []ACLRule {
	var rules []ACLRule
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(trimmed, "cached ACL log flows") ||
			strings.Contains(trimmed, " elements;") || strings.Contains(trimmed, " remark ") ||
			strings.Contains(trimmed, " standard ") || !strings.Contains(trimmed, " extended ") {
			continue
		}
		rule := parseACLLine(trimmed)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}
	return rules
}

func parseACLLine(line string) *ACLRule {
	rule := &ACLRule{}
	tokens := tokenize(line)
	if len(tokens) < 6 {
		return nil
	}

	i := 0

	if tokens[i] != "access-list" {
		return nil
	}
	i++

	rule.Name = tokens[i]
	i++

	// "line" <number>
	if i < len(tokens) && tokens[i] == "line" {
		i++
		if i < len(tokens) {
			rule.Line, _ = strconv.Atoi(tokens[i])
			i++
		}
	}

	// "extended"
	if i < len(tokens) && tokens[i] == "extended" {
		i++
	}

	// action
	if i < len(tokens) {
		rule.Action = tokens[i]
		i++
	}

	// protocol
	if i < len(tokens) {
		if (tokens[i] == "object-group" || tokens[i] == "object") && i+1 < len(tokens) {
			rule.Protocol = "object-group:" + tokens[i+1]
			i += 2
		} else {
			rule.Protocol = tokens[i]
			i++
		}
	}

	// source address
	var srcMask string
	i = parseAddress(tokens, i, &rule.SourceAddr, &srcMask)
	rule.SourceMask = srcMask

	// source port (for tcp/udp)
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		var srcPort string
		i = parsePort(tokens, i, &srcPort)
	}

	// destination address
	var dstMask string
	i = parseAddress(tokens, i, &rule.DestAddr, &dstMask)
	rule.DestMask = dstMask

	// destination port
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		i = parsePort(tokens, i, &rule.DestPort)

		// Parse port operator
		if rule.DestPort != "" {
			parts := strings.Fields(rule.DestPort)
			if len(parts) >= 1 {
				rule.PortOp = parts[0]
				if len(parts) >= 3 && parts[0] == "range" {
					rule.PortEnd = parts[2]
					rule.DestPort = parts[1]
				} else if len(parts) >= 2 {
					rule.DestPort = parts[1]
				}
			}
		}
	}

	// hitcnt, logging, etc.
	for j := i; j < len(tokens); j++ {
		tok := tokens[j]
		if strings.HasPrefix(tok, "(hitcnt=") {
			cnt := strings.TrimPrefix(tok, "(hitcnt=")
			cnt = strings.TrimSuffix(cnt, ")")
			rule.HitCount, _ = strconv.Atoi(cnt)
		}
		if tok == "log" {
			rule.Logging = true
		}
	}

	return rule
}

func parseAddress(tokens []string, i int, addr, mask *string) int {
	if i >= len(tokens) {
		return i
	}
	switch tokens[i] {
	case "any", "any4", "any6":
		*addr = "any"
		return i + 1
	case "host":
		i++
		if i < len(tokens) {
			*addr = tokens[i]
			*mask = "255.255.255.255"
			return i + 1
		}
		return i
	case "object-group", "object":
		i++
		if i < len(tokens) {
			*addr = "object-group:" + tokens[i]
			return i + 1
		}
		return i
	case "interface":
		i++
		if i < len(tokens) {
			*addr = "interface:" + tokens[i]
			return i + 1
		}
		return i
	default:
		*addr = tokens[i]
		i++
		if i < len(tokens) && isIPv4(tokens[i]) {
			*mask = tokens[i]
			i++
		}
		return i
	}
}

func parsePort(tokens []string, i int, port *string) int {
	if i >= len(tokens) {
		return i
	}
	switch tokens[i] {
	case "eq":
		i++
		if i < len(tokens) {
			*port = "eq " + tokens[i]
			return i + 1
		}
	case "range":
		i++
		if i+1 < len(tokens) {
			*port = "range " + tokens[i] + " " + tokens[i+1]
			return i + 2
		}
	case "gt":
		i++
		if i < len(tokens) {
			*port = "gt " + tokens[i]
			return i + 1
		}
	case "lt":
		i++
		if i < len(tokens) {
			*port = "lt " + tokens[i]
			return i + 1
		}
	case "neq":
		i++
		if i < len(tokens) {
			*port = "neq " + tokens[i]
			return i + 1
		}
	case "object-group":
		i++
		if i < len(tokens) {
			*port = "object-group:" + tokens[i]
			return i + 1
		}
	}
	return i
}

func tokenize(line string) []string {
	var tokens []string
	inParen := false
	var current strings.Builder
	for _, ch := range line {
		switch {
		case ch == '(':
			inParen = true
			current.WriteRune(ch)
		case ch == ')':
			inParen = false
			current.WriteRune(ch)
			tokens = append(tokens, current.String())
			current.Reset()
		case ch == ' ' || ch == '\t':
			if inParen {
				current.WriteRune(ch)
			} else if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// ParseConnections parses "show conn" output.
var connRe = regexp.MustCompile(
	`(?i)(TCP|UDP)\s+\S+\s+([\d.]+):(\d+)\s+\S+\s+([\d.]+):(\d+),\s*idle\s+(\S+),.*?flags\s+(\S+)`,
)

func ParseConnections(output string) []ASAConnection {
	var conns []ASAConnection
	for _, line := range strings.Split(output, "\n") {
		m := connRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		srcPort, _ := strconv.Atoi(m[3])
		dstPort, _ := strconv.Atoi(m[5])
		conns = append(conns, ASAConnection{
			Protocol:   strings.ToUpper(m[1]),
			SourceIP:   m[2],
			SourcePort: srcPort,
			DestIP:     m[4],
			DestPort:   dstPort,
			IdleTime:   m[6],
			Flags:      m[7],
		})
	}
	return conns
}

// ParseObjectGroups parses "show object-group" output.
func ParseObjectGroups(output string) []ASAObjectGroup {
	var groups []ASAObjectGroup
	var current *ASAObjectGroup

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "object-group ") {
			if current != nil {
				groups = append(groups, *current)
			}
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				current = &ASAObjectGroup{
					Type: parts[1],
					Name: parts[2],
				}
			}
			continue
		}

		if current != nil && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			current.Members = append(current.Members, trimmed)
		} else if !strings.HasPrefix(trimmed, "object-group ") {
			if current != nil {
				groups = append(groups, *current)
				current = nil
			}
		}
	}

	if current != nil {
		groups = append(groups, *current)
	}

	return groups
}

// ParseRoutes parses "show route" output.
var routeRe = regexp.MustCompile(
	`^([A-Z*]+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+\[(\d+)/(\d+)\]\s+via\s+([\d.]+),\s+(\S+)|\s+is directly connected,\s+(\S+))`,
)

func ParseRoutes(output string) []ASARoute {
	var routes []ASARoute
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "Codes:") || strings.TrimSpace(line) == "" {
			continue
		}

		m := routeRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		route := ASARoute{
			Destination: m[2],
			Mask:        m[3],
		}

		if m[6] != "" {
			route.Metric, _ = strconv.Atoi(m[5])
			route.Gateway = m[6]
			route.Interface = m[7]
		} else if m[8] != "" {
			route.Interface = m[8]
		}

		routes = append(routes, route)
	}
	return routes
}

// ParseAccessGroups parses "show access-group" output.
var accessGroupRe = regexp.MustCompile(`access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)`)

func ParseAccessGroups(output string) []ASAAccessGroup {
	var bindings []ASAAccessGroup
	for _, line := range strings.Split(output, "\n") {
		if m := accessGroupRe.FindStringSubmatch(line); m != nil {
			bindings = append(bindings, ASAAccessGroup{
				ACLName:   m[1],
				Direction: m[2],
				Interface: m[3],
			})
		}
	}
	return bindings
}

// ParseNATRules parses "show nat detail" output.
func ParseNATRules(output string) []ASANATRule {
	var rules []ASANATRule
	var current *ASANATRule
	currentSection := ""

	sectionRe := regexp.MustCompile(`(?i)(Manual|Auto)\s+NAT\s+Policies`)
	lineNumRe := regexp.MustCompile(`^\s*\d+\s+\((\S+)\)\s+to\s+\((\S+)\)`)
	sourceRe := regexp.MustCompile(`Source\s+-\s+Origin:\s+(.+?),\s+Translated:\s+(.+)`)
	destRe := regexp.MustCompile(`Destination\s+-\s+Origin:\s+(.+?),\s+Translated:\s+(.+)`)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")

		if m := sectionRe.FindStringSubmatch(line); m != nil {
			currentSection = m[1]
			continue
		}

		if m := lineNumRe.FindStringSubmatch(line); m != nil {
			if current != nil {
				rules = append(rules, *current)
			}
			current = &ASANATRule{
				Section:   currentSection,
				Interface: m[1],
			}
			continue
		}

		if current == nil {
			continue
		}

		if m := sourceRe.FindStringSubmatch(line); m != nil {
			current.RealSource = strings.TrimSpace(m[1])
			current.MappedSource = strings.TrimSpace(m[2])
		}
		if m := destRe.FindStringSubmatch(line); m != nil {
			current.RealDest = strings.TrimSpace(m[1])
			current.MappedDest = strings.TrimSpace(m[2])
		}
	}

	if current != nil {
		rules = append(rules, *current)
	}

	return rules
}
