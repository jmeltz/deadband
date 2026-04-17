package acl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jmeltz/deadband/pkg/site"
)

// Standard OT protocol ports
var otPorts = []int{502, 44818, 102, 9600, 47808, 5007, 2222, 18245, 20000}

// Standard IT service ports
var itPorts = []int{22, 80, 443, 3389, 5900}

// Standard web ports
var webPorts = []int{80, 443}

// GenerateDefaultPolicy creates a default deny-all policy with standard OT exceptions.
func GenerateDefaultPolicy(s site.Site) Policy {
	b := make([]byte, 8)
	rand.Read(b)
	now := time.Now().UTC()

	p := Policy{
		ID:            hex.EncodeToString(b),
		SiteID:        s.ID,
		Name:          fmt.Sprintf("Default Policy — %s", s.Name),
		Rules:         []PolicyRule{},
		DefaultAction: "deny",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	zones := s.Zones
	if len(zones) == 0 {
		return p
	}

	// Build purpose index
	byPurpose := make(map[string][]string)
	for _, z := range zones {
		byPurpose[z.Purpose] = append(byPurpose[z.Purpose], z.Name)
	}

	ruleIdx := 0
	newRule := func(src, dst, action string, ports []int, desc string) PolicyRule {
		ruleIdx++
		rb := make([]byte, 4)
		rand.Read(rb)
		if ports == nil {
			ports = []int{}
		}
		return PolicyRule{
			ID:          hex.EncodeToString(rb),
			SourceZone:  src,
			DestZone:    dst,
			Ports:       ports,
			Action:      action,
			Description: desc,
		}
	}

	// OT → OT: allow OT protocol ports
	for _, src := range byPurpose["ot"] {
		for _, dst := range byPurpose["ot"] {
			if src == dst {
				continue
			}
			p.Rules = append(p.Rules, newRule(src, dst, "allow", otPorts,
				"Allow OT protocol traffic between OT zones"))
		}
	}

	// IT → DMZ: allow HTTP/HTTPS
	for _, src := range byPurpose["it"] {
		for _, dst := range byPurpose["dmz"] {
			p.Rules = append(p.Rules, newRule(src, dst, "allow", webPorts,
				"Allow IT to DMZ web traffic"))
		}
	}

	// Corporate → IT: allow standard IT ports
	for _, src := range byPurpose["corporate"] {
		for _, dst := range byPurpose["it"] {
			p.Rules = append(p.Rules, newRule(src, dst, "allow", itPorts,
				"Allow corporate to IT standard services"))
		}
	}

	// DMZ → OT: deny all (explicit, no direct path)
	for _, src := range byPurpose["dmz"] {
		for _, dst := range byPurpose["ot"] {
			p.Rules = append(p.Rules, newRule(src, dst, "deny", nil,
				"No direct DMZ to OT path — must traverse application proxy"))
		}
	}

	// Safety → * and * → Safety: deny all
	for _, safety := range byPurpose["safety"] {
		for _, z := range zones {
			if z.Name == safety {
				continue
			}
			p.Rules = append(p.Rules, newRule(safety, z.Name, "deny", nil,
				"Safety systems are isolated — no outbound traffic"))
			p.Rules = append(p.Rules, newRule(z.Name, safety, "deny", nil,
				"Safety systems are isolated — no inbound traffic"))
		}
	}

	return p
}
