package asa

import "fmt"

// Collect runs all read-only show commands and parses the output.
func Collect(client *Client, progress func(string)) (*CollectionResult, error) {
	result := &CollectionResult{}

	log := func(format string, args ...any) {
		if progress != nil {
			progress(fmt.Sprintf(format, args...))
		}
	}

	// show version
	log("Running: show version")
	out, err := client.Execute("show version")
	if err != nil {
		log("Warning: show version failed: %v", err)
	} else {
		result.Version = ParseVersion(out)
		log("Version: %s", result.Version)
	}

	// show interface
	log("Running: show interface")
	ifaceOut, err := client.Execute("show interface")
	if err != nil {
		log("Warning: show interface failed: %v", err)
	}

	// show nameif
	log("Running: show nameif")
	nameifOut, err := client.Execute("show nameif")
	if err != nil {
		log("Warning: show nameif failed: %v", err)
	}

	if ifaceOut != "" {
		result.Interfaces = ParseInterfaces(ifaceOut, nameifOut)
		log("Parsed %d interfaces", len(result.Interfaces))
	}

	// show access-list
	log("Running: show access-list")
	out, err = client.Execute("show access-list")
	if err != nil {
		log("Warning: show access-list failed: %v", err)
	} else {
		result.ACLRules = ParseACLRules(out)
		log("Parsed %d ACL rules", len(result.ACLRules))
	}

	// show conn all
	log("Running: show conn all")
	out, err = client.Execute("show conn all")
	if err != nil {
		log("Warning: show conn failed: %v", err)
	} else {
		result.Connections = ParseConnections(out)
		log("Parsed %d connections", len(result.Connections))
	}

	// show object-group
	log("Running: show object-group")
	out, err = client.Execute("show object-group")
	if err != nil {
		log("Warning: show object-group failed: %v", err)
	} else {
		result.ObjectGroups = ParseObjectGroups(out)
		log("Parsed %d object groups", len(result.ObjectGroups))
	}

	// show route
	log("Running: show route")
	out, err = client.Execute("show route")
	if err != nil {
		log("Warning: show route failed: %v", err)
	} else {
		result.Routes = ParseRoutes(out)
		log("Parsed %d routes", len(result.Routes))
	}

	// show access-group
	log("Running: show access-group")
	out, err = client.Execute("show access-group")
	if err != nil {
		log("Warning: show access-group failed: %v", err)
	} else {
		result.AccessGroups = ParseAccessGroups(out)
		log("Parsed %d access-group bindings", len(result.AccessGroups))
	}

	// show nat detail
	log("Running: show nat detail")
	out, err = client.Execute("show nat detail")
	if err != nil {
		log("Warning: show nat detail failed: %v", err)
	} else {
		result.NATRules = ParseNATRules(out)
		log("Parsed %d NAT rules", len(result.NATRules))
	}

	return result, nil
}
