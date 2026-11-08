package posture

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/discover"
)

// Well-known ports grouped by role.
var (
	// OTPorts are probed first. These are lightweight identity-read ports
	// used by ICS, intralogistics/ASRS, and HVAC/BMS protocols.
	OTPorts = []int{
		44818, // CIP/EtherNet/IP
		102,   // S7comm
		502,   // Modbus TCP
		47808, // BACnet/IP (UDP)
		5007,  // MELSEC/SLMP
		9600,  // FINS
		18245, // GE-SRTP
		4840,  // OPC UA
		48898, // Beckhoff TwinCAT ADS
		2111,  // SICK SOPAS CoLa-A/B Aux
		2112,  // SICK SOPAS CoLa-A/B Host
		2122,  // SICK SOPAS CoLa-2
		1911,  // Tridium Niagara Fox
		4911,  // Tridium Niagara FoxS
	}

	// ITPorts are probed second and ONLY on hosts that did NOT respond
	// to any OT port. This avoids sending unnecessary IT traffic to PLCs.
	ITPorts = []int{
		22,   // SSH
		80,   // HTTP
		443,  // HTTPS
		3389, // RDP
		135,  // RPC/DCOM
		445,  // SMB
		8080, // HTTP-alt
		8443, // HTTPS-alt
		53,   // DNS
	}

	// NetworkPorts are probed alongside IT ports (same phase).
	NetworkPorts = []int{
		161, // SNMP
		23,  // Telnet
		179, // BGP
	}
)

// HostResult represents the scan results for a single IP address.
type HostResult struct {
	IP        string `json:"ip"`
	OpenPorts []int  `json:"open_ports"`
}

// ScanSubnet performs a two-phase, sensitivity-ordered host scan.
//
// Scan order (most-sensitive first):
//
//  1. OT probe phase — TCP connect to OT ports (CIP, S7, Modbus, etc.)
//     on ALL hosts. Hosts that respond are tagged as OT-positive.
//     Hosts already in the asset store are pre-tagged as OT-positive.
//
//  2. IT/Network probe phase — TCP connect to IT ports (SSH, HTTP, RDP,
//     SMB, etc.) and network ports (SNMP, Telnet, BGP) ONLY on hosts
//     that are NOT OT-positive. This protects OT controllers from
//     receiving unnecessary IT-service connection attempts.
//
// This ordering ensures PLCs and RTUs are never probed with IT port
// scans (which could trigger watchdog timers or IDS alerts on
// sensitive OT equipment), while still providing full visibility
// into non-OT endpoints sharing the same subnet.
func ScanSubnet(cidr string, timeout time.Duration, concurrency int, progress func(string)) ([]HostResult, error) {
	return ScanSubnetWithAssets(cidr, timeout, concurrency, nil, progress)
}

// ScanSubnetWithAssets is like ScanSubnet but accepts known assets to
// pre-classify OT hosts before scanning, providing an additional
// safety layer — hosts already identified as OT by prior discovery
// are never probed with IT ports even if their OT ports are down.
func ScanSubnetWithAssets(cidr string, timeout time.Duration, concurrency int, assets []asset.Asset, progress func(string)) ([]HostResult, error) {
	ips, err := discover.ExpandCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Pre-tag known OT hosts from the asset store.
	knownOT := make(map[string]bool)
	for _, a := range assets {
		if a.Protocol != "" { // has an OT protocol from prior discovery
			knownOT[a.IP] = true
		}
	}

	// ---- Phase 1: OT port probes (all hosts) ----
	if progress != nil {
		progress("Phase 1: probing " + strconv.Itoa(len(ips)) + " hosts on " + strconv.Itoa(len(OTPorts)) + " OT ports...")
	}

	otResults := scanPorts(ips, OTPorts, timeout, concurrency)

	// Build OT-positive set: known OT assets + hosts that responded to OT ports
	otPositive := make(map[string]bool)
	for ip := range knownOT {
		otPositive[ip] = true
	}
	for _, r := range otResults {
		otPositive[r.ip] = true
	}

	otPosCount := 0
	for _, ip := range ips {
		if otPositive[ip] {
			otPosCount++
		}
	}
	if progress != nil {
		progress("Phase 1 complete: " + strconv.Itoa(otPosCount) + " OT-positive hosts identified")
	}

	// ---- Phase 2: IT/Network probes (non-OT hosts only) ----
	var nonOTIPs []string
	for _, ip := range ips {
		if !otPositive[ip] {
			nonOTIPs = append(nonOTIPs, ip)
		}
	}

	itNetPorts := append(append([]int{}, ITPorts...), NetworkPorts...)

	if progress != nil {
		progress("Phase 2: probing " + strconv.Itoa(len(nonOTIPs)) + " non-OT hosts on " + strconv.Itoa(len(itNetPorts)) + " IT/network ports (skipping " + strconv.Itoa(otPosCount) + " OT hosts)...")
	}

	itResults := scanPorts(nonOTIPs, itNetPorts, timeout, concurrency)

	// ---- Merge results ----
	hostMap := make(map[string][]int)
	for _, r := range otResults {
		hostMap[r.ip] = append(hostMap[r.ip], r.port)
	}
	for _, r := range itResults {
		hostMap[r.ip] = append(hostMap[r.ip], r.port)
	}
	// Include known OT hosts that may not have any ports open right now
	for ip := range knownOT {
		if _, exists := hostMap[ip]; !exists {
			// Known OT but no ports responded — still include as alive
			hostMap[ip] = []int{}
		}
	}

	hosts := make([]HostResult, 0, len(hostMap))
	for ip, ports := range hostMap {
		hosts = append(hosts, HostResult{IP: ip, OpenPorts: ports})
	}

	if progress != nil {
		progress("Host scan complete: " + strconv.Itoa(len(hosts)) + " live hosts found")
	}

	return hosts, nil
}

// probeResult is an internal type for tracking individual port probe results.
type probeResult struct {
	ip   string
	port int
}

// scanPorts probes a set of IPs on a set of ports concurrently.
func scanPorts(ips []string, ports []int, timeout time.Duration, concurrency int) []probeResult {
	var mu sync.Mutex
	var results []probeResult

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				if !probeHostPort(ip, port, timeout) {
					return
				}

				mu.Lock()
				results = append(results, probeResult{ip: ip, port: port})
				mu.Unlock()
			}(ip, port)
		}
	}

	wg.Wait()
	return results
}

// probeHostPort checks whether port is responsive on ip, using read-only UDP
// application probes for UDP-native protocols (BACnet/47808 and SNMP/161) and
// TCP connect for TCP services.
func probeHostPort(ip string, port int, timeout time.Duration) bool {
	switch port {
	case discover.BACnetPort:
		return probeBACnetUDP(ip, port, timeout)
	case discover.SNMPPort:
		return discover.SNMPGetSysDescr(ip, port, timeout) != ""
	default:
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}
}

// probeBACnetUDP sends a minimal 8-byte read-only BACnet/IP Who-Is unicast frame
// and checks for a valid BVLC response header.
func probeBACnetUDP(ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	whoIs := []byte{0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08}
	if _, err := conn.Write(whoIs); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return false
	}
	_, payload, err := discover.ParseBVLC(buf[:n])
	return err == nil && len(payload) >= 2
}
