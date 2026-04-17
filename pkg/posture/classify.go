package posture

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/asset"
)

// DeviceClass categorises a host based on its open ports and known asset data.
type DeviceClass string

const (
	ClassOT      DeviceClass = "ot"
	ClassIT      DeviceClass = "it"
	ClassNetwork DeviceClass = "network"
	ClassUnknown DeviceClass = "unknown"
)

// ClassifiedHost combines scan results with a classification label.
type ClassifiedHost struct {
	IP          string         `json:"ip"`
	DeviceClass DeviceClass    `json:"device_class"`
	OpenPorts   []int          `json:"open_ports"`
	Services    []string       `json:"services"`
	AssetID     string         `json:"asset_id,omitempty"`
	AssetName   string         `json:"asset_name,omitempty"`
	Vendor      string         `json:"vendor,omitempty"`
	Model       string         `json:"model,omitempty"`
	Hostname    string         `json:"hostname,omitempty"`
	OSGuess     string         `json:"os_guess,omitempty"`
	Presumption string         `json:"presumption,omitempty"`
	Banners     []BannerResult `json:"banners,omitempty"`
}

// PortServiceName maps well-known ports to human-readable service labels.
var PortServiceName = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	53:    "DNS",
	80:    "HTTP",
	102:   "S7comm",
	135:   "RPC",
	161:   "SNMP",
	179:   "BGP",
	443:   "HTTPS",
	445:   "SMB",
	502:   "Modbus",
	3389:  "RDP",
	4840:  "OPC UA",
	5007:  "MELSEC",
	8080:  "HTTP-alt",
	8443:  "HTTPS-alt",
	9600:  "FINS",
	18245: "GE-SRTP",
	44818: "CIP/EIP",
	47808: "BACnet",
}

// ClassifyHosts labels each scanned host and enriches with known asset data.
// It performs follow-up protocol banner probes on non-OT hosts to extract
// hostnames, OS versions, and service identification.
func ClassifyHosts(hosts []HostResult, assets []asset.Asset) []ClassifiedHost {
	return ClassifyHostsWithProgress(hosts, assets, 3*time.Second, 32, nil)
}

// ClassifyHostsWithTimeout is like ClassifyHosts but allows configuring
// the probe timeout and concurrency.
func ClassifyHostsWithTimeout(hosts []HostResult, assets []asset.Asset, timeout time.Duration, concurrency int) []ClassifiedHost {
	return ClassifyHostsWithProgress(hosts, assets, timeout, concurrency, nil)
}

// ClassifyHostsWithProgress performs classification, SMB probing for RDP hosts,
// and protocol banner grabbing for all non-OT hosts. The progress callback
// reports phase status. OT-class hosts are excluded from all follow-up probes.
func ClassifyHostsWithProgress(hosts []HostResult, assets []asset.Asset, timeout time.Duration, concurrency int, progress func(string)) []ClassifiedHost {
	assetByIP := make(map[string]*asset.Asset, len(assets))
	for i := range assets {
		assetByIP[assets[i].IP] = &assets[i]
	}

	otSet := portSet(OTPorts)
	itSet := portSet(ITPorts)
	netSet := portSet(NetworkPorts)

	out := make([]ClassifiedHost, 0, len(hosts))
	for _, h := range hosts {
		ch := ClassifiedHost{
			IP:        h.IP,
			OpenPorts: h.OpenPorts,
			Services:  serviceNames(h.OpenPorts),
		}

		// Enrich from asset store
		if a, ok := assetByIP[h.IP]; ok {
			ch.AssetID = a.ID
			ch.AssetName = a.Name
			ch.Vendor = a.Vendor
			ch.Model = a.Model
		}

		// Classify
		hasOT := hasAnyPort(h.OpenPorts, otSet)
		hasIT := hasAnyPort(h.OpenPorts, itSet)
		hasNet := hasAnyPort(h.OpenPorts, netSet)

		switch {
		case hasOT, ch.AssetID != "":
			ch.DeviceClass = ClassOT
		case hasIT && !hasNet:
			ch.DeviceClass = ClassIT
		case hasNet && !hasIT:
			ch.DeviceClass = ClassNetwork
		case hasIT && hasNet:
			ch.DeviceClass = ClassNetwork
		default:
			ch.DeviceClass = ClassUnknown
		}

		// Port-based presumptions (will be enriched after banner phase)
		ch.Presumption = presumeIdentity(h.OpenPorts)

		out = append(out, ch)
	}

	// ---- Phase 2: SMB probe on hosts with RDP (3389) open ----
	// RDP → almost certainly Windows → SMB reveals hostname + OS version.
	smbTargets := make([]int, 0)
	for i, ch := range out {
		if portIn(ch.OpenPorts, 3389) && ch.DeviceClass != ClassOT {
			smbTargets = append(smbTargets, i)
		}
	}
	if len(smbTargets) > 0 {
		if progress != nil {
			progress(fmt.Sprintf("Probing %d RDP hosts via SMB for hostname/OS...", len(smbTargets)))
		}
		probeSMBHosts(out, smbTargets, timeout, concurrency)
	}

	// ---- Phase 3: Protocol banner probes on non-OT hosts ----
	bannerTargets := make([]int, 0)
	for i, ch := range out {
		if ch.DeviceClass == ClassOT {
			continue // Safety: never probe OT hosts
		}
		if len(ch.OpenPorts) == 0 {
			continue
		}
		bannerTargets = append(bannerTargets, i)
	}
	if len(bannerTargets) > 0 {
		if progress != nil {
			progress(fmt.Sprintf("Probing %d hosts for service banners (SSH, HTTP, SNMP, Telnet)...", len(bannerTargets)))
		}
		probeBannerHosts(out, bannerTargets, timeout, concurrency)
	}

	// Enrich presumptions with banner data
	for i := range out {
		out[i].Presumption = enrichedPresumption(out[i])
	}

	return out
}

// probeSMBHosts runs SMB probes concurrently against hosts with RDP open
// and fills in Hostname and OSGuess.
func probeSMBHosts(hosts []ClassifiedHost, indices []int, timeout time.Duration, concurrency int) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, idx := range indices {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			info, err := ProbeSMB(hosts[i].IP, timeout)
			if err != nil || info == nil {
				return
			}
			if info.Hostname != "" {
				hosts[i].Hostname = info.Hostname
			}
			if info.OSVer != "" {
				label := osVersionLabel(info.OSVer)
				if label != "" {
					hosts[i].OSGuess = label + " (" + info.OSVer + ")"
				} else {
					hosts[i].OSGuess = "Windows (" + info.OSVer + ")"
				}
			}
		}(idx)
	}
	wg.Wait()
}

// probeBannerHosts runs protocol-appropriate banner probes concurrently
// on the specified hosts. Each host is probed only for protocols it has open.
// OT hosts must be pre-filtered by the caller.
func probeBannerHosts(hosts []ClassifiedHost, indices []int, timeout time.Duration, concurrency int) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, idx := range indices {
		h := &hosts[idx]
		ps := portSet(h.OpenPorts)

		type probeJob struct {
			run func() (*BannerResult, error)
		}
		var jobs []probeJob

		// SSH
		if ps[22] {
			ip := h.IP
			jobs = append(jobs, probeJob{func() (*BannerResult, error) {
				return ProbeSSH(ip, timeout)
			}})
		}

		// HTTP ports
		for _, port := range []int{80, 443, 8080, 8443} {
			if ps[port] {
				ip, p := h.IP, port
				jobs = append(jobs, probeJob{func() (*BannerResult, error) {
					return ProbeHTTP(ip, p, timeout)
				}})
			}
		}

		// SNMP
		if ps[161] {
			ip := h.IP
			jobs = append(jobs, probeJob{func() (*BannerResult, error) {
				return ProbeSNMP(ip, timeout)
			}})
		}

		// Telnet
		if ps[23] {
			ip := h.IP
			jobs = append(jobs, probeJob{func() (*BannerResult, error) {
				return ProbeTelnet(ip, timeout)
			}})
		}

		// SMB without RDP — hosts WITH RDP already got SMB probed above
		if ps[445] && !ps[3389] {
			ip := h.IP
			i := idx
			jobs = append(jobs, probeJob{func() (*BannerResult, error) {
				info, err := ProbeSMB(ip, timeout)
				if err != nil || info == nil {
					return nil, err
				}
				// Fill hostname/OS as side-effect
				mu.Lock()
				if info.Hostname != "" {
					hosts[i].Hostname = info.Hostname
				}
				if info.OSVer != "" {
					label := osVersionLabel(info.OSVer)
					if label != "" {
						hosts[i].OSGuess = label + " (" + info.OSVer + ")"
					} else {
						hosts[i].OSGuess = "Windows (" + info.OSVer + ")"
					}
				}
				mu.Unlock()
				banner := info.Hostname
				if info.Domain != "" {
					banner += " \\ " + info.Domain
				}
				return &BannerResult{
					Port:    445,
					Proto:   "SMB",
					Banner:  banner,
					Product: "Windows SMB",
					Version: info.OSVer,
				}, nil
			}})
		}

		// Dispatch all jobs for this host
		for _, job := range jobs {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, fn func() (*BannerResult, error)) {
				defer wg.Done()
				defer func() { <-sem }()

				result, err := fn()
				if err != nil || result == nil {
					return
				}
				mu.Lock()
				hosts[i].Banners = append(hosts[i].Banners, *result)
				mu.Unlock()
			}(idx, job.run)
		}
	}
	wg.Wait()
}

// enrichedPresumption builds an identity string from banner data when
// available, falling back to the port-based presumeIdentity heuristic.
func enrichedPresumption(h ClassifiedHost) string {
	if len(h.Banners) == 0 {
		return presumeIdentity(h.OpenPorts)
	}

	bannerByProto := make(map[string]*BannerResult)
	for i := range h.Banners {
		bannerByProto[h.Banners[i].Proto] = &h.Banners[i]
	}

	var parts []string

	// OS identification from SMB probe
	if h.OSGuess != "" {
		if h.Hostname != "" {
			parts = append(parts, h.Hostname+" — "+h.OSGuess)
		} else {
			parts = append(parts, h.OSGuess)
		}
	} else if h.Hostname != "" {
		parts = append(parts, h.Hostname)
	}

	// SSH banner
	if b, ok := bannerByProto["SSH"]; ok && b.Product != "" {
		detail := b.Product
		if b.Version != "" {
			detail += " " + b.Version
		}
		parts = append(parts, detail)
	}

	// HTTP server
	for _, proto := range []string{"HTTP", "HTTPS"} {
		if b, ok := bannerByProto[proto]; ok && b.Product != "" {
			parts = append(parts, b.Product)
			break
		}
	}

	// SNMP sysDescr
	if b, ok := bannerByProto["SNMP"]; ok && b.Banner != "" {
		desc := b.Banner
		if len(desc) > 80 {
			desc = desc[:80] + "..."
		}
		parts = append(parts, desc)
	}

	// Telnet banner
	if b, ok := bannerByProto["Telnet"]; ok && b.Banner != "" {
		desc := b.Banner
		if len(desc) > 60 {
			desc = desc[:60] + "..."
		}
		parts = append(parts, desc)
	}

	if len(parts) == 0 {
		return presumeIdentity(h.OpenPorts)
	}

	return strings.Join(parts, " | ")
}

// presumeIdentity infers a host's likely identity from its open port
// combination. Returns a human-readable label or "".
func presumeIdentity(ports []int) string {
	ps := portSet(ports)

	hasRDP := ps[3389]
	hasSMB := ps[445]
	hasSSH := ps[22]
	hasHTTP := ps[80] || ps[443] || ps[8080] || ps[8443]
	hasRPC := ps[135]
	hasSNMP := ps[161]
	hasTelnet := ps[23]
	hasBGP := ps[179]
	hasDNS := ps[53]

	switch {
	// Windows endpoints
	case hasRDP && hasSMB && hasRPC:
		return "Windows workstation/server (RDP + SMB + RPC)"
	case hasRDP && hasSMB:
		return "Windows endpoint (RDP + SMB)"
	case hasRDP:
		return "Windows endpoint (RDP enabled)"

	// Domain infrastructure
	case hasSMB && hasRPC && hasDNS:
		return "Windows domain controller (SMB + RPC + DNS)"
	case hasSMB && hasRPC:
		return "Windows server (SMB + RPC)"
	case hasSMB && hasHTTP:
		return "Windows server (SMB + HTTP)"

	// Network infrastructure
	case hasSNMP && hasBGP:
		return "Network router (SNMP + BGP)"
	case hasSNMP && hasTelnet && hasHTTP:
		return "Managed network switch (SNMP + Telnet + HTTP)"
	case hasSNMP && hasTelnet:
		return "Managed network device (SNMP + Telnet)"
	case hasSNMP && hasHTTP:
		return "Managed network device (SNMP + HTTP)"
	case hasBGP:
		return "Network router (BGP)"

	// Linux/Unix servers
	case hasSSH && hasHTTP && !hasSMB:
		return "Linux/Unix server (SSH + HTTP)"
	case hasSSH && hasDNS:
		return "DNS server (SSH + DNS)"
	case hasSSH && !hasSMB && !hasRDP:
		return "Linux/Unix host (SSH)"

	// Web-only
	case hasHTTP && !hasSSH && !hasSMB && !hasSNMP:
		return "Web server / appliance (HTTP only)"

	// DNS-only
	case hasDNS && !hasSSH && !hasHTTP:
		return "DNS appliance"

	default:
		return ""
	}
}

func portSet(ports []int) map[int]bool {
	s := make(map[int]bool, len(ports))
	for _, p := range ports {
		s[p] = true
	}
	return s
}

func hasAnyPort(open []int, set map[int]bool) bool {
	for _, p := range open {
		if set[p] {
			return true
		}
	}
	return false
}

func serviceNames(ports []int) []string {
	var names []string
	for _, p := range ports {
		if n, ok := PortServiceName[p]; ok {
			names = append(names, n)
		}
	}
	return names
}
