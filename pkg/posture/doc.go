// Package posture performs network posture analysis on OT subnets.
//
// It discovers all live hosts (not just OT devices), classifies them,
// identifies segmentation concerns, and recommends compensating controls.
//
// # Sensitivity-Ordered Scanning Protocol
//
// All probing follows a strict most-sensitive-first ordering. Each phase
// gates the next: hosts identified as OT in an earlier phase are excluded
// from all subsequent, more-intrusive phases. This protects PLCs, RTUs,
// and other OT controllers from receiving traffic that could trigger
// watchdog timers, fault states, or IDS alerts.
//
//	Phase 0 — Asset Store Pre-Tagging
//	──────────────────────────────────
//	Before any packets are sent, hosts already in the asset store with
//	a known OT protocol (from prior discovery) are pre-tagged as
//	OT-positive. This provides a safety layer even if a PLC's OT port
//	is temporarily down — it will never receive IT probes.
//
//	    Source: ScanSubnetWithAssets (hostscan.go)
//	    Input:  asset.Store — assets with Protocol != ""
//	    Output: knownOT map[string]bool
//
//	Phase 1 — OT Port Scan (all hosts)
//	───────────────────────────────────
//	TCP connect to 8 OT protocol ports on EVERY host in the CIDR.
//	These are lightweight identity-read ports used by ICS protocols.
//	A TCP connect to these ports is the same handshake that HMIs and
//	engineering workstations perform routinely — safe for OT networks.
//
//	    Ports:  44818 (CIP/EtherNet-IP), 102 (S7comm), 502 (Modbus TCP),
//	            47808 (BACnet/IP), 5007 (MELSEC/SLMP), 9600 (FINS),
//	            18245 (GE-SRTP), 4840 (OPC UA)
//	    Source: hostscan.go — scanPorts(ips, OTPorts, ...)
//	    Output: otPositive set = knownOT ∪ {hosts that responded on any OT port}
//
//	Phase 2 — IT / Network Port Scan (non-OT hosts only)
//	─────────────────────────────────────────────────────
//	TCP connect to 12 IT/infrastructure ports ONLY on hosts NOT in the
//	OT-positive set. This is the first exclusion gate: confirmed OT
//	devices never see SSH, RDP, SMB, or any other IT service probes.
//
//	    Ports:  22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP),
//	            135 (RPC/DCOM), 445 (SMB), 8080 (HTTP-alt),
//	            8443 (HTTPS-alt), 53 (DNS),
//	            161 (SNMP), 23 (Telnet), 179 (BGP)
//	    Source: hostscan.go — scanPorts(nonOTIPs, itNetPorts, ...)
//	    Gate:   otPositive[ip] == true → skip
//
//	Phase 3 — Classification
//	────────────────────────
//	Hosts are classified based on which ports responded. No packets
//	are sent in this phase — it is purely analytical.
//
//	    OT:      Any OT port open, OR matched an existing asset
//	    IT:      Only IT ports open (SSH, HTTP, RDP, SMB, etc.)
//	    Network: SNMP, Telnet, or BGP without IT ports (switches, routers)
//	    Unknown: Alive but does not match any category
//
//	    Source: classify.go — ClassifyHostsWithProgress
//
//	Phase 4 — SMB/NTLMSSP Probe (RDP hosts only, non-OT)
//	──────────────────────────────────────────────────────
//	For hosts with RDP (3389) open, perform an unauthenticated SMB2
//	negotiate + NTLMSSP challenge exchange on port 445. RDP implies
//	Windows, and the NTLMSSP challenge contains the machine hostname,
//	Active Directory domain, and OS build version — all returned
//	without credentials.
//
//	This is the same two-packet exchange Windows performs when browsing
//	a network share. No authentication is attempted.
//
//	    Trigger: port 3389 open AND DeviceClass != OT
//	    Target:  port 445 (SMB)
//	    Extracts: hostname, domain, OS version (e.g., "10.0.19041")
//	    Source:  smbprobe.go — ProbeSMB
//	    Gate:    DeviceClass == ClassOT → skip
//
//	Phase 5 — Protocol Banner Probes (all non-OT hosts)
//	────────────────────────────────────────────────────
//	For every non-OT host, perform protocol-appropriate banner grabs
//	on each open port. Only protocols the host actually has open are
//	probed — no speculative connections.
//
//	    SSH (port 22):
//	        Read the SSH identification string sent on connect.
//	        Example: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
//	        Source: banners.go — ProbeSSH
//
//	    HTTP/HTTPS (ports 80, 443, 8080, 8443):
//	        Send HTTP GET, extract Server header + <title> tag.
//	        Uses InsecureSkipVerify for self-signed certs.
//	        Example: "Apache/2.4.52 — Rockwell Automation Dashboard"
//	        Source: banners.go — ProbeHTTP
//
//	    SNMP (port 161):
//	        Send SNMPv2c GET for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
//	        using community string "public".
//	        Example: "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)"
//	        Source: banners.go — ProbeSNMP
//
//	    Telnet (port 23):
//	        Read the initial banner/login prompt.
//	        Example: "Cisco 2960 Switch | Username:"
//	        Source: banners.go — ProbeTelnet
//
//	    SMB (port 445, without RDP):
//	        Same NTLMSSP probe as Phase 4, but for Windows servers that
//	        have SMB open without RDP. Catches domain controllers,
//	        file servers, and other headless Windows hosts.
//	        Source: smbprobe.go — ProbeSMB
//
//	    Gate: DeviceClass == ClassOT → skip entirely
//
//	Phase 6 — Presumption Enrichment
//	─────────────────────────────────
//	No packets sent. Combines banner data with port-based heuristics
//	to produce a human-readable identity for each host. Falls back to
//	port-only inference when no banners were collected.
//
//	    Source: classify.go — enrichedPresumption
//
// # Safety Invariant
//
// A host classified as OT (by Phase 0 pre-tagging, Phase 1 port
// response, or asset store match) will NEVER receive:
//   - IT/Network port scans (Phase 2)
//   - SMB/NTLMSSP probes (Phase 4)
//   - Banner grabs of any kind (Phase 5)
//
// This is enforced at three independent checkpoints:
//  1. hostscan.go: otPositive set excludes OT IPs from Phase 2 scan
//  2. classify.go: DeviceClass != ClassOT gate on SMB probe targets
//  3. classify.go: DeviceClass == ClassOT → continue in banner target loop
package posture
