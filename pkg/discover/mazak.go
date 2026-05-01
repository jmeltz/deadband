// Package discover — Yamazaki Mazak machine tool discovery.
//
// Mazak fingerprinting fans out two read-only probes per host with CIP >
// MTConnect precedence:
//
//  1. EtherNet/IP CIP ListIdentity on UDP/44818. Highest-confidence —
//     Mazak's ODVA Vendor ID (246) is unique to Yamazaki Mazak. Fires when
//     the EtherNet/IP option is enabled on the controller.
//
//  2. MTConnect agent on TCP/5000 (and TCP/5001 fallback). Mazak's official
//     connectivity story is MTConnect: a `GET /probe` returns XML containing
//     `<Device manufacturer="Mazak" model="Integrex|QTN|Nexus|HCN|VCN|...">`.
//     The probe endpoint is read-only and unauthenticated by default per
//     the MTConnect spec; cppagent is the reference implementation.
//
// Mazatrol Smooth-era controllers run a Mitsubishi MELDAS kernel behind a
// Windows IPC HMI, but the raw MELSEC/SLMP module is not exposed on the
// user LAN — the existing MELSEC probe will not detect Mazaks. CIP and
// MTConnect are the only viable default-on, unauthenticated network
// signals.
//
// Mazaks without the MTConnect option AND without EtherNet/IP enabled are
// effectively invisible to active scanning. SmartBox 2.0 / iSmart Box
// gateways (when present) aggregate downstream machines and respond to
// MTConnect on the same `/probe` endpoint with multiple `<Device>` entries.
package discover

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// MazakIdentity carries fields extracted from a Mazak fingerprint.
type MazakIdentity struct {
	Model        string // e.g. "Integrex i-400S", "QTN-200", "VCN-500"
	SerialNumber string // when reported by MTConnect probe
	Version      string // firmware/agent version when present
	Banner       string // raw evidence (CIP product name, MTConnect Header, etc.)
	Source       string // "cip" or "mtconnect"
	AgentPort    int    // MTConnect port that responded (when source=mtconnect)
}

// MTConnect default ports surveyed in priority order. cppagent's reference
// default is 5000; integrators sometimes shift to 5001 to coexist with
// other tooling. Mazak's iSmart Factory cloud uses 56xx/57xx but those are
// off-machine — not relevant here.
var mazakMTConnectPorts = []int{5000, 5001}

// FirebirdPort is TCP/3050 — Firebird/Interbase RDBMS default. Mazatrol
// Smooth uses an embedded Firebird database for tool/program/parameter
// storage; its presence on a Windows-HMI-shaped host is a strong Mazak
// signal in combination with other ports.
const FirebirdPort = 3050

// mazakSimpleTCPPorts are the five Windows "Simple TCP/IP Services"
// (Echo/Discard/Daytime/Qotd/Chargen). They're a single Windows feature
// that ships off-by-default since Server 2003; Mazatrol Smooth's HMI image
// enables all five. Default Windows admins essentially never turn this on.
var mazakSimpleTCPPorts = []int{7, 9, 13, 17, 19}

// mazakBonusPorts add weight to the port-shape match without being
// required. LPD (515) and MSMQ (1801) are commonly enabled on Smooth HMI
// images; their presence reinforces but doesn't drive the heuristic.
var mazakBonusPorts = []int{515, 1801}

// mazakModelRE matches Mazak product family names that appear in MTConnect
// `<Device model="...">` attributes and in CIP ProductName strings.
var mazakModelRE = regexp.MustCompile(
	`(?i)\b(Integrex|QuickTurn|QTN|Nexus|HCN|VCN|Variaxis|Multiplex|Smooth)\b[\w\- ]*`,
)

// mazakHostnameRE matches Mazak-pattern NetBIOS hostnames as set by Mazak
// integrators at commissioning. Discriminator words (mazatrol, integrex,
// smoothx, variaxis, multiplex, quickturn) are essentially Mazak-only —
// generic terms like "smooth" alone are NOT in this list.
var mazakHostnameRE = regexp.MustCompile(
	`(?i)\b(mazak|mazatrol|integrex|smoothx|smoothg|smoothai|nexus|qtn|quickturn|variaxis|multiplex|smartbox)\b`,
)

// mazakHTTPRE matches Mazak strings inside an HTTP / response body. Used
// when the controller's IIS-on-Smooth serves a branded operator/monitor
// page instead of the bare iisstart welcome.
var mazakHTTPRE = regexp.MustCompile(
	`(?i)\b(mazak|mazatrol|smoothmonitor|smoothx|smoothg|smoothai|integrex|nexus|variaxis|multiplex|quickturn)\b`,
)

// MazakCIP probes UDP/44818 with EtherNet/IP ListIdentity. Returns nil, nil
// unless VendorID matches Mazak's ODVA registry value.
func MazakCIP(ip string, timeout time.Duration) (*MazakIdentity, error) {
	cip, err := ListIdentityUnicast(ip, timeout)
	if err != nil || cip == nil {
		return nil, nil
	}
	if cip.VendorID != MazakCIPVendorID {
		return nil, nil
	}
	id := &MazakIdentity{
		Model:   strings.TrimSpace(cip.ProductName),
		Version: fmt.Sprintf("%d.%d", cip.RevMajor, cip.RevMinor),
		Banner:  fmt.Sprintf("CIP vendor=%d product=%q rev=%d.%d", cip.VendorID, cip.ProductName, cip.RevMajor, cip.RevMinor),
		Source:  "cip",
	}
	return id, nil
}

// mtconnectProbe is the minimal subset of /probe XML we care about. The
// MTConnect spec defines this in MTC_Part2_Devices; cppagent emits the same
// shape regardless of vendor.
type mtconnectProbe struct {
	XMLName xml.Name `xml:"MTConnectDevices"`
	Header  struct {
		Sender     string `xml:"sender,attr"`
		InstanceID string `xml:"instanceId,attr"`
		Version    string `xml:"version,attr"`
	} `xml:"Header"`
	Devices struct {
		Device []struct {
			Name        string `xml:"name,attr"`
			UUID        string `xml:"uuid,attr"`
			Description struct {
				Manufacturer string `xml:"manufacturer,attr"`
				Model        string `xml:"model,attr"`
				Serial       string `xml:"serialNumber,attr"`
			} `xml:"Description"`
		} `xml:"Device"`
	} `xml:"Devices"`
}

// MazakMTConnect fetches `GET /probe` against TCP/port and returns a Mazak
// identity if the XML response contains a `<Device>` whose Description
// manufacturer matches "Mazak" (case-insensitive). Falls through to model
// substring match for genericized agent configs that don't set
// manufacturer explicitly.
func MazakMTConnect(ip string, port int, timeout time.Duration) (*MazakIdentity, error) {
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("http://%s/probe", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "deadband/0.5")
	req.Header.Set("Accept", "application/xml,text/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil && len(body) == 0 {
		return nil, nil
	}
	// Cheap path-out: MTConnect probe responses always start with
	// `<MTConnectDevices` — bail on anything else without paying parser cost.
	if !strings.Contains(string(body), "MTConnectDevices") {
		return nil, nil
	}

	var probe mtconnectProbe
	if err := xml.Unmarshal(body, &probe); err != nil {
		return nil, nil
	}

	// Walk devices. First Mazak match wins; an aggregator (SmartBox) may
	// host many devices, all reported via this single probe.
	for _, d := range probe.Devices.Device {
		mfr := strings.ToLower(d.Description.Manufacturer)
		if strings.Contains(mfr, "mazak") || strings.Contains(mfr, "yamazaki") ||
			mazakModelRE.MatchString(d.Description.Model) ||
			mazakModelRE.MatchString(d.Name) {
			id := &MazakIdentity{
				Model:        firstNonEmpty(d.Description.Model, d.Name),
				SerialNumber: d.Description.Serial,
				Version:      probe.Header.Version,
				Banner:       fmt.Sprintf("MTConnect %s — %s/%s", probe.Header.Version, d.Description.Manufacturer, firstNonEmpty(d.Description.Model, d.Name)),
				Source:       "mtconnect",
				AgentPort:    port,
			}
			return id, nil
		}
	}
	return nil, nil
}

// NetBIOSPort is UDP/137, the NetBIOS Name Service port.
const NetBIOSPort = 137

// buildNBSTATRequest constructs a 50-byte NetBIOS Name Service node-status
// request packet (NBSTAT). Targets the wildcard NetBIOS name "*" so the
// responder enumerates every name registered on the host. Mirrors the
// `nbtscan` / `nmblookup -A` workflow.
func buildNBSTATRequest() []byte {
	buf := make([]byte, 50)
	// Transaction ID — fixed; we only send one request per host so the ID
	// just needs to round-trip in the response header.
	buf[0] = 0xAA
	buf[1] = 0xBB
	// Flags = 0x0000 (standard query, opcode 0)
	binary.BigEndian.PutUint16(buf[4:6], 1) // questions = 1
	// Answer/Authority/Additional RR counts left zero
	buf[12] = 0x20 // encoded name length (32 bytes, fixed for NetBIOS)
	// Encoded name "*\x00\x00..." (16-byte unencoded → 32-byte encoded).
	// '*' is 0x2A → high nibble 2 → 'C' (0x43), low nibble A → 'K' (0x4B).
	// All subsequent NULs → 'A' 'A'.
	buf[13] = 'C'
	buf[14] = 'K'
	for i := 15; i < 13+32; i++ {
		buf[i] = 'A'
	}
	buf[45] = 0x00 // name terminator
	// Question type NBSTAT = 0x0021
	binary.BigEndian.PutUint16(buf[46:48], 0x0021)
	// Question class IN = 0x0001
	binary.BigEndian.PutUint16(buf[48:50], 0x0001)
	return buf
}

// parseNBSTATResponse extracts the 15-character NetBIOS names from an
// NBSTAT response packet. Returns nil on any parse failure rather than
// trying to recover — malformed responses are not informative for
// fingerprinting.
//
// Layout (RFC 1002 § 4.2.18):
//
//	0..11   header (12 bytes)
//	12..    question section: 1 byte len + 32 bytes name + 1 byte term + 4 bytes type/class = 38 bytes
//	50..    answer RR: 34 bytes name (1 + 32 + 1) + 10 bytes type/class/TTL/RDLEN = 44 bytes
//	94..    RDATA: 1 byte name count, then N×18 bytes (15 name + 1 suffix + 2 flags)
func parseNBSTATResponse(data []byte) []string {
	const rdataStart = 12 + 38 + 44
	if len(data) < rdataStart+1 {
		return nil
	}
	// Sanity: header flags should have the response bit set (0x8000).
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return nil
	}
	// Sanity: at least one answer RR.
	if binary.BigEndian.Uint16(data[6:8]) == 0 {
		return nil
	}

	count := int(data[rdataStart])
	offset := rdataStart + 1
	names := make([]string, 0, count)
	for i := 0; i < count && offset+18 <= len(data); i++ {
		raw := data[offset : offset+15]
		name := strings.TrimRight(string(raw), " \x00")
		// suffix at offset+15 indicates the name's purpose; we don't
		// distinguish workstation vs server suffixes for fingerprinting,
		// just collect every printable name.
		if name != "" && isPrintableASCII(name) {
			names = append(names, name)
		}
		offset += 18
	}
	return names
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// MazakNetBIOS sends an NBSTAT query to UDP/137 and reports a Mazak
// identity if any returned NetBIOS name matches the Mazak hostname regex.
// Returns nil, nil on no response, parse failure, or non-Mazak hostnames.
//
// Read-only by construction: we only send the standard NBSTAT wildcard
// query, no name registration or release. Many Mazak Smooth controllers
// have NetBIOS enabled by default; Windows 10/11 disables it on Public
// network profiles, so the probe is best-effort.
func MazakNetBIOS(ip string, timeout time.Duration) (*MazakIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", NetBIOSPort))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildNBSTATRequest()); err != nil {
		return nil, nil
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil
	}

	names := parseNBSTATResponse(buf[:n])
	for _, name := range names {
		if mazakHostnameRE.MatchString(name) {
			return &MazakIdentity{
				Model:  name,
				Banner: fmt.Sprintf("NetBIOS hostname=%s", name),
				Source: "netbios",
			}, nil
		}
	}
	return nil, nil
}

// MazakHTTP fetches GET / over plain HTTP and reports a Mazak identity if
// the response body or Server header carry Mazak-specific strings.
// Lower-confidence than CIP / MTConnect / NetBIOS — bare IIS welcomes
// don't carry Mazak text — but it's the right fallback when the
// connectivity options aren't enabled and NetBIOS is firewalled.
func MazakHTTP(ip string, timeout time.Duration) (*MazakIdentity, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", net.JoinHostPort(ip, "80")), nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "deadband/0.5")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil && len(body) == 0 {
		return nil, nil
	}
	bodyStr := string(body)
	server := resp.Header.Get("Server")

	matched := mazakHTTPRE.MatchString(bodyStr) || mazakHTTPRE.MatchString(server)
	if !matched {
		return nil, nil
	}

	id := &MazakIdentity{
		Banner: fmt.Sprintf("HTTP %s server=%q — %s", resp.Status, server, firstLineMazak(bodyStr)),
		Source: "http",
	}
	if m := mazakModelRE.FindString(bodyStr); m != "" {
		id.Model = strings.TrimSpace(m)
	}
	return id, nil
}

func firstLineMazak(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 120 {
			line = line[:120] + "..."
		}
		return line
	}
	return ""
}

// MazakPortShape is the last-resort fingerprint for Mazatrol Smooth
// controllers running their stock Windows IPC HMI image without any of
// the optional connectivity packages (no EtherNet/IP, no MTConnect, no
// custom HTTP page, NetBIOS firewalled).
//
// It runs two cheap parallel checks:
//
//  1. TCP-connect probes against the {Firebird 3050, Simple TCP/IP Services
//     7/9/13/17/19, LPD 515, MSMQ 1801} port set. The combination of
//     Firebird PLUS three or more Simple TCP/IP Services on the same
//     Windows host is essentially a Mazatrol Smooth signature — Simple
//     TCP/IP Services is a single Windows feature that's off by default
//     since Server 2003 and almost nobody enables on a non-OEM image.
//
//  2. A Firebird `op_connect` handshake on port 3050 if it's open. The
//     server's first response opcode (op_accept = 3 or op_reject = 4)
//     confirms the listener actually speaks Firebird, ruling out unrelated
//     services that happen to bind 3050.
//
// Returns:
//   - nil if Firebird isn't open (the heuristic anchor) — too noisy without it
//   - identity with Source="firebird" if Firebird handshake succeeds
//   - identity with Source="port-shape" if Firebird port is open but
//     handshake didn't complete, AND ≥3 Simple TCP/IP Services responded
//   - nil if neither threshold met
//
// All probes are read-only — TCP connects close immediately, the Firebird
// op_connect is the standard handshake message with no auth attempt.
func MazakPortShape(ip string, timeout time.Duration) (*MazakIdentity, error) {
	// Phase 1: parallel TCP-connect probes.
	type portStatus struct {
		port int
		open bool
	}
	allPorts := append([]int{FirebirdPort}, mazakSimpleTCPPorts...)
	allPorts = append(allPorts, mazakBonusPorts...)
	results := make(chan portStatus, len(allPorts))

	var wg sync.WaitGroup
	for _, p := range allPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", p)), timeout)
			open := err == nil
			if c != nil {
				_ = c.Close()
			}
			results <- portStatus{p, open}
		}(p)
	}
	wg.Wait()
	close(results)

	openPorts := make(map[int]bool)
	for s := range results {
		if s.open {
			openPorts[s.port] = true
		}
	}

	// Anchor: Firebird must be open. Without it the rest is too generic.
	if !openPorts[FirebirdPort] {
		return nil, nil
	}

	// Count Simple TCP/IP Services hits.
	simpleHits := 0
	for _, p := range mazakSimpleTCPPorts {
		if openPorts[p] {
			simpleHits++
		}
	}
	if simpleHits < 3 {
		// Firebird alone — too noisy. Any Windows app server could host
		// Firebird; it's only Mazak-specific in combination with the
		// HMI port shape.
		return nil, nil
	}

	// Phase 2: Firebird handshake confirmation.
	confirmed := mazakFirebirdHandshake(ip, timeout)

	bonus := 0
	for _, p := range mazakBonusPorts {
		if openPorts[p] {
			bonus++
		}
	}
	source := "port-shape"
	model := "Mazatrol Smooth (port-shape match)"
	if confirmed {
		source = "firebird"
		model = "Mazatrol Smooth (Firebird-confirmed)"
	}
	banner := fmt.Sprintf("port-shape: firebird=%v simpleTCP=%d/5 bonus=%d/2 firebird_handshake=%v",
		openPorts[FirebirdPort], simpleHits, bonus, confirmed)

	return &MazakIdentity{
		Model:  model,
		Banner: banner,
		Source: source,
	}, nil
}

// mazakFirebirdHandshake sends a minimal Firebird op_connect packet and
// returns true if the server's first response opcode is in the valid
// Firebird response range (op_accept=3, op_reject=4, op_response=9, etc.).
// Read-only: op_connect carries no credentials and the connection closes
// after the response is read.
func mazakFirebirdHandshake(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", FirebirdPort)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildFirebirdOpConnect()
	if _, err := conn.Write(pkt); err != nil {
		return false
	}

	buf := make([]byte, 16)
	n, err := io.ReadFull(conn, buf[:4])
	if err != nil || n < 4 {
		return false
	}
	opcode := binary.BigEndian.Uint32(buf[:4])
	// Valid Firebird response opcodes for op_connect are op_accept (3),
	// op_reject (4), op_disconnect (5), op_response (9), op_accept_data (81),
	// op_cond_accept (87). Be permissive — any opcode in the small valid
	// range counts as "this is Firebird".
	switch opcode {
	case 3, 4, 5, 9, 81, 87:
		return true
	}
	// Some Firebird builds reply with a higher op_accept_data variant; allow
	// anything <=128 as a Firebird-ish opcode.
	return opcode > 0 && opcode <= 128
}

// buildFirebirdOpConnect emits a minimal op_connect packet (CONNECT_VERSION2,
// arch_generic, file_name="test", one protocol entry) sufficient for any
// Firebird/Interbase server to send back a parseable response. We don't care
// whether the protocols negotiate; we just need any valid response opcode.
func buildFirebirdOpConnect() []byte {
	pkt := make([]byte, 0, 64)
	put := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		pkt = append(pkt, b[:]...)
	}
	put(1)  // op_connect
	put(19) // op_attach (the eventual operation)
	put(2)  // CONNECT_VERSION2 — older form, no user_identification field
	put(1)  // arch_generic

	// file_name "test" — 4-byte length prefix + 4 bytes of data (no padding
	// needed since 4 % 4 == 0).
	put(4)
	pkt = append(pkt, []byte("test")...)

	// Protocol count
	put(1)

	// Single protocol entry (version 10, arch_generic, type range 0..1,
	// weight 1)
	put(10)
	put(1)
	put(0)
	put(1)
	put(1)

	return pkt
}

// SMBPort is TCP/445, the direct SMB-over-TCP port. Used by the Mazak SMB
// probe to extract the controller's NetBIOS hostname over an anonymous
// SMB2 NEGOTIATE + SESSION_SETUP exchange — works even when UDP/137 is
// firewalled (Windows Firewall Public-profile default).
const SMBPort = 445

// MazakSMB runs an anonymous SMB2 NEGOTIATE + SESSION_SETUP against TCP/445
// and parses the NTLMSSP_CHALLENGE_MESSAGE TargetInfo for the server's
// NetBIOS computer name. Returns a Mazak identity if the hostname matches
// the Mazak hostname regex; nil otherwise.
//
// Read-only by construction: the exchange goes only as far as
// NTLMSSP_CHALLENGE (server emits this before any auth attempt). We never
// send NTLMSSP_AUTHENTICATE, never list shares, never touch the file
// system. This is the same surface `nmap --script smb-os-discovery` and
// `nbtscan` use.
//
// The hostname doubles as the Model field — Mazak integrators commonly
// set it to the actual product name (e.g. "INTEGREX-I400S",
// "MAZAK-NEXUS-450").
func MazakSMB(ip string, timeout time.Duration) (*MazakIdentity, error) {
	hostname := smb2Hostname(ip, timeout)
	if hostname == "" {
		return nil, nil
	}
	if !mazakHostnameRE.MatchString(hostname) {
		return nil, nil
	}
	return &MazakIdentity{
		Model:  hostname,
		Banner: fmt.Sprintf("SMB2 NTLMSSP NbComputerName=%s", hostname),
		Source: "smb",
	}, nil
}

// smb2Hostname performs an anonymous SMB2 NEGOTIATE + SESSION_SETUP
// exchange against ip:445 and extracts the server's NetBIOS computer name
// from the NTLMSSP_CHALLENGE TargetInfo AV_PAIRS. Returns "" on any
// failure mode (connection refused, parse error, missing AV pair).
func smb2Hostname(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", SMBPort)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: SMB2 NEGOTIATE
	if err := writeNBT(conn, smb2NegotiateRequest()); err != nil {
		return ""
	}
	if _, err := readNBT(conn); err != nil {
		return ""
	}

	// Step 2: SMB2 SESSION_SETUP with embedded NTLMSSP_NEGOTIATE
	if err := writeNBT(conn, smb2SessionSetupRequest()); err != nil {
		return ""
	}
	body, err := readNBT(conn)
	if err != nil {
		return ""
	}

	// Locate the NTLMSSP_CHALLENGE_MESSAGE inside the SecurityBuffer.
	// Rather than parse SPNEGO ASN.1, scan for the NTLMSSP signature
	// directly — the structure is self-describing from there.
	idx := bytesIndex(body, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return ""
	}
	return parseNTLMSSPChallenge(body[idx:])
}

// writeNBT prefixes a SMB payload with the 4-byte NetBIOS-over-TCP session
// header (1 byte type=0x00, 3 bytes big-endian length).
func writeNBT(conn net.Conn, payload []byte) error {
	hdr := []byte{0x00, byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload))}
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// readNBT reads one NetBIOS-over-TCP framed message and returns the SMB
// payload. The 4-byte header is consumed but not returned.
func readNBT(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length < 4 || length > 65536 {
		return nil, fmt.Errorf("invalid NBT message length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// smb2NegotiateRequest returns a 102-byte SMB2 NEGOTIATE_REQUEST advertising
// only dialect 2.0.2 — supported by every Windows since Vista/2008 and
// avoids the SMB 3.1.1 NegotiateContext parsing complexity.
func smb2NegotiateRequest() []byte {
	pkt := make([]byte, 64+36+2)
	// SMB2 header
	copy(pkt[0:4], []byte{0xFE, 'S', 'M', 'B'})
	pkt[4] = 64 // StructureSize low byte
	// CreditCharge=0, Status=0, Command=0(NEGOTIATE), CreditRequest=1
	pkt[14] = 1 // CreditRequest low byte
	// MessageId=0, TreeId=0, SessionId=0 — all zeros from make([]byte)
	// Body starts at offset 64
	pkt[64] = 36 // StructureSize=36
	pkt[66] = 1  // DialectCount=1
	pkt[68] = 1  // SecurityMode=SIGNING_ENABLED
	// Capabilities=0, ClientGuid=zeros, ClientStartTime=0
	// Dialects[0] = SMB 2.0.2 = 0x0202
	pkt[100] = 0x02
	pkt[101] = 0x02
	return pkt
}

// smb2SessionSetupRequest returns a SMB2 SESSION_SETUP_REQUEST whose
// SecurityBuffer is a SPNEGO NegTokenInit wrapping NTLMSSP_NEGOTIATE.
// Hostname-extraction-only — no credentials are sent.
func smb2SessionSetupRequest() []byte {
	// NTLMSSP_NEGOTIATE_MESSAGE (40 bytes)
	ntlmNeg := []byte{
		0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, // "NTLMSSP\0"
		0x01, 0x00, 0x00, 0x00, // MessageType=1
		0x07, 0x82, 0x08, 0xA2, // NegotiateFlags: UNICODE|REQ_TARGET|NTLM|SIGN|EXT_SESSION_SECURITY
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DomainNameFields (empty)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // WorkstationFields (empty)
		0x06, 0x01, 0xB1, 0x1D, 0x00, 0x00, 0x00, 0x0F, // Version (Windows 10 spoof)
	}

	// SPNEGO NegTokenInit wrapper around the NTLMSSP_NEGOTIATE
	// (ASN.1 DER, hand-assembled — total 74 bytes outer)
	spnego := []byte{
		0x60, 0x48, // APPLICATION 0, length 72
		0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, // OID 1.3.6.1.5.5.2 (SPNEGO)
		0xA0, 0x3E, // [0] context tag, length 62
		0x30, 0x3C, // SEQUENCE, length 60
		0xA0, 0x0E, // [0] mechTypes, length 14
		0x30, 0x0C, // SEQUENCE OF OID, length 12
		0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, // OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
		0xA2, 0x2A, // [2] mechToken, length 42
		0x04, 0x28, // OCTET STRING, length 40
	}
	spnego = append(spnego, ntlmNeg...)

	// SMB2 SESSION_SETUP_REQUEST body (25 bytes header + spnego)
	bodyHdr := make([]byte, 24)
	bodyHdr[0] = 25 // StructureSize=25
	// Flags=0, SecurityMode=1, Capabilities=0, Channel=0
	bodyHdr[2] = 1                                  // SecurityMode = SIGNING_ENABLED
	binary.LittleEndian.PutUint16(bodyHdr[12:14], 88) // SecurityBufferOffset = 64 (header) + 24 (body header) = 88
	binary.LittleEndian.PutUint16(bodyHdr[14:16], uint16(len(spnego)))
	// PreviousSessionId = 0

	// SMB2 header
	pkt := make([]byte, 64)
	copy(pkt[0:4], []byte{0xFE, 'S', 'M', 'B'})
	pkt[4] = 64                                       // StructureSize
	pkt[12] = 1                                       // CreditCharge
	binary.LittleEndian.PutUint16(pkt[16:18], 0x0001) // Command=SESSION_SETUP
	pkt[18] = 1                                       // CreditRequest
	binary.LittleEndian.PutUint64(pkt[24:32], 1)      // MessageId=1
	// All other fields zero

	pkt = append(pkt, bodyHdr...)
	pkt = append(pkt, spnego...)
	return pkt
}

// parseNTLMSSPChallenge takes a byte slice starting with "NTLMSSP\0" and
// returns the MsvAvNbComputerName from the TargetInfo AV_PAIRS, decoded
// from UTF-16LE. Returns "" on any parse failure.
func parseNTLMSSPChallenge(b []byte) string {
	// NTLMSSP_CHALLENGE_MESSAGE layout:
	//   0  Signature (8)
	//   8  MessageType (4) — must be 2
	//   12 TargetNameFields (8): Len(2), MaxLen(2), Offset(4)
	//   20 NegotiateFlags (4)
	//   24 ServerChallenge (8)
	//   32 Reserved (8)
	//   40 TargetInfoFields (8): Len(2), MaxLen(2), Offset(4)
	//   48 Version (8)
	//   56 ... payload
	if len(b) < 56 {
		return ""
	}
	if binary.LittleEndian.Uint32(b[8:12]) != 2 {
		return ""
	}
	tiLen := binary.LittleEndian.Uint16(b[40:42])
	tiOff := binary.LittleEndian.Uint32(b[44:48])
	if tiLen == 0 || int(tiOff)+int(tiLen) > len(b) {
		return ""
	}
	ti := b[tiOff : int(tiOff)+int(tiLen)]

	// Walk AV_PAIRS: AvId(2), AvLen(2), Value(AvLen)
	for i := 0; i+4 <= len(ti); {
		avID := binary.LittleEndian.Uint16(ti[i : i+2])
		avLen := binary.LittleEndian.Uint16(ti[i+2 : i+4])
		if avID == 0 { // MsvAvEOL
			break
		}
		if i+4+int(avLen) > len(ti) {
			break
		}
		if avID == 1 { // MsvAvNbComputerName
			return decodeUTF16LE(ti[i+4 : i+4+int(avLen)])
		}
		i += 4 + int(avLen)
	}
	return ""
}

// decodeUTF16LE decodes a UTF-16 little-endian byte slice to a Go string.
// Stops at the first NUL code unit. Used for NTLMSSP AV_PAIR values.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+2 <= len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// bytesIndex is a thin wrapper to avoid pulling in the bytes package just
// for one Index call. Returns -1 when sub is not found in s.
func bytesIndex(s, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	if len(s) < len(sub) {
		return -1
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// MazakProbe runs all six Mazak fingerprints concurrently against ip and
// returns the first positive hit, with this precedence:
//
//	CIP (vendor=246) > NetBIOS UDP (hostname pattern) > SMB2 NTLMSSP (hostname pattern) >
//	MTConnect (manufacturer=Mazak) > HTTP (body match) > Port-shape (Firebird + Simple TCP/IP services)
//
// CIP wins because vendor ID is canonical. NetBIOS UDP and SMB2 NTLMSSP
// both extract the Windows hostname; UDP is faster but firewalled by
// default on Windows 10/11 Public profile, so SMB over TCP/445 is the
// reliable fallback. MTConnect carries an integrator-set manufacturer
// attribute. HTTP body-match is a fallback for branded operator pages.
// Port-shape is the last-resort heuristic for stock Smooth HMIs serving a
// bare IIS welcome with both NetBIOS and SMB hostname disclosure dead.
//
// Verbose callback (when non-nil) reports per-probe outcomes for
// `--mode mazak` operators on a single host.
func MazakProbe(ip string, timeout time.Duration, verbose func(string)) *MazakIdentity {
	var (
		mu       sync.Mutex
		cipID    *MazakIdentity
		nbID     *MazakIdentity
		smbID    *MazakIdentity
		httpID   *MazakIdentity
		shapeID  *MazakIdentity
		mtIDs    []*MazakIdentity
		wg       sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		id, _ := MazakCIP(ip, timeout)
		mu.Lock()
		cipID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Mazak CIP probe (%s:%d): no Mazak identity", ip, EIPPort))
			} else {
				verbose(fmt.Sprintf("Mazak CIP probe (%s:%d): %s", ip, EIPPort, id.Banner))
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		id, _ := MazakNetBIOS(ip, timeout)
		mu.Lock()
		nbID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Mazak NetBIOS probe (%s:%d): no Mazak-pattern hostname", ip, NetBIOSPort))
			} else {
				verbose(fmt.Sprintf("Mazak NetBIOS probe (%s:%d): %s", ip, NetBIOSPort, id.Banner))
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		id, _ := MazakSMB(ip, timeout)
		mu.Lock()
		smbID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Mazak SMB probe (%s:%d): no Mazak-pattern hostname via NTLMSSP", ip, SMBPort))
			} else {
				verbose(fmt.Sprintf("Mazak SMB probe (%s:%d): %s", ip, SMBPort, id.Banner))
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		id, _ := MazakHTTP(ip, timeout)
		mu.Lock()
		httpID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Mazak HTTP probe (%s:80): no Mazak strings in /", ip))
			} else {
				verbose(fmt.Sprintf("Mazak HTTP probe (%s:80): %s", ip, id.Banner))
			}
		}
	}()

	mtIDs = make([]*MazakIdentity, len(mazakMTConnectPorts))
	for i, port := range mazakMTConnectPorts {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			id, _ := MazakMTConnect(ip, p, timeout)
			mu.Lock()
			mtIDs[idx] = id
			mu.Unlock()
			if verbose != nil {
				if id == nil {
					verbose(fmt.Sprintf("Mazak MTConnect probe (%s:%d): no manufacturer=Mazak in /probe", ip, p))
				} else {
					verbose(fmt.Sprintf("Mazak MTConnect probe (%s:%d): %s", ip, p, id.Banner))
				}
			}
		}(i, port)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		id, _ := MazakPortShape(ip, timeout)
		mu.Lock()
		shapeID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Mazak port-shape probe (%s): no Mazatrol-Smooth signature", ip))
			} else {
				verbose(fmt.Sprintf("Mazak port-shape probe (%s): %s", ip, id.Banner))
			}
		}
	}()

	wg.Wait()

	switch {
	case cipID != nil:
		return cipID
	case nbID != nil:
		return nbID
	case smbID != nil:
		return smbID
	}
	for _, id := range mtIDs {
		if id != nil {
			return id
		}
	}
	if httpID != nil {
		return httpID
	}
	if shapeID != nil {
		return shapeID
	}
	return nil
}

// MazakIdentityToDevice converts a MazakIdentity to an inventory.Device.
func MazakIdentityToDevice(ip string, id *MazakIdentity) inventory.Device {
	model := id.Model
	if model == "" {
		model = "Unknown Model"
	}
	dev := inventory.Device{
		IP:       ip,
		Vendor:   "Yamazaki Mazak",
		Model:    model,
		Firmware: id.Version,
		Serial:   id.SerialNumber,
		Protocol: "mazak-" + id.Source,
		Port:     mazakPortFor(id),
	}
	if id.Banner != "" {
		dev.Extra = map[string]string{"banner": id.Banner, "probe": id.Source}
	}
	return dev
}

func mazakPortFor(id *MazakIdentity) int {
	switch id.Source {
	case "cip":
		return EIPPort
	case "netbios":
		return NetBIOSPort
	case "smb":
		return SMBPort
	case "http":
		return 80
	case "firebird", "port-shape":
		return FirebirdPort
	case "mtconnect":
		if id.AgentPort != 0 {
			return id.AgentPort
		}
		return 5000
	default:
		return 0
	}
}

// discoverMazak runs MazakProbe over a slice of IPs concurrently.
func discoverMazak(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("Mazak: probing %d host(s) — CIP/UDP %d, NetBIOS/UDP %d, SMB/TCP %d, MTConnect/TCP %v, HTTP/TCP 80, port-shape (Firebird/TCP %d + Simple TCP/IP services)",
			len(ips), EIPPort, NetBIOSPort, SMBPort, mazakMTConnectPorts, FirebirdPort))
	}

	verbose := func(s string) {}
	if progress != nil && len(ips) == 1 {
		verbose = progress
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		devices []inventory.Device
		sem     = make(chan struct{}, concurrency)
	)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id := MazakProbe(ip, timeout, verbose)
			if id == nil {
				return
			}

			dev := MazakIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()

			if progress != nil {
				progress(fmt.Sprintf("Mazak: %s → %s (via %s)", ip, dev.Model, id.Source))
			}
		}(ip)
	}

	wg.Wait()
	return devices
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
