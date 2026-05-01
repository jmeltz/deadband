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

// MazakProbe runs all four Mazak fingerprints concurrently against ip and
// returns the first positive hit, with this precedence:
//
//	CIP (vendor=246) > NetBIOS (hostname pattern) > MTConnect (manufacturer=Mazak) > HTTP (body match)
//
// CIP wins because vendor ID is canonical. MTConnect outranks NetBIOS in
// product code structure, but we put NetBIOS second here because in
// practice an i-400S with no MTConnect option exposes nothing on TCP/5000
// while still emitting a Mazak-pattern NetBIOS name. HTTP is the
// lowest-confidence fallback for shops with NetBIOS firewalled and
// branded IIS pages.
//
// Verbose callback (when non-nil) reports per-probe outcomes for
// `--mode mazak` operators on a single host.
func MazakProbe(ip string, timeout time.Duration, verbose func(string)) *MazakIdentity {
	var (
		mu       sync.Mutex
		cipID    *MazakIdentity
		nbID     *MazakIdentity
		httpID   *MazakIdentity
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
	wg.Wait()

	switch {
	case cipID != nil:
		return cipID
	case nbID != nil:
		return nbID
	}
	for _, id := range mtIDs {
		if id != nil {
			return id
		}
	}
	if httpID != nil {
		return httpID
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
	case "http":
		return 80
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
		progress(fmt.Sprintf("Mazak: probing %d host(s) — CIP/UDP %d, NetBIOS/UDP %d, MTConnect/TCP %v, HTTP/TCP 80",
			len(ips), EIPPort, NetBIOSPort, mazakMTConnectPorts))
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
