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

// MazakProbe runs CIP + MTConnect (default port set) concurrently against
// ip with CIP > MTConnect precedence. Verbose progress callback (when
// non-nil) reports per-probe outcomes for `--mode mazak` operators.
func MazakProbe(ip string, timeout time.Duration, verbose func(string)) *MazakIdentity {
	var (
		mu    sync.Mutex
		cipID *MazakIdentity
		mtIDs []*MazakIdentity
		wg    sync.WaitGroup
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

	if cipID != nil {
		return cipID
	}
	for _, id := range mtIDs {
		if id != nil {
			return id
		}
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
		progress(fmt.Sprintf("Mazak: probing %d host(s) — CIP/UDP %d, MTConnect/TCP %v",
			len(ips), EIPPort, mazakMTConnectPorts))
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
