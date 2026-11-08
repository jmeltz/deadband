package discover

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// Tridium Niagara Fox / FoxS Read-Only Probe (TCP/1911, TCP/4911).
//
// Strictly read-only: sends a single "fox hello" session-greeting message and
// disconnects immediately upon reading the unauthenticated banner dictionary.
// Never attempts station authentication, BOG graph writes, or action invocation.

const foxHelloRequest = "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};\n;\n"

// FoxIdentity holds parsed metadata from a Tridium Niagara Fox/FoxS hello response.
type FoxIdentity struct {
	FoxVersion  string
	AppName     string
	AppVersion  string
	StationName string
	HostName    string
	HostID      string
	BrandID     string
	OSName      string
	OSVersion   string
}

func buildFoxHelloRequest() []byte {
	return []byte(foxHelloRequest)
}

func stripFoxTypedPrefix(val string) string {
	if len(val) >= 2 && val[1] == ':' {
		switch val[0] {
		case 's', 'i', 'b', 'l', 'f', 'd', 'z', 'o':
			return val[2:]
		}
	}
	return val
}

// ParseFoxHello parses a Tridium Niagara "fox hello" banner message.
func ParseFoxHello(raw string) (*FoxIdentity, error) {
	idx := strings.Index(raw, "fox ")
	if idx < 0 {
		return nil, fmt.Errorf("missing fox magic header")
	}
	sub := raw[idx:]
	firstLineEnd := strings.IndexByte(sub, '\n')
	if firstLineEnd < 0 {
		return nil, fmt.Errorf("truncated fox header line")
	}
	headerLine := strings.ToLower(strings.TrimSpace(sub[:firstLineEnd]))
	if !strings.HasPrefix(headerLine, "fox ") || !strings.Contains(headerLine, "hello") {
		return nil, fmt.Errorf("unexpected fox message header: %q", headerLine)
	}

	openBrace := strings.IndexByte(sub, '{')
	closeBrace := strings.Index(sub, "};")
	if openBrace < 0 || closeBrace <= openBrace {
		return nil, fmt.Errorf("missing fox property dictionary braces")
	}

	body := sub[openBrace+1 : closeBrace]
	props := make(map[string]string)
	for _, rawLine := range strings.Split(body, "\n") {
		line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := stripFoxTypedPrefix(strings.TrimSpace(line[eq+1:]))
		props[key] = val
	}

	if len(props) == 0 {
		return nil, fmt.Errorf("empty fox hello dictionary")
	}

	return &FoxIdentity{
		FoxVersion:  props["fox.version"],
		AppName:     props["app.name"],
		AppVersion:  props["app.version"],
		StationName: props["station.name"],
		HostName:    props["hostName"],
		HostID:      props["hostId"],
		BrandID:     props["brandId"],
		OSName:      props["os.name"],
		OSVersion:   props["os.version"],
	}, nil
}

func foxVendorAndBrandPrefix(brandID string) (vendor string, oemProduct string) {
	b := strings.ToLower(strings.TrimSpace(brandID))
	switch {
	case b == "" || b == "vykon" || b == "tridium" || b == "niagara":
		return "Tridium", ""
	case strings.Contains(b, "honeywell") || b == "webs" || strings.Contains(b, "alerton") || strings.Contains(b, "centraline") || strings.Contains(b, "trend"):
		return "Honeywell", "WEBs-N4"
	case b == "jci" || b == "fx" || strings.Contains(b, "johnson") || strings.Contains(b, "facilityexplorer"):
		return "Johnson Controls", "Facility Explorer"
	case strings.Contains(b, "distech") || strings.Contains(b, "ecnet"):
		return "Distech Controls", "EC-Net 4"
	case strings.Contains(b, "schneider") || strings.Contains(b, "ecostruxure") || b == "tac":
		return "Schneider Electric", "EcoStruxure"
	case strings.Contains(b, "siemens") || strings.Contains(b, "talon"):
		return "Siemens", "TALON"
	case b == "abb" || strings.Contains(b, "cylon"):
		return "ABB", "Cylon"
	case strings.Contains(b, "phoenix"):
		return "Phoenix Contact", "Emalytics"
	default:
		return "Tridium", ""
	}
}

// FoxIdentityToDevice converts a parsed FoxIdentity into an inventory.Device.
func FoxIdentityToDevice(ip string, port int, useTLS bool, id *FoxIdentity) inventory.Device {
	vendor, oemProd := foxVendorAndBrandPrefix(id.BrandID)

	hwPlatform := ""
	upperHostID := strings.ToUpper(id.HostID)
	upperOS := strings.ToUpper(id.OSName)
	switch {
	case strings.Contains(upperHostID, "NPM9") || strings.Contains(upperHostID, "TITAN"):
		hwPlatform = "JACE-9000"
	case strings.Contains(upperHostID, "NPM8"):
		hwPlatform = "JACE-8000"
	case strings.Contains(upperHostID, "NPM6") || strings.Contains(upperHostID, "NPM7") || strings.Contains(upperHostID, "JACE"):
		hwPlatform = "JACE"
	case strings.Contains(upperOS, "QNX"):
		hwPlatform = "JACE"
	default:
		if strings.EqualFold(id.AppName, "Station") && id.StationName != "" {
			hwPlatform = "Supervisor"
		} else {
			hwPlatform = "Framework"
		}
	}

	modelParts := []string{"Niagara"}
	if oemProd != "" {
		modelParts = append(modelParts, oemProd)
	}
	if hwPlatform != "" {
		modelParts = append(modelParts, hwPlatform)
	}
	model := strings.Join(modelParts, " ")

	hostname := strings.TrimSpace(id.HostName)
	if hostname == "" {
		hostname = strings.TrimSpace(id.StationName)
	}

	extra := make(map[string]string)
	if id.StationName != "" {
		extra["station_name"] = id.StationName
	}
	if id.BrandID != "" {
		extra["brand_id"] = id.BrandID
	}
	if id.HostID != "" {
		extra["host_id"] = id.HostID
	}
	if osInfo := strings.TrimSpace(id.OSName + " " + id.OSVersion); osInfo != "" {
		extra["os"] = osInfo
	}
	if useTLS {
		extra["tls"] = "true"
	}
	if len(extra) == 0 {
		extra = nil
	}

	return inventory.Device{
		IP:       ip,
		Vendor:   vendor,
		Model:    model,
		Firmware: strings.TrimSpace(id.AppVersion),
		Hostname: hostname,
		Protocol: "fox",
		Port:     port,
		Extra:    extra,
	}
}

// FoxIdentify dials ip:port over TCP (or TLS when useTLS is true), sends a read-only
// "fox hello" handshake, and parses the returned station/supervisor metadata.
func FoxIdentify(ip string, port int, useTLS bool, timeout time.Duration) (*FoxIdentity, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	var (
		conn net.Conn
		err  error
	)
	dialer := &net.Dialer{Timeout: timeout}
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // OT JACE/Supervisor endpoints routinely use self-signed station certs
			MinVersion:         tls.VersionTLS10,
		})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildFoxHelloRequest()); err != nil {
		return nil, nil
	}

	buf := make([]byte, 4096)
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
			if strings.Contains(string(buf[:total]), "};") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if total == 0 {
		return nil, nil
	}
	return ParseFoxHello(string(buf[:total]))
}

func discoverFox(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	type target struct {
		port   int
		useTLS bool
	}
	targets := []target{
		{FoxSPort, true},
		{FoxPort, false},
	}

	openMap := make(map[string][]target)
	for _, t := range targets {
		for _, ip := range ScanPorts(ips, t.port, timeout, concurrency) {
			openMap[ip] = append(openMap[ip], t)
		}
	}
	if progress != nil {
		progress(fmt.Sprintf("Tridium Niagara Fox/FoxS: %d/%d hosts with TCP/1911 or 4911 open", len(openMap), len(ips)))
	}
	if len(openMap) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		devices []inventory.Device
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for ip, candTargets := range openMap {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string, candTargets []target) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, t := range candTargets {
				id, err := FoxIdentify(ip, t.port, t.useTLS, timeout)
				if err == nil && id != nil {
					dev := FoxIdentityToDevice(ip, t.port, t.useTLS, id)
					mu.Lock()
					devices = append(devices, dev)
					mu.Unlock()
					return
				}
			}
		}(ip, candTargets)
	}
	wg.Wait()
	return devices
}
