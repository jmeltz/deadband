package discover

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// SICK SOPAS CoLa-A / CoLa-B Read-Only Auto-ID & LiDAR Probe (TCP/2111, TCP/2112).
//
// Used heavily across KNAPP, Swisslog, and Dematic conveyor barcode-reading tunnels
// (MSC800, CLV6xx, ICR890, Lector65x) and AMR safety/navigation LiDARs.
// Strictly read-only: sends CoLa-A "\x02sRN DeviceIdent\x03" (Read by Name).
// Never sends sWN (Write) or sMN (Method Invocation).

var sickVersionRe = regexp.MustCompile(`(?i)^v?\d+\.\d+(?:\.\d+)*[a-z0-9_-]*$`)
var sickModelTokenRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{2,}$`)

type SICKIdentity struct {
	Model    string
	Firmware string
	Port     int
}

func buildCoLaADeviceIdent() []byte {
	return []byte("\x02sRN DeviceIdent\x03")
}

func parseCoLaDeviceIdentResponse(raw []byte, port int) (*SICKIdentity, error) {
	if len(raw) < 6 {
		return nil, fmt.Errorf("CoLa response too short")
	}

	var payload []byte
	if start := bytes.IndexByte(raw, 0x02); start >= 0 {
		if bytes.HasPrefix(raw[start:], []byte{0x02, 0x02, 0x02, 0x02}) && len(raw[start:]) >= 10 {
			// CoLa-B binary framing: 4x STX + 4-byte BE length + payload + 1-byte XOR checksum
			payload = raw[start+8:]
		} else {
			rest := raw[start+1:]
			if end := bytes.IndexByte(rest, 0x03); end >= 0 {
				payload = rest[:end]
			} else {
				payload = rest
			}
		}
	} else {
		return nil, fmt.Errorf("missing CoLa STX framing")
	}

	// Clean printable ASCII tokens
	var sb strings.Builder
	for _, b := range payload {
		if b >= 0x20 && b < 0x7f {
			sb.WriteByte(b)
		} else {
			sb.WriteByte(' ')
		}
	}
	text := strings.TrimSpace(sb.String())
	if !strings.Contains(text, "sRA") && !strings.Contains(text, "sFA") {
		return nil, fmt.Errorf("not a CoLa response: %q", text)
	}
	if strings.HasPrefix(text, "sFA") {
		// Fault answer confirms a genuine SICK SOPAS responder even if DeviceIdent index differs
		return &SICKIdentity{
			Model: "SOPAS Sensor",
			Port:  port,
		}, nil
	}

	tokens := strings.Fields(text)
	// Typical CoLa-A response: "sRA DeviceIdent 6 MSC800 6 V2.40" or "sRA DeviceIdent MSC800 V2.40.1"
	model := ""
	firmware := ""
	for i := 0; i < len(tokens); i++ {
		tok := strings.Trim(tokens[i], "\"'")
		if tok == "sRA" || tok == "DeviceIdent" || tok == "0" {
			continue
		}
		if model == "" && sickModelTokenRe.MatchString(tok) && !sickVersionRe.MatchString(tok) {
			model = tok
			continue
		}
		if model != "" && firmware == "" && sickVersionRe.MatchString(tok) {
			firmware = tok
			break
		}
	}
	if model == "" {
		model = "SOPAS Auto-ID / LiDAR"
	}
	return &SICKIdentity{
		Model:    model,
		Firmware: firmware,
		Port:     port,
	}, nil
}

// SICKIdentify probes a single host+port with read-only CoLa-A DeviceIdent.
func SICKIdentify(ip string, port int, timeout time.Duration) (*SICKIdentity, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildCoLaADeviceIdent()); err != nil {
		return nil, nil
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, nil
	}
	return parseCoLaDeviceIdentResponse(buf[:n], port)
}

func discoverSICK(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	ports := []int{SICKPortA, SICKPortB}
	openByIP := make(map[string]int)
	for _, p := range ports {
		for _, ip := range ScanPorts(ips, p, timeout, concurrency) {
			if _, exists := openByIP[ip]; !exists {
				openByIP[ip] = p
			}
		}
	}
	if progress != nil {
		progress(fmt.Sprintf("SICK SOPAS: %d/%d hosts with TCP/2111-2112 open", len(openByIP), len(ips)))
	}
	if len(openByIP) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		devices []inventory.Device
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for ip, firstPort := range openByIP {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string, firstPort int) {
			defer wg.Done()
			defer func() { <-sem }()

			tryOrder := []int{firstPort}
			if firstPort == SICKPortA {
				tryOrder = append(tryOrder, SICKPortB)
			} else {
				tryOrder = append(tryOrder, SICKPortA)
			}

			for _, p := range tryOrder {
				id, err := SICKIdentify(ip, p, timeout)
				if err == nil && id != nil {
					mu.Lock()
					devices = append(devices, inventory.Device{
						IP:       ip,
						Vendor:   "SICK",
						Model:    id.Model,
						Firmware: id.Firmware,
						Protocol: "sick",
						Port:     id.Port,
					})
					mu.Unlock()
					return
				}
			}
		}(ip, firstPort)
	}
	wg.Wait()
	return devices
}
