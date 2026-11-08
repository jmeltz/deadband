package discover

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// SICK SOPAS CoLa-A / CoLa-B / CoLa-2 Read-Only Auto-ID & LiDAR Probe (TCP/2111, 2112, 2122).
//
// Used heavily across KNAPP, Swisslog, Dematic, and Vanderlande conveyor barcode tunnels
// (MSC800, CLV6xx, ICR890, Lector65x) and AMR safety/navigation LiDARs (microScan3, nanoScan3).
// Strictly read-only: sends CoLa-A/B "sRN DeviceIdent" or CoLa-2 "RN DeviceIdent".
// Never sends sWN/WN (Write) or sMN/MN (Method Invocation).

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

// buildCoLaBDeviceIdent builds a binary CoLa-B Read-by-Name DeviceIdent frame:
// 4x STX (0x02) + 4-byte BE length + "sRN DeviceIdent" + 1-byte XOR checksum.
func buildCoLaBDeviceIdent() []byte {
	body := []byte("sRN DeviceIdent")
	var xor byte
	for _, b := range body {
		xor ^= b
	}
	frame := make([]byte, 8+len(body)+1)
	copy(frame[0:4], []byte{0x02, 0x02, 0x02, 0x02})
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[8:8+len(body)], body)
	frame[8+len(body)] = xor
	return frame
}

// buildCoLa2DeviceIdent builds a read-only CoLa-2 "RN" (Read Variable by Name)
// request for "DeviceIdent" on TCP/2122 (no trailing checksum in CoLa-2).
func buildCoLa2DeviceIdent(reqID uint16) []byte {
	varName := []byte("DeviceIdent")
	// HubCntr(1)=0 + NoC(1)=0 + SessionID(4)=0 + ReqID(2 LE) + Cmd("RN", 2) + NameLen(2 LE) + Name(11) = 23 bytes
	body := make([]byte, 12+len(varName))
	body[0] = 0x00 // HubCntr
	body[1] = 0x00 // NoC
	binary.LittleEndian.PutUint32(body[2:6], 0)
	binary.LittleEndian.PutUint16(body[6:8], reqID)
	body[8] = 'R'
	body[9] = 'N'
	binary.LittleEndian.PutUint16(body[10:12], uint16(len(varName)))
	copy(body[12:], varName)

	frame := make([]byte, 8+len(body))
	copy(frame[0:4], []byte{0x02, 0x02, 0x02, 0x02})
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[8:], body)
	return frame
}

// ParseSICKCoLaFrame parses a CoLa-A, CoLa-B, or CoLa-2 response frame.
func ParseSICKCoLaFrame(raw []byte, port int) (*SICKIdentity, error) {
	if id, err := parseCoLa2Response(raw, port); err == nil && id != nil {
		return id, nil
	}
	return parseCoLaDeviceIdentResponse(raw, port)
}

func parseCoLa2Response(raw []byte, port int) (*SICKIdentity, error) {
	start := bytes.Index(raw, []byte{0x02, 0x02, 0x02, 0x02})
	if start < 0 || len(raw[start:]) < 18 {
		return nil, fmt.Errorf("not a CoLa-2 frame")
	}
	sub := raw[start:]
	beLen := int(binary.BigEndian.Uint32(sub[4:8]))
	leLen := int(binary.LittleEndian.Uint32(sub[4:8]))
	bodyLen := len(sub) - 8
	if beLen > 0 && 8+beLen <= len(sub) {
		bodyLen = beLen
	} else if leLen > 0 && 8+leLen <= len(sub) {
		bodyLen = leLen
	}
	body := sub[8 : 8+bodyLen]
	if len(body) < 10 {
		return nil, fmt.Errorf("CoLa-2 body too short")
	}

	// Skip HubCntr(1) + NoC(1) + NoC routing bytes + SessionID(4) + ReqID(2)
	noc := int(body[1])
	hdrOff := 2 + noc + 4 + 2
	if hdrOff+2 > len(body) {
		return nil, fmt.Errorf("CoLa-2 header truncated")
	}
	cmd := string(body[hdrOff : hdrOff+2])
	if cmd == "FA" {
		return &SICKIdentity{
			Model: "SOPAS CoLa-2 Sensor",
			Port:  port,
		}, nil
	}
	if cmd != "RA" && cmd != "OA" {
		return nil, fmt.Errorf("not a CoLa-2 Read/Open Answer: %q", cmd)
	}
	payload := body[hdrOff+2:]

	// First try structured CoLa-2 FlexString decoding: [uint16 LE len][name][uint16 LE len][version]
	if len(payload) >= 4 {
		nLen := int(binary.LittleEndian.Uint16(payload[0:2]))
		if nLen > 0 && nLen <= 64 && 2+nLen <= len(payload) {
			name := strings.TrimSpace(string(payload[2 : 2+nLen]))
			ver := ""
			rem := payload[2+nLen:]
			if len(rem) >= 2 {
				vLen := int(binary.LittleEndian.Uint16(rem[0:2]))
				if vLen > 0 && vLen <= 64 && 2+vLen <= len(rem) {
					ver = strings.TrimSpace(string(rem[2 : 2+vLen]))
				}
			}
			if sickModelTokenRe.MatchString(name) {
				return &SICKIdentity{
					Model:    name,
					Firmware: ver,
					Port:     port,
				}, nil
			}
		}
	}

	// Fallback: tokenize printable ASCII in CoLa-2 RA payload
	model, fw := extractSICKModelAndFirmware(payload)
	if model == "" {
		model = "SOPAS CoLa-2 Sensor"
	}
	return &SICKIdentity{
		Model:    model,
		Firmware: fw,
		Port:     port,
	}, nil
}

func extractSICKModelAndFirmware(payload []byte) (string, string) {
	var sb strings.Builder
	for _, b := range payload {
		if b >= 0x20 && b < 0x7f {
			sb.WriteByte(b)
		} else {
			sb.WriteByte(' ')
		}
	}
	tokens := strings.Fields(sb.String())
	model := ""
	firmware := ""
	for _, rawTok := range tokens {
		tok := strings.Trim(rawTok, "\"'")
		if tok == "sRA" || tok == "RA" || tok == "DeviceIdent" || tok == "0" {
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
	return model, firmware
}

func parseCoLaDeviceIdentResponse(raw []byte, port int) (*SICKIdentity, error) {
	if len(raw) < 6 {
		return nil, fmt.Errorf("CoLa response too short")
	}

	var payload []byte
	if start := bytes.IndexByte(raw, 0x02); start >= 0 {
		if bytes.HasPrefix(raw[start:], []byte{0x02, 0x02, 0x02, 0x02}) && len(raw[start:]) >= 10 {
			// CoLa-B binary framing: 4x STX + 4-byte BE length + payload + 1-byte XOR checksum
			bodyLen := int(binary.BigEndian.Uint32(raw[start+4 : start+8]))
			if bodyLen > 0 && start+8+bodyLen <= len(raw) {
				payload = raw[start+8 : start+8+bodyLen]
			} else {
				// Strip trailing 1-byte XOR checksum if truncated
				payload = raw[start+8 : len(raw)-1]
			}
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
		return &SICKIdentity{
			Model: "SOPAS Sensor",
			Port:  port,
		}, nil
	}

	model, firmware := extractSICKModelAndFirmware(payload)
	if model == "" {
		model = "SOPAS Auto-ID / LiDAR"
	}
	return &SICKIdentity{
		Model:    model,
		Firmware: firmware,
		Port:     port,
	}, nil
}

func sickQueryOnce(addr string, req []byte, port int, timeout time.Duration) (*SICKIdentity, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("empty SICK response")
	}
	return ParseSICKCoLaFrame(buf[:n], port)
}

// SICKIdentify probes a single host+port with read-only CoLa-A, CoLa-B, or CoLa-2 DeviceIdent.
func SICKIdentify(ip string, port int, timeout time.Duration) (*SICKIdentity, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	if port == SICKPortCoLa2 {
		id, err := sickQueryOnce(addr, buildCoLa2DeviceIdent(1), port, timeout)
		if err == nil && id != nil {
			return id, nil
		}
		return nil, nil
	}

	// On 2111/2112 (or custom test ports): try CoLa-A first, then CoLa-B binary fallback, then CoLa-2
	perAttempt := timeout
	if perAttempt > 800*time.Millisecond {
		perAttempt = 800 * time.Millisecond
	}
	for _, req := range [][]byte{buildCoLaADeviceIdent(), buildCoLaBDeviceIdent(), buildCoLa2DeviceIdent(1)} {
		if id, err := sickQueryOnce(addr, req, port, perAttempt); err == nil && id != nil {
			return id, nil
		}
	}
	return nil, nil
}

func discoverSICK(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	ports := []int{SICKPortB, SICKPortA, SICKPortCoLa2}
	openByIP := make(map[string][]int)
	for _, p := range ports {
		for _, ip := range ScanPorts(ips, p, timeout, concurrency) {
			openByIP[ip] = append(openByIP[ip], p)
		}
	}
	if progress != nil {
		progress(fmt.Sprintf("SICK SOPAS: %d/%d hosts with TCP/2111, 2112, or 2122 open", len(openByIP), len(ips)))
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

	for ip, openPorts := range openByIP {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string, openPorts []int) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, p := range openPorts {
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
		}(ip, openPorts)
	}
	wg.Wait()
	return devices
}
