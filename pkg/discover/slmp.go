package discover

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// SLMP (Seamless Message Protocol) constants — 3E binary frame format.
// Used by Mitsubishi MELSEC iQ-R, iQ-F, Q, L, and FX5 series PLCs.
const (
	// Subheaders
	slmpReqSubheader  = 0x50 // 3E binary request: 0x50 0x00
	slmpRespSubheader = 0xD0 // 3E binary response: 0xD0 0x00

	// Default addressing (own station)
	slmpNetworkNo = 0x00
	slmpStationNo = 0xFF

	// Monitoring timer: units of 250ms (0x0010 = 4s)
	slmpTimer = 0x0010

	// Commands
	slmpCmdReadTypeName = 0x0101 // Read CPU Model Name

	// End codes
	slmpEndCodeSuccess = 0x0000
)

// SLMPIdentity holds parsed identity from an SLMP Read Type Name response.
type SLMPIdentity struct {
	ModelName string // e.g. "R04CPU", "Q03UDVCPU", "FX5U-32MT/ES"
	TypeCode  uint16 // CPU type code (if present in response)
}

// --- Frame builders ---

// buildSLMPRequest constructs a complete SLMP 3E binary request frame.
func buildSLMPRequest(command, subcommand uint16, data []byte) []byte {
	// Data length = timer(2) + command(2) + subcommand(2) + extra data
	dataLen := 2 + 2 + 2 + len(data)

	frame := make([]byte, 9+dataLen)

	// Subheader
	frame[0] = slmpReqSubheader
	frame[1] = 0x00

	// Addressing
	frame[2] = slmpNetworkNo
	frame[3] = slmpStationNo
	binary.LittleEndian.PutUint16(frame[4:6], 0x03FF) // Module I/O (own station)
	frame[6] = 0x00                                     // Multidrop station

	// Data length
	binary.LittleEndian.PutUint16(frame[7:9], uint16(dataLen))

	// Monitoring timer
	binary.LittleEndian.PutUint16(frame[9:11], slmpTimer)

	// Command and subcommand
	binary.LittleEndian.PutUint16(frame[11:13], command)
	binary.LittleEndian.PutUint16(frame[13:15], subcommand)

	if len(data) > 0 {
		copy(frame[15:], data)
	}

	return frame
}

// buildReadTypeNameRequest builds an SLMP Read Type Name request (command 0x0101).
func buildReadTypeNameRequest() []byte {
	return buildSLMPRequest(slmpCmdReadTypeName, 0x0000, nil)
}

// --- Parsers ---

// parseSLMPResponse validates an SLMP 3E binary response and returns the end code and payload.
func parseSLMPResponse(data []byte) (endCode uint16, payload []byte, err error) {
	if len(data) < 11 {
		return 0, nil, fmt.Errorf("SLMP response too short: %d bytes", len(data))
	}

	if data[0] != slmpRespSubheader || data[1] != 0x00 {
		return 0, nil, fmt.Errorf("SLMP subheader 0x%02X%02X, want 0xD000", data[0], data[1])
	}

	dataLen := binary.LittleEndian.Uint16(data[7:9])
	if int(dataLen)+9 > len(data) {
		return 0, nil, fmt.Errorf("SLMP data length %d exceeds frame %d", dataLen, len(data)-9)
	}

	endCode = binary.LittleEndian.Uint16(data[9:11])

	if dataLen > 2 {
		payload = data[11 : 9+int(dataLen)]
	}

	return endCode, payload, nil
}

// parseReadTypeNameResponse extracts the CPU model name from a Read Type Name response.
// The response payload is a 16-byte space/null-padded ASCII model name,
// optionally followed by a 2-byte CPU type code.
func parseReadTypeNameResponse(data []byte) (*SLMPIdentity, error) {
	endCode, payload, err := parseSLMPResponse(data)
	if err != nil {
		return nil, err
	}
	if endCode != slmpEndCodeSuccess {
		return nil, fmt.Errorf("SLMP end code 0x%04X (error)", endCode)
	}
	if len(payload) < 16 {
		return nil, fmt.Errorf("Read Type Name payload too short: %d bytes", len(payload))
	}

	modelName := strings.TrimRight(string(payload[:16]), " \x00")

	var typeCode uint16
	if len(payload) >= 18 {
		typeCode = binary.LittleEndian.Uint16(payload[16:18])
	}

	return &SLMPIdentity{
		ModelName: modelName,
		TypeCode:  typeCode,
	}, nil
}

// --- Scanner ---

// SLMPIdentify performs SLMP identification against a single IP on port 5007.
// Returns nil, nil if the host doesn't respond or isn't a Mitsubishi PLC.
func SLMPIdentify(ip string, timeout time.Duration) (*SLMPIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", SLMPPort))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildReadTypeNameRequest()); err != nil {
		return nil, nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil
	}

	id, err := parseReadTypeNameResponse(buf[:n])
	if err != nil {
		return nil, nil
	}

	if id.ModelName == "" {
		return nil, nil
	}

	return id, nil
}

// slmpIdentityToDevice converts an SLMPIdentity to an inventory.Device.
func slmpIdentityToDevice(ip string, id *SLMPIdentity) inventory.Device {
	return inventory.Device{
		IP:     ip,
		Vendor: "Mitsubishi Electric",
		Model:  id.ModelName,
	}
}

// discoverSLMP performs MELSEC/SLMP device identification across a set of IPs.
// Port-scans TCP 5007 first, then sends Read Type Name to responsive hosts.
func discoverSLMP(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("MELSEC/SLMP scanning %d hosts on port %d...", len(ips), SLMPPort))
	}

	openHosts := ScanPorts(ips, SLMPPort, timeout, concurrency)

	if progress != nil {
		progress(fmt.Sprintf("MELSEC/SLMP found %d hosts with port %d open", len(openHosts), SLMPPort))
	}

	if len(openHosts) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		devices []inventory.Device
	)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range openHosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id, err := SLMPIdentify(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := slmpIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	if progress != nil {
		progress(fmt.Sprintf("MELSEC/SLMP identified %d Mitsubishi devices", len(devices)))
	}

	return devices
}
