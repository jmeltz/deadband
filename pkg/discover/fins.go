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

// FINS/UDP protocol constants
const (
	finsICFCommand  byte = 0x80 // Command frame, response required
	finsICFResponse byte = 0xC0 // Response frame mask
	finsGCTDefault  byte = 0x02 // Default permitted gateway count

	finsMRCControllerRead byte = 0x05 // Controller Data Read MRC
	finsSRCControllerRead byte = 0x01 // Controller Data Read SRC

	finsModelLen   = 20 // Controller model field length (ASCII, space/null padded)
	finsVersionLen = 20 // Controller version field length (ASCII, space/null padded)
)

// FINSIdentity holds identification data from a FINS Controller Data Read response.
type FINSIdentity struct {
	Model   string
	Version string
}

// buildFINSHeader constructs a 10-byte FINS header for a command frame.
//
//	Byte 0: ICF (0x80 = command, response required)
//	Byte 1: RSV (0x00)
//	Byte 2: GCT (gateway count)
//	Byte 3: DNA (destination network, 0x00 = local)
//	Byte 4: DA1 (destination node)
//	Byte 5: DA2 (destination unit, 0x00 = CPU)
//	Byte 6: SNA (source network, 0x00 = local)
//	Byte 7: SA1 (source node)
//	Byte 8: SA2 (source unit, 0x00)
//	Byte 9: SID (service ID)
func buildFINSHeader(dstNode, srcNode, sid byte) []byte {
	return []byte{
		finsICFCommand, // ICF
		0x00,           // RSV
		finsGCTDefault, // GCT
		0x00,           // DNA: local network
		dstNode,        // DA1: destination node
		0x00,           // DA2: CPU unit
		0x00,           // SNA: local network
		srcNode,        // SA1: source node
		0x00,           // SA2
		sid,            // SID
	}
}

// buildControllerDataReadRequest builds a FINS/UDP Controller Data Read (0501) request.
// This command returns the controller model and firmware version with no parameters.
func buildControllerDataReadRequest(dstNode, srcNode byte) []byte {
	header := buildFINSHeader(dstNode, srcNode, 0x01)
	return append(header, finsMRCControllerRead, finsSRCControllerRead)
}

// ParseFINSResponse validates a FINS response frame and returns the end code and payload.
// Minimum frame: 10 (header) + 2 (command) + 2 (end code) = 14 bytes.
func ParseFINSResponse(data []byte, expectedMRC, expectedSRC byte) (uint16, []byte, error) {
	if len(data) < 14 {
		return 0, nil, fmt.Errorf("FINS response too short: %d bytes", len(data))
	}

	// ICF bit 6 must be set for a response
	if data[0]&finsICFResponse != finsICFResponse {
		return 0, nil, fmt.Errorf("not a FINS response: ICF=0x%02X", data[0])
	}

	// Verify echoed command code
	if data[10] != expectedMRC || data[11] != expectedSRC {
		return 0, nil, fmt.Errorf("unexpected command: %02X%02X (expected %02X%02X)",
			data[10], data[11], expectedMRC, expectedSRC)
	}

	endCode := binary.BigEndian.Uint16(data[12:14])
	return endCode, data[14:], nil
}

// ParseControllerDataRead extracts model and version from a Controller Data Read payload.
// Layout: 20 bytes model (ASCII, padded) + 20 bytes version (ASCII, padded).
func ParseControllerDataRead(payload []byte) (*FINSIdentity, error) {
	if len(payload) < finsModelLen+finsVersionLen {
		return nil, fmt.Errorf("controller data too short: %d bytes (need %d)", len(payload), finsModelLen+finsVersionLen)
	}

	model := strings.TrimRight(string(payload[:finsModelLen]), " \x00")
	version := strings.TrimRight(string(payload[finsModelLen:finsModelLen+finsVersionLen]), " \x00")

	return &FINSIdentity{Model: model, Version: version}, nil
}

// lastOctet extracts the last octet from an IPv4 address string.
func lastOctet(ip string) byte {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0
	}
	return v4[3]
}

// FINSIdentify sends a Controller Data Read to a single IP over UDP and returns
// the device identity. Returns nil, nil if the host doesn't respond.
func FINSIdentify(ip string, timeout time.Duration) (*FINSIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", FINSPort))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	// DA1 = last octet of target IP (standard FINS/UDP node addressing)
	dstNode := lastOctet(ip)
	srcNode := byte(0xFE) // 254: common for external tools

	req := buildControllerDataReadRequest(dstNode, srcNode)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return nil, nil
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil // Timeout — host doesn't speak FINS
	}

	endCode, payload, err := ParseFINSResponse(buf[:n], finsMRCControllerRead, finsSRCControllerRead)
	if err != nil {
		return nil, nil
	}

	if endCode != 0x0000 {
		return nil, nil
	}

	return ParseControllerDataRead(payload)
}

// FINSIdentityToDevice converts a FINSIdentity to an inventory.Device.
func FINSIdentityToDevice(ip string, id *FINSIdentity) inventory.Device {
	return inventory.Device{
		IP:       ip,
		Vendor:   "Omron",
		Model:    id.Model,
		Firmware: id.Version,
		Protocol: "fins",
		Port:     FINSPort,
	}
}

func discoverFINS(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("FINS: probing %d hosts on UDP/%d", len(ips), FINSPort))
	}

	// UDP-based: no TCP port pre-scan. Send FINS directly to each IP.
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

			id, err := FINSIdentify(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := FINSIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()

			if progress != nil {
				progress(fmt.Sprintf("FINS: %s → %s %s (fw %s)", ip, dev.Vendor, dev.Model, dev.Firmware))
			}
		}(ip)
	}

	wg.Wait()
	return devices
}
