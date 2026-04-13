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

// S7comm protocol constants
const (
	tpktVersion    = 0x03
	cotpCR         = 0xE0 // Connection Request
	cotpCC         = 0xD0 // Connection Confirm
	cotpDR         = 0x80 // Disconnect Request (reject)
	cotpDT         = 0xF0 // Data Transfer
	s7ProtocolID   = 0x32
	s7MsgJob       = 0x01 // Job Request
	s7MsgAckData   = 0x03 // Ack-Data
	s7FuncSetup    = 0xF0 // Setup Communication
	s7FuncReadSZL  = 0x04 // Read SZL
	s7SubReadSZL   = 0x01
	szlComponentID = 0x001C // Component Identification
)

// S7Identity holds parsed identity fields from an S7comm SZL read.
type S7Identity struct {
	ModuleName      string // e.g. "CPU 1214C DC/DC/DC"
	OrderNumber     string // MLFB e.g. "6ES7 214-1AG40-0XB0"
	FirmwareVersion string // e.g. "V4.5.2"
	SerialNumber    string
}

// --- Frame builders ---

// buildTPKT wraps payload with a 4-byte TPKT header.
func buildTPKT(payload []byte) []byte {
	length := 4 + len(payload)
	buf := make([]byte, length)
	buf[0] = tpktVersion
	buf[1] = 0 // reserved
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	copy(buf[4:], payload)
	return buf
}

// buildCOTPConnectRequest builds a COTP Connection Request with TSAP parameters.
// rack and slot encode the target PLC addressing.
func buildCOTPConnectRequest(rack, slot int) []byte {
	// COTP CR PDU: length, PDU type, dst-ref, src-ref, class/option, + TSAP params
	srcTSAP := uint16(0x0100)
	dstTSAP := uint16(0x0100) | uint16(rack<<5) | uint16(slot)

	cotp := []byte{
		17,     // COTP length (remaining bytes after this)
		cotpCR, // PDU type
		0x00, 0x00, // Destination reference
		0x00, 0x01, // Source reference
		0x00, // Class 0, no extended formats
		// Parameter: src-tsap
		0xC1, 0x02, byte(srcTSAP >> 8), byte(srcTSAP),
		// Parameter: dst-tsap
		0xC2, 0x02, byte(dstTSAP >> 8), byte(dstTSAP),
		// Parameter: TPDU size
		0xC0, 0x01, 0x0A, // 1024 bytes
	}
	return buildTPKT(cotp)
}

// buildS7SetupCommunication builds the S7 Setup Communication request.
func buildS7SetupCommunication() []byte {
	// COTP Data header (3 bytes)
	cotp := []byte{0x02, cotpDT, 0x80} // length=2, DT, last fragment

	// S7 header (10 bytes) + Setup parameters (8 bytes)
	s7 := []byte{
		s7ProtocolID, // Protocol ID
		s7MsgJob,     // Message type: Job
		0x00, 0x00,   // Reserved
		0x00, 0x01, // PDU reference
		0x00, 0x08, // Parameter length (8 bytes)
		0x00, 0x00, // Data length (0)
		// Parameters: Setup Communication
		s7FuncSetup, // Function
		0x00,        // Reserved
		0x00, 0x01,  // Max AMQ calling
		0x00, 0x01,  // Max AMQ called
		0x01, 0xE0,  // PDU size: 480
	}

	payload := append(cotp, s7...)
	return buildTPKT(payload)
}

// buildSZLReadRequest builds an S7 SZL Read request for the given SZL-ID and index.
func buildSZLReadRequest(szlID, szlIndex uint16) []byte {
	cotp := []byte{0x02, cotpDT, 0x80}

	s7 := []byte{
		s7ProtocolID,
		s7MsgJob,
		0x00, 0x00, // Reserved
		0x00, 0x02, // PDU reference
		0x00, 0x08, // Parameter length (8 bytes)
		0x00, 0x04, // Data length (4 bytes)
		// Parameters
		s7FuncReadSZL,
		s7SubReadSZL,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sequence number + reserved
		// Data: SZL request
		0x00, 0x00, // SZL-ID placeholder
		0x00, 0x00, // SZL-Index placeholder
	}

	binary.BigEndian.PutUint16(s7[18:20], szlID)
	binary.BigEndian.PutUint16(s7[20:22], szlIndex)

	payload := append(cotp, s7...)
	return buildTPKT(payload)
}

// --- Parsers ---

// ParseTPKT validates and strips the TPKT header, returning the payload.
func ParseTPKT(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("TPKT too short: %d bytes", len(data))
	}
	if data[0] != tpktVersion {
		return nil, fmt.Errorf("TPKT version %d, want %d", data[0], tpktVersion)
	}
	length := binary.BigEndian.Uint16(data[2:4])
	if int(length) > len(data) {
		return nil, fmt.Errorf("TPKT length %d exceeds data %d", length, len(data))
	}
	return data[4:length], nil
}

// parseCOTPResponse validates a COTP response and returns the PDU type.
func parseCOTPResponse(data []byte) (byte, []byte, error) {
	payload, err := ParseTPKT(data)
	if err != nil {
		return 0, nil, err
	}
	if len(payload) < 2 {
		return 0, nil, fmt.Errorf("COTP too short: %d bytes", len(payload))
	}
	pduLen := int(payload[0])
	pduType := payload[1]
	if len(payload) < pduLen+1 {
		return 0, nil, fmt.Errorf("COTP truncated")
	}
	return pduType, payload[pduLen+1:], nil
}

// parseS7SetupResponse validates an S7 Setup Communication response.
func parseS7SetupResponse(data []byte) error {
	pduType, s7Data, err := parseCOTPResponse(data)
	if err != nil {
		return err
	}
	if pduType != cotpDT {
		return fmt.Errorf("expected COTP DT (0x%02X), got 0x%02X", cotpDT, pduType)
	}
	if len(s7Data) < 10 {
		return fmt.Errorf("S7 response too short: %d bytes", len(s7Data))
	}
	if s7Data[0] != s7ProtocolID {
		return fmt.Errorf("S7 protocol ID 0x%02X, want 0x%02X", s7Data[0], s7ProtocolID)
	}
	if s7Data[1] != s7MsgAckData {
		return fmt.Errorf("S7 msg type 0x%02X, want 0x%02X (Ack-Data)", s7Data[1], s7MsgAckData)
	}
	return nil
}

// ParseSZLResponse parses an SZL 0x001C response into an S7Identity.
func ParseSZLResponse(data []byte) (*S7Identity, error) {
	pduType, s7Data, err := parseCOTPResponse(data)
	if err != nil {
		return nil, err
	}
	if pduType != cotpDT {
		return nil, fmt.Errorf("expected COTP DT, got 0x%02X", pduType)
	}
	// S7 header: 12 bytes (10 header + 2 error code for ack-data)
	if len(s7Data) < 12 {
		return nil, fmt.Errorf("S7 SZL response too short: %d bytes", len(s7Data))
	}
	if s7Data[0] != s7ProtocolID {
		return nil, fmt.Errorf("S7 protocol ID 0x%02X, want 0x%02X", s7Data[0], s7ProtocolID)
	}
	if s7Data[1] != s7MsgAckData {
		return nil, fmt.Errorf("S7 msg type 0x%02X, want Ack-Data", s7Data[1])
	}

	paramLen := binary.BigEndian.Uint16(s7Data[6:8])
	dataLen := binary.BigEndian.Uint16(s7Data[8:10])

	// Skip past header (10 bytes) + error class/code (2 bytes) + parameters
	offset := 12 + int(paramLen)
	if offset+int(dataLen) > len(s7Data) {
		return nil, fmt.Errorf("S7 SZL data truncated")
	}

	// SZL data starts with: return code (1), transport size (1), data length (2)
	szlData := s7Data[offset:]
	if len(szlData) < 4 {
		return nil, fmt.Errorf("SZL data header too short")
	}
	if szlData[0] != 0xFF {
		return nil, fmt.Errorf("SZL return code 0x%02X, want 0xFF (success)", szlData[0])
	}

	szlPayloadLen := binary.BigEndian.Uint16(szlData[2:4])
	szlPayload := szlData[4:]
	if len(szlPayload) < int(szlPayloadLen) {
		return nil, fmt.Errorf("SZL payload truncated")
	}
	szlPayload = szlPayload[:szlPayloadLen]

	// SZL header: SZL-ID (2) + entry count (2) + entry length (2)
	if len(szlPayload) < 6 {
		return nil, fmt.Errorf("SZL list header too short")
	}
	entryCount := binary.BigEndian.Uint16(szlPayload[2:4])
	entryLen := binary.BigEndian.Uint16(szlPayload[4:6])
	entries := szlPayload[6:]

	id := &S7Identity{}
	for i := 0; i < int(entryCount); i++ {
		start := i * int(entryLen)
		if start+int(entryLen) > len(entries) {
			break
		}
		entry := entries[start : start+int(entryLen)]
		if len(entry) < 2 {
			continue
		}
		index := binary.BigEndian.Uint16(entry[0:2])
		// The value field starts at byte 2, null-terminated string in fixed-width field
		value := extractNullTerminated(entry[2:])

		switch index {
		case 1: // Order number (MLFB)
			id.OrderNumber = value
		case 2: // Module name
			id.ModuleName = value
		case 3: // Plant identification / serial
			id.SerialNumber = value
		case 7: // Firmware version
			id.FirmwareVersion = value
		}
	}

	return id, nil
}

// extractNullTerminated extracts a string from a null-padded fixed-width field.
func extractNullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return strings.TrimSpace(string(b[:i]))
		}
	}
	return strings.TrimSpace(string(b))
}

// --- Scanner ---

// S7Identify performs the full S7comm identification handshake against a single IP.
// Returns nil, nil if the host is not an S7 PLC (connection refused, wrong protocol).
func S7Identify(ip string, timeout time.Duration) (*S7Identity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", S7Port))

	// Try S7-300/400 TSAP first (rack 0, slot 2), then S7-1200/1500 (rack 0, slot 0)
	tsaps := [][2]int{{0, 2}, {0, 0}}

	for _, tsap := range tsaps {
		id, err := s7Handshake(addr, tsap[0], tsap[1], timeout)
		if err == nil && id != nil {
			return id, nil
		}
		// If connection was refused or timed out on first try, no point retrying
		if err != nil && !isCOTPReject(err) {
			return nil, nil
		}
	}
	return nil, nil
}

func isCOTPReject(err error) bool {
	return err != nil && strings.Contains(err.Error(), "COTP rejected")
}

func s7Handshake(addr string, rack, slot int, timeout time.Duration) (*S7Identity, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 2048)

	// Phase 1: COTP Connection Request
	if _, err := conn.Write(buildCOTPConnectRequest(rack, slot)); err != nil {
		return nil, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	pduType, _, err := parseCOTPResponse(buf[:n])
	if err != nil {
		return nil, err
	}
	if pduType == cotpDR {
		return nil, fmt.Errorf("COTP rejected")
	}
	if pduType != cotpCC {
		return nil, fmt.Errorf("unexpected COTP PDU type 0x%02X", pduType)
	}

	// Phase 2: S7 Setup Communication
	if _, err := conn.Write(buildS7SetupCommunication()); err != nil {
		return nil, err
	}
	n, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if err := parseS7SetupResponse(buf[:n]); err != nil {
		return nil, err
	}

	// Phase 3: SZL Read (Component Identification)
	if _, err := conn.Write(buildSZLReadRequest(szlComponentID, 0x0000)); err != nil {
		return nil, err
	}
	n, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return ParseSZLResponse(buf[:n])
}

// S7IdentityToDevice converts an S7Identity to an inventory.Device.
func S7IdentityToDevice(ip string, id *S7Identity) inventory.Device {
	model := id.ModuleName
	if model == "" {
		model = id.OrderNumber
	}

	fw := id.FirmwareVersion
	// Strip leading "V" prefix for consistency (e.g. "V4.5.2" → "4.5.2")
	fw = strings.TrimPrefix(fw, "V")
	fw = strings.TrimPrefix(fw, "v")

	return inventory.Device{
		IP:       ip,
		Vendor:   "Siemens",
		Model:    model,
		Firmware: fw,
	}
}

// discoverS7 performs S7comm discovery across a set of IPs.
// First does a TCP port scan on 102 to find responsive hosts, then runs
// the full S7 handshake concurrently on open hosts.
func discoverS7(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("S7comm scanning %d hosts on port %d...", len(ips), S7Port))
	}

	openHosts := ScanPorts(ips, S7Port, timeout, concurrency)

	if progress != nil {
		progress(fmt.Sprintf("S7comm found %d hosts with port %d open", len(openHosts), S7Port))
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

			id, err := S7Identify(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := S7IdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	if progress != nil {
		progress(fmt.Sprintf("S7comm identified %d Siemens devices", len(devices)))
	}

	return devices
}
