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

// GE-SRTP (Service Request Transport Protocol) constants.
// Used by Emerson / GE PACSystems, Series 90, and VersaMax PLCs on TCP 18245.
const (
	// Packet types (byte 0)
	srtpTypeInitACK    byte = 0x01
	srtpTypeRequest    byte = 0x02
	srtpTypeRequestACK byte = 0x03

	// Message types (byte 31)
	srtpMsgShort    byte = 0xC0 // Short request
	srtpMsgShortACK byte = 0xD4 // Short response
	srtpMsgShortErr byte = 0xD1 // Error response

	// Service request codes (byte 42 for SHORT messages)
	srtpSvcControllerType byte = 0x43 // Return Controller Type
	srtpSvcProgramName    byte = 0x03 // Return Program Name

	// Frame size — all SRTP frames use a fixed 56-byte header
	srtpFrameSize = 56
)

// SRTPIdentity holds identification data from GE-SRTP Controller Data Read.
type SRTPIdentity struct {
	TypeCode uint16
	Model    string
}

// Known GE/Emerson controller type codes mapped to product names.
// Values sourced from Wireshark ge-srtp dissector and GE documentation.
var srtpControllerTypes = map[uint16]string{
	// Series 90-30
	0x09: "Series 90-30 CPU (IC693)",
	0x0A: "Series 90-30 CPU (IC693)",
	// Series 90-70
	0x06: "Series 90-70 CPU (IC697)",
	0x07: "Series 90-70 CPU (IC697)",
	// PACSystems RX3i
	0x60: "PACSystems RX3i (IC695)",
	0x61: "PACSystems RX3i (IC695)",
	0x62: "PACSystems RX3i CPE330",
	0x63: "PACSystems RX3i CPE400",
	// PACSystems RX7i
	0x70: "PACSystems RX7i (IC698)",
	0x71: "PACSystems RX7i (IC698)",
	// PACSystems RSTi-EP CPE100/CPE115
	0x80: "PACSystems RSTi-EP CPE100",
	0x81: "PACSystems RSTi-EP CPE115",
	// VersaMax
	0x20: "VersaMax (IC200)",
	0x21: "VersaMax Micro (IC200)",
}

// buildSRTPInitFrame returns the 56-byte INIT frame (all zeros).
func buildSRTPInitFrame() []byte {
	return make([]byte, srtpFrameSize)
}

// buildSRTPRequest constructs a 56-byte SHORT service request.
//
//	Byte 0:  0x02 (REQUEST)
//	Byte 2:  0x06 (sequence number)
//	Byte 9:  0x01 (constant for reads)
//	Byte 17: 0x01 (constant for reads)
//	Byte 30: 0x06 (message sequence)
//	Byte 31: 0xC0 (SHORT message type)
//	Bytes 36-39: 0x100E0000 (mailbox destination)
//	Byte 40: 0x01 (packet 1 of 1)
//	Byte 41: 0x01 (total packets)
//	Byte 42: service code
func buildSRTPRequest(serviceCode byte) []byte {
	msg := make([]byte, srtpFrameSize)
	msg[0] = srtpTypeRequest
	msg[2] = 0x06  // Sequence number
	msg[9] = 0x01  // Read constant
	msg[17] = 0x01 // Read constant
	msg[30] = 0x06 // Message sequence
	msg[31] = srtpMsgShort
	msg[36] = 0x10 // Mailbox destination
	msg[37] = 0x0E
	msg[40] = 0x01 // Packet 1 of 1
	msg[41] = 0x01
	msg[42] = serviceCode
	return msg
}

// parseSRTPInitResponse validates an INIT_ACK response.
func parseSRTPInitResponse(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("empty SRTP response")
	}
	if data[0] != srtpTypeInitACK {
		return fmt.Errorf("not INIT_ACK: type=0x%02X", data[0])
	}
	return nil
}

// parseSRTPServiceResponse validates a service request response and returns
// the inline data (bytes 44-49 of a SHORT_ACK) plus any extended payload.
func parseSRTPServiceResponse(data []byte) ([]byte, error) {
	if len(data) < srtpFrameSize {
		return nil, fmt.Errorf("SRTP response too short: %d bytes", len(data))
	}
	if data[0] != srtpTypeRequestACK {
		return nil, fmt.Errorf("not a request ACK: type=0x%02X", data[0])
	}
	if data[31] == srtpMsgShortErr {
		return nil, fmt.Errorf("SRTP error response")
	}

	// Inline data from SHORT_ACK is at bytes 44-49 (6 bytes)
	inline := data[44:50]

	// Check for extended payload after the 56-byte header
	textLen := binary.LittleEndian.Uint16(data[4:6])
	if textLen > 0 && len(data) >= srtpFrameSize+int(textLen) {
		return append(inline, data[srtpFrameSize:srtpFrameSize+int(textLen)]...), nil
	}

	return inline, nil
}

// parseControllerTypeData extracts a controller identity from the response payload.
func parseControllerTypeData(payload []byte) *SRTPIdentity {
	if len(payload) < 2 {
		return &SRTPIdentity{Model: "PLC"}
	}

	typeCode := binary.LittleEndian.Uint16(payload[0:2])
	model := srtpControllerName(typeCode)

	return &SRTPIdentity{TypeCode: typeCode, Model: model}
}

// parseProgramNameData extracts the program name from a Return Program Name response.
func parseProgramNameData(payload []byte) string {
	name := strings.TrimRight(string(payload), " \x00")
	// Limit to printable ASCII
	var clean []byte
	for _, b := range []byte(name) {
		if b >= 0x20 && b < 0x7F {
			clean = append(clean, b)
		}
	}
	return string(clean)
}

func srtpControllerName(typeCode uint16) string {
	if name, ok := srtpControllerTypes[typeCode]; ok {
		return name
	}
	if typeCode == 0 {
		return "PLC"
	}
	return fmt.Sprintf("PLC (type 0x%04X)", typeCode)
}

// SRTPIdentify connects to a single IP via GE-SRTP and returns device identity.
// Returns nil, nil if the host doesn't respond or doesn't speak SRTP.
func SRTPIdentify(ip string, timeout time.Duration) (*SRTPIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", SRTPPort))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	buf := make([]byte, 512)

	// Step 1: INIT handshake (56 bytes of zeros)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildSRTPInitFrame()); err != nil {
		return nil, nil
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil
	}
	if err := parseSRTPInitResponse(buf[:n]); err != nil {
		return nil, nil
	}

	// Step 2: Controller Type request (service 0x43)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildSRTPRequest(srtpSvcControllerType)); err != nil {
		return nil, nil
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err = conn.Read(buf)
	if err != nil {
		return nil, nil
	}

	payload, err := parseSRTPServiceResponse(buf[:n])
	if err != nil {
		// Controller Type failed — device speaks SRTP but rejected the request.
		// Still report it as a GE/Emerson PLC.
		return &SRTPIdentity{Model: "PLC"}, nil
	}

	return parseControllerTypeData(payload), nil
}

func srtpIdentityToDevice(ip string, id *SRTPIdentity) inventory.Device {
	return inventory.Device{
		IP:     ip,
		Vendor: "Emerson / GE",
		Model:  id.Model,
	}
}

func discoverSRTP(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("SRTP: scanning %d hosts for TCP/%d", len(ips), SRTPPort))
	}

	// TCP-based: pre-scan port first
	open := ScanPorts(ips, SRTPPort, timeout, concurrency)

	if progress != nil {
		progress(fmt.Sprintf("SRTP: %d hosts have port %d open", len(open), SRTPPort))
	}

	if len(open) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		devices []inventory.Device
		sem     = make(chan struct{}, concurrency)
	)

	for _, ip := range open {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id, err := SRTPIdentify(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := srtpIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()

			if progress != nil {
				progress(fmt.Sprintf("SRTP: %s → %s %s", ip, dev.Vendor, dev.Model))
			}
		}(ip)
	}

	wg.Wait()
	return devices
}
