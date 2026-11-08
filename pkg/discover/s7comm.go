package discover

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
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
		17,         // COTP length (remaining bytes after this)
		cotpCR,     // PDU type
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
		0x00, 0x01, // Max AMQ called
		0x01, 0xE0, // PDU size: 480
	}

	payload := append(cotp, s7...)
	return buildTPKT(payload)
}

// buildSZLReadRequest builds an S7 SZL Read request for the given SZL-ID and index.
func buildSZLReadRequest(szlID, szlIndex uint16) []byte {
	// CPU functions / Read SZL is UserData (ROSCTR 0x07), not Read Var.
	// The request data carries return/transport/length before ID and index.
	s7 := []byte{0x32, 0x07, 0, 0, 0, 2, 0, 8, 0, 8,
		0, 1, 0x12, 4, 0x11, 0x44, 1, 0,
		0xff, 9, 0, 4, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(s7[22:24], szlID)
	binary.BigEndian.PutUint16(s7[24:26], szlIndex)
	return buildTPKT(append([]byte{2, cotpDT, 0x80}, s7...))
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
	if length < 4 || int(length) > len(data) {
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
	if len(s7Data) < 12 {
		return fmt.Errorf("S7 response too short: %d bytes", len(s7Data))
	}
	if s7Data[0] != s7ProtocolID {
		return fmt.Errorf("S7 protocol ID 0x%02X, want 0x%02X", s7Data[0], s7ProtocolID)
	}
	if s7Data[1] != s7MsgAckData {
		return fmt.Errorf("S7 msg type 0x%02X, want 0x%02X (Ack-Data)", s7Data[1], s7MsgAckData)
	}
	if s7Data[10] != 0 || s7Data[11] != 0 {
		return fmt.Errorf("S7 setup refused: 0x%02x%02x", s7Data[10], s7Data[11])
	}
	return nil
}

// ParseSZLResponse parses an unfragmented UserData SZL 0x001C or 0x0011
// response. Component identity strings and firmware are separate SZLs: 001C
// record 7 is the module type name, never firmware. Layout checked against
// Siemens STEP 7 component-identification documentation and Snap7's public
// read-SZL/client implementation, independently of the synthetic responder personas.
func ParseSZLResponse(data []byte) (*S7Identity, error) {
	if len(data) < 7 || data[4] != 2 || data[6] != 0x80 {
		return nil, fmt.Errorf("unsupported COTP segmentation")
	}
	pduType, s7, err := parseCOTPResponse(data)
	if err != nil {
		return nil, err
	}
	if pduType != cotpDT || len(s7) < 10 || s7[0] != s7ProtocolID || s7[1] != 0x07 {
		return nil, fmt.Errorf("expected S7 UserData SZL response")
	}
	paramLen := int(binary.BigEndian.Uint16(s7[6:8]))
	dataLen := int(binary.BigEndian.Uint16(s7[8:10]))
	if paramLen < 12 || 10+paramLen+dataLen != len(s7) {
		return nil, fmt.Errorf("truncated or unsupported SZL response framing")
	}
	params := s7[10 : 10+paramLen]
	if params[0] != 0 || params[1] != 1 || params[2] != 0x12 || params[3] != 8 || params[4] != 0x12 || params[5] != 0x84 || params[6] != 1 || params[9] != 0 || params[10] != 0 || params[11] != 0 {
		return nil, fmt.Errorf("unsupported, fragmented or refused SZL response")
	}
	szl := s7[10+paramLen:]
	if len(szl) < 12 || szl[0] != 0xff || szl[1] != 9 || int(binary.BigEndian.Uint16(szl[2:4])) != len(szl)-4 {
		return nil, fmt.Errorf("invalid SZL data header")
	}
	payload := szl[4:]
	szlID := binary.BigEndian.Uint16(payload[:2])
	entryLen := int(binary.BigEndian.Uint16(payload[4:6]))
	entryCount := int(binary.BigEndian.Uint16(payload[6:8]))
	entries := payload[8:]
	if entryLen < 2 || entryCount == 0 || entryCount > 4096 || entryLen*entryCount != len(entries) {
		return nil, fmt.Errorf("invalid SZL record layout")
	}
	id := &S7Identity{}
	for i := 0; i < entryCount; i++ {
		entry := entries[i*entryLen : (i+1)*entryLen]
		index := binary.BigEndian.Uint16(entry[:2])
		switch szlID {
		case 0x001c, 0x011c:
			if entryLen != 34 {
				return nil, fmt.Errorf("unsupported component record size %d", entryLen)
			}
			value := extractNullTerminated(entry[2:])
			switch index {
			case 2:
				if id.ModuleName == "" {
					id.ModuleName = value
				}
			case 5:
				id.SerialNumber = value
			case 7:
				id.ModuleName = value
			}
		case 0x0011, 0x0111:
			if entryLen != 28 {
				return nil, fmt.Errorf("unsupported module record size %d", entryLen)
			}
			switch index {
			case 1:
				id.OrderNumber = extractNullTerminated(entry[2:22])
			case 7:
				if entry[24] != 0x56 {
					return nil, fmt.Errorf("unsupported firmware record encoding")
				}
				id.FirmwareVersion = fmt.Sprintf("%d.%d.%d", entry[25], entry[26], entry[27])
			}
		default:
			return nil, fmt.Errorf("unsupported identity SZL 0x%04x", szlID)
		}
	}
	return id, nil
}

// Read exactly one bounded TPKT frame; TCP segmentation does not change its
// application framing. Multi-part SZL responses are explicitly unsupported.
func readS7Frame(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if header[0] != 3 || header[1] != 0 || length < 7 || length > 8192 {
		return nil, fmt.Errorf("invalid TPKT frame length %d", length)
	}
	frame := make([]byte, length)
	copy(frame, header)
	_, err := io.ReadFull(r, frame[4:])
	return frame, err
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

var (
	siemensMLFBRe    = regexp.MustCompile(`(?i)\b(6ES7\s*[0-9]{3}-[0-9A-Z]{5}-[0-9A-Z]{4}|6GK[0-9]\s*[0-9]{3}-[0-9A-Z]{5}-[0-9A-Z]{4})\b`)
	siemensFWRe      = regexp.MustCompile(`(?i)(?:FW|Firmware(?:\s+version)?)[\s:=]*V?\.?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`)
	siemensPortalVRe = regexp.MustCompile(`\bV([0-9]+\.[0-9]+\.[0-9]+)\b`)
	siemensCPUModRe  = regexp.MustCompile(`(?i)\b(CPU[\s-]*15[0-9]{2}[A-Z0-9/ -]*|CPU[\s-]*12[0-9]{2}[A-Z0-9/ -]*|ET\s*200SP[A-Z0-9/ -]*|CPU[\s-]*31[0-9][A-Z0-9/ -]*|CPU[\s-]*41[0-9][A-Z0-9/ -]*)\b`)
)

// ParseSiemensSysDescr parses an SNMP sysDescr.0 string from a Siemens SIMATIC S7-1500,
// S7-1200, or ET200SP controller (e.g. "Siemens, SIMATIC S7, CPU-1500, 6ES7 516-3FN02-0AB0, HW: 3, FW: V.2.9.4, S C-M4U82914").
func ParseSiemensSysDescr(sysDescr string) *S7Identity {
	lower := strings.ToLower(sysDescr)
	if !strings.Contains(lower, "siemens") || (!strings.Contains(lower, "simatic") && !strings.Contains(lower, "6es7")) {
		return nil
	}

	id := &S7Identity{}
	if m := siemensMLFBRe.FindStringSubmatch(sysDescr); len(m) > 1 {
		id.OrderNumber = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	if m := siemensFWRe.FindStringSubmatch(sysDescr); len(m) > 1 {
		id.FirmwareVersion = strings.TrimSpace(m[1])
	}
	if m := siemensCPUModRe.FindStringSubmatch(sysDescr); len(m) > 1 {
		mod := strings.TrimSpace(m[1])
		// Trim at comma if regex matched across fields
		if comma := strings.IndexByte(mod, ','); comma > 0 {
			mod = strings.TrimSpace(mod[:comma])
		}
		if strings.EqualFold(mod, "CPU-1500") {
			mod = "SIMATIC S7-1500"
		} else if strings.EqualFold(mod, "CPU-1200") {
			mod = "SIMATIC S7-1200"
		}
		id.ModuleName = mod
	}

	for _, part := range strings.Split(sysDescr, ",") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, "S ") && len(p) >= 6 {
			id.SerialNumber = p
			break
		}
	}

	if id.ModuleName == "" {
		if id.OrderNumber != "" {
			id.ModuleName = "SIMATIC S7 (" + id.OrderNumber + ")"
		} else {
			id.ModuleName = "SIMATIC S7"
		}
	}
	return id
}

// ParseSiemensWebPortal parses a TIA Portal S7-1500 / S7-1200 / ET200SP embedded web
// diagnostics response (/Portal/Portal.mwsl?PriNav=Ident) or TLS certificate subject.
func ParseSiemensWebPortal(corpus string, certCN string) *S7Identity {
	combined := corpus + "\n" + certCN
	lower := strings.ToLower(combined)
	if !strings.Contains(lower, "simatic") &&
		!strings.Contains(lower, "s7-1500") &&
		!strings.Contains(lower, "s7-1200") &&
		!strings.Contains(lower, "et200sp") &&
		!strings.Contains(lower, "et 200sp") &&
		!siemensMLFBRe.MatchString(combined) {
		return nil
	}

	id := &S7Identity{}
	if m := siemensMLFBRe.FindStringSubmatch(combined); len(m) > 1 {
		id.OrderNumber = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	if m := siemensFWRe.FindStringSubmatch(combined); len(m) > 1 {
		id.FirmwareVersion = strings.TrimSpace(m[1])
	} else if m := siemensPortalVRe.FindStringSubmatch(combined); len(m) > 1 {
		id.FirmwareVersion = strings.TrimSpace(m[1])
	}
	if m := siemensCPUModRe.FindStringSubmatch(combined); len(m) > 1 {
		mod := strings.TrimSpace(m[1])
		if nl := strings.IndexAny(mod, "<,\r\n"); nl > 0 {
			mod = strings.TrimSpace(mod[:nl])
		}
		id.ModuleName = mod
	}
	if id.ModuleName == "" {
		switch {
		case strings.Contains(lower, "s7-1500"):
			id.ModuleName = "SIMATIC S7-1500"
		case strings.Contains(lower, "et200sp") || strings.Contains(lower, "et 200sp"):
			id.ModuleName = "SIMATIC ET 200SP"
		case strings.Contains(lower, "s7-1200"):
			id.ModuleName = "SIMATIC S7-1200"
		default:
			id.ModuleName = "SIMATIC S7"
		}
	}
	return id
}

func s7ProbeWebPortalURL(client *http.Client, targetURL string) *S7Identity {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Deadband-OT-Discovery/1.0 (Read-Only)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var parts []string
	if srv := resp.Header.Get("Server"); srv != "" {
		parts = append(parts, srv)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		parts = append(parts, loc)
	}
	certCN := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		certCN = leaf.Subject.CommonName
		parts = append(parts, leaf.Subject.CommonName)
		parts = append(parts, leaf.Subject.Organization...)
		parts = append(parts, leaf.Issuer.CommonName)
		parts = append(parts, leaf.Issuer.Organization...)
	}
	parts = append(parts, string(body))
	return ParseSiemensWebPortal(strings.Join(parts, "\n"), certCN)
}

// --- Scanner ---

// S7Identify performs the classic S7comm SZL 0x001C identification handshake against a single IP.
// Returns nil, nil if the host is not an S7 PLC or rejects classic 0x32 SZL reads.
func S7Identify(ip string, timeout time.Duration) (*S7Identity, error) {
	id, _ := s7ProbeTCP(ip, S7Port, timeout)
	return id, nil
}

func s7ProbeTCP(ip string, port int, timeout time.Duration) (id *S7Identity, cotpConfirmed bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	// Try S7-300/400 (rack 0, slot 2), S7-1500/ET200SP (rack 0, slot 1), and S7-1200 (rack 0, slot 0)
	tsaps := [][2]int{{0, 2}, {0, 1}, {0, 0}}

	for _, tsap := range tsaps {
		gotID, sawCOTP, dialFailed, _ := s7Handshake(addr, tsap[0], tsap[1], timeout)
		if sawCOTP {
			cotpConfirmed = true
		}
		if gotID != nil {
			return gotID, true
		}
		if dialFailed && !cotpConfirmed {
			return nil, false
		}
	}
	return nil, cotpConfirmed
}

func s7Handshake(addr string, rack, slot int, timeout time.Duration) (id *S7Identity, sawCOTP bool, dialFailed bool, err error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, false, true, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Phase 1: COTP Connection Request
	if _, err := conn.Write(buildCOTPConnectRequest(rack, slot)); err != nil {
		return nil, false, false, err
	}
	frame, err := readS7Frame(conn)
	if err != nil {
		return nil, false, false, err
	}
	pduType, _, err := parseCOTPResponse(frame)
	if err != nil {
		return nil, false, false, err
	}
	if pduType == cotpDR {
		return nil, true, false, fmt.Errorf("COTP rejected")
	}
	if pduType != cotpCC {
		return nil, false, false, fmt.Errorf("unexpected COTP PDU type 0x%02X", pduType)
	}
	sawCOTP = true

	// Phase 2: S7 Setup Communication
	if _, err := conn.Write(buildS7SetupCommunication()); err != nil {
		return nil, sawCOTP, false, err
	}
	frame, err = readS7Frame(conn)
	if err != nil {
		return nil, sawCOTP, false, err
	}
	if err := parseS7SetupResponse(frame); err != nil {
		return nil, sawCOTP, false, err
	}

	// Phase 3: SZL Read (Component Identification)
	if _, err := conn.Write(buildSZLReadRequest(szlComponentID, 0x0000)); err != nil {
		return nil, sawCOTP, false, err
	}
	frame, err = readS7Frame(conn)
	if err != nil {
		return nil, sawCOTP, false, err
	}
	parsed, err := ParseSZLResponse(frame)
	if err != nil {
		return nil, sawCOTP, false, err
	}
	// Firmware and order code come from module identification, not 001C.
	if _, err := conn.Write(buildSZLReadRequest(0x0011, 0)); err == nil {
		if frame, err := readS7Frame(conn); err == nil {
			if module, err := ParseSZLResponse(frame); err == nil {
				parsed.OrderNumber = module.OrderNumber
				parsed.FirmwareVersion = module.FirmwareVersion
			}
		}
	}
	return parsed, sawCOTP, false, nil
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
	fw = strings.TrimPrefix(fw, ".")

	return inventory.Device{
		IP:       ip,
		Vendor:   "Siemens",
		Model:    model,
		Firmware: fw,
		Serial:   id.SerialNumber,
		OrderNum: id.OrderNumber,
		Protocol: "s7",
		Port:     S7Port,
	}
}

// discoverS7 performs S7comm discovery across a set of IPs.
// When TCP/102 is open but TIA Portal S7-1500/1200 PUT/GET is disabled (rejecting SZL 0x001C),
// falls back to read-only SNMP sysDescr.0 and TIA Portal HTTPS/HTTP /Portal/ diagnostics.
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

	httpClient := newAncillaryHTTPClient(timeout)
	snmpTimeout := timeout
	if snmpTimeout > 750*time.Millisecond {
		snmpTimeout = 750 * time.Millisecond
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

			id, cotpConfirmed := s7ProbeTCP(ip, S7Port, timeout)
			if id == nil {
				// Fallback 1: Read-only SNMPv2c sysDescr.0 (PROFINET S7-1500 / ET200SP / S7-1200)
				if sysDescr := SNMPGetSysDescr(ip, SNMPPort, snmpTimeout); sysDescr != "" {
					id = ParseSiemensSysDescr(sysDescr)
				}
			}
			if id == nil {
				// Fallback 2: Read-only TIA Portal embedded web server (/Portal/Portal.mwsl?PriNav=Ident)
				for _, u := range []string{
					fmt.Sprintf("https://%s/Portal/Portal.mwsl?PriNav=Ident", ip),
					fmt.Sprintf("http://%s/Portal/Portal.mwsl?PriNav=Ident", ip),
				} {
					if webID := s7ProbeWebPortalURL(httpClient, u); webID != nil {
						id = webID
						break
					}
				}
			}
			if id == nil && cotpConfirmed {
				// Host genuinely spoke RFC 1006 TPKT + ISO 8073 COTP on TCP/102 with PUT/GET disabled
				id = &S7Identity{ModuleName: "SIMATIC S7-1200/1500"}
			}
			if id == nil {
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
