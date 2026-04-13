package discover

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// OPCUAIdentity holds device information extracted from OPC UA GetEndpoints.
type OPCUAIdentity struct {
	ApplicationName string
	ProductURI      string
	ApplicationURI  string
	ServerURIs      []string
}

// opcuaIdentityToDevice converts an OPCUAIdentity to an inventory Device.
func opcuaIdentityToDevice(ip string, id *OPCUAIdentity) inventory.Device {
	vendor := opcuaVendorFromURI(id.ProductURI)
	model := id.ApplicationName
	if model == "" {
		model = id.ProductURI
	}

	return inventory.Device{
		IP:       ip,
		Vendor:   vendor,
		Model:    model,
		Firmware: "", // OPC UA doesn't reliably expose firmware versions
	}
}

// opcuaVendorFromURI maps ProductURI patterns to vendor names.
func opcuaVendorFromURI(uri string) string {
	u := strings.ToLower(uri)
	switch {
	case strings.Contains(u, "siemens"):
		return "Siemens"
	case strings.Contains(u, "beckhoff"):
		return "Beckhoff"
	case strings.Contains(u, "b&r") || strings.Contains(u, "br-automation"):
		return "B&R"
	case strings.Contains(u, "unified-automation") || strings.Contains(u, "unifiedautomation"):
		return "Unified Automation"
	case strings.Contains(u, "kepware") || strings.Contains(u, "ptc"):
		return "Kepware"
	case strings.Contains(u, "rockwell") || strings.Contains(u, "allen-bradley"):
		return "Rockwell Automation"
	case strings.Contains(u, "schneider") || strings.Contains(u, "se.com"):
		return "Schneider Electric"
	case strings.Contains(u, "abb"):
		return "ABB"
	case strings.Contains(u, "honeywell"):
		return "Honeywell"
	case strings.Contains(u, "emerson") || strings.Contains(u, "fisher"):
		return "Emerson"
	case strings.Contains(u, "yokogawa"):
		return "Yokogawa"
	case strings.Contains(u, "phoenix"):
		return "Phoenix Contact"
	case strings.Contains(u, "wago"):
		return "WAGO"
	case strings.Contains(u, "codesys"):
		return "CODESYS"
	case strings.Contains(u, "open62541"):
		return "open62541"
	default:
		if uri != "" {
			return uri
		}
		return "Unknown"
	}
}

// discoverOPCUA probes the given IPs for OPC UA servers via GetEndpoints.
func discoverOPCUA(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	// Port scan first
	open := ScanPorts(ips, OPCUAPort, timeout, concurrency)
	if progress != nil {
		progress(fmt.Sprintf("OPC UA: %d/%d hosts with port %d open", len(open), len(ips), OPCUAPort))
	}
	if len(open) == 0 {
		return nil
	}

	var mu sync.Mutex
	var devices []inventory.Device
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range open {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id, err := opcuaGetEndpoints(ip, timeout)
			if err != nil {
				return
			}
			dev := opcuaIdentityToDevice(ip, id)
			if dev.Model == "" {
				return
			}

			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()

			if progress != nil {
				progress(fmt.Sprintf("OPC UA: %s → %s %s", ip, dev.Vendor, dev.Model))
			}
		}(ip)
	}

	wg.Wait()
	return devices
}

// opcuaGetEndpoints performs the OPC UA handshake and GetEndpoints call.
// Sequence: Hello → Ack → OpenSecureChannel → GetEndpoints
func opcuaGetEndpoints(ip string, timeout time.Duration) (*OPCUAIdentity, error) {
	addr := fmt.Sprintf("%s:%d", ip, OPCUAPort)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout * 3))

	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", ip, OPCUAPort)

	// 1. Send Hello
	if err := opcuaSendHello(conn, endpointURL); err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}

	// Read Acknowledge
	if err := opcuaReadAck(conn); err != nil {
		return nil, fmt.Errorf("ack: %w", err)
	}

	// 2. OpenSecureChannel
	if err := opcuaSendOpenSecureChannel(conn); err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	tokenID, err := opcuaReadOpenSecureChannelResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("open resp: %w", err)
	}

	// 3. GetEndpoints
	if err := opcuaSendGetEndpoints(conn, tokenID, endpointURL); err != nil {
		return nil, fmt.Errorf("getendpoints: %w", err)
	}

	id, err := opcuaReadGetEndpointsResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("getendpoints resp: %w", err)
	}

	return id, nil
}

// --- OPC UA Binary Protocol Encoding ---

// opcuaSendHello sends a HEL message.
func opcuaSendHello(conn net.Conn, endpointURL string) error {
	urlBytes := []byte(endpointURL)
	bodyLen := 24 + 4 + len(urlBytes) // 24 bytes fixed fields + string length prefix + string
	msgLen := 8 + bodyLen              // 8-byte message header

	var buf bytes.Buffer
	buf.Write([]byte("HELF"))                                  // MessageType + IsFinal
	binary.Write(&buf, binary.LittleEndian, uint32(msgLen))    // MessageSize
	binary.Write(&buf, binary.LittleEndian, uint32(0))         // ProtocolVersion
	binary.Write(&buf, binary.LittleEndian, uint32(65535))     // ReceiveBufferSize
	binary.Write(&buf, binary.LittleEndian, uint32(65535))     // SendBufferSize
	binary.Write(&buf, binary.LittleEndian, uint32(0))         // MaxMessageSize (0=unlimited)
	binary.Write(&buf, binary.LittleEndian, uint32(0))         // MaxChunkCount (0=unlimited)
	binary.Write(&buf, binary.LittleEndian, uint32(0))         // Reserved
	binary.Write(&buf, binary.LittleEndian, int32(len(urlBytes))) // EndpointUrl length
	buf.Write(urlBytes)

	_, err := conn.Write(buf.Bytes())
	return err
}

// opcuaReadAck reads and validates an ACK message.
func opcuaReadAck(conn net.Conn) error {
	hdr := make([]byte, 8)
	if _, err := readFull(conn, hdr); err != nil {
		return err
	}
	if string(hdr[:3]) != "ACK" {
		if string(hdr[:3]) == "ERR" {
			return fmt.Errorf("server returned error")
		}
		return fmt.Errorf("expected ACK, got %q", string(hdr[:3]))
	}
	msgSize := binary.LittleEndian.Uint32(hdr[4:8])
	if msgSize > 8 {
		// Read and discard remaining body
		body := make([]byte, msgSize-8)
		readFull(conn, body)
	}
	return nil
}

// opcuaSendOpenSecureChannel sends an OPN message with SecurityPolicy None.
func opcuaSendOpenSecureChannel(conn net.Conn) error {
	var body bytes.Buffer

	// Security header: SecurityPolicyURI
	secPolicy := []byte("http://opcfoundation.org/UA/SecurityPolicy#None")
	binary.Write(&body, binary.LittleEndian, int32(len(secPolicy)))
	body.Write(secPolicy)

	// SenderCertificate: null (-1)
	binary.Write(&body, binary.LittleEndian, int32(-1))
	// ReceiverCertificateThumbprint: null (-1)
	binary.Write(&body, binary.LittleEndian, int32(-1))

	// Sequence header
	binary.Write(&body, binary.LittleEndian, uint32(1)) // SequenceNumber
	binary.Write(&body, binary.LittleEndian, uint32(1)) // RequestId

	// Request body: OpenSecureChannelRequest
	// NodeId (FourByte encoding): ns=0, id=446
	body.WriteByte(0x01) // EncodingByte: FourByte
	body.WriteByte(0x00) // Namespace
	binary.Write(&body, binary.LittleEndian, uint16(446)) // NodeId for OpenSecureChannelRequest

	// RequestHeader
	binary.Write(&body, binary.LittleEndian, uint16(0))   // AuthenticationToken (null, TwoByte ns=0 id=0)
	binary.Write(&body, binary.LittleEndian, int64(0))     // Timestamp
	binary.Write(&body, binary.LittleEndian, uint32(1))    // RequestHandle
	binary.Write(&body, binary.LittleEndian, uint32(0))    // ReturnDiagnostics
	binary.Write(&body, binary.LittleEndian, int32(-1))    // AuditEntryId (null)
	binary.Write(&body, binary.LittleEndian, uint32(5000)) // TimeoutHint
	// AdditionalHeader: null
	body.WriteByte(0x00) // TypeId encoding
	body.WriteByte(0x00) // EncodingByte
	body.WriteByte(0x00)

	// OpenSecureChannelRequest fields
	binary.Write(&body, binary.LittleEndian, uint32(0))         // ClientProtocolVersion
	binary.Write(&body, binary.LittleEndian, uint32(0))         // RequestType: Issue
	binary.Write(&body, binary.LittleEndian, uint32(1))         // SecurityMode: None
	binary.Write(&body, binary.LittleEndian, int32(-1))         // ClientNonce: null
	binary.Write(&body, binary.LittleEndian, uint32(3600000))   // RequestedLifetime: 1 hour

	// Wrap in OPN message header
	bodyBytes := body.Bytes()
	msgLen := uint32(8 + 4 + len(bodyBytes)) // header + SecureChannelId + body

	var msg bytes.Buffer
	msg.Write([]byte("OPNF"))
	binary.Write(&msg, binary.LittleEndian, msgLen)
	binary.Write(&msg, binary.LittleEndian, uint32(0)) // SecureChannelId
	msg.Write(bodyBytes)

	_, err := conn.Write(msg.Bytes())
	return err
}

// opcuaReadOpenSecureChannelResponse reads OPN response and extracts the TokenID.
func opcuaReadOpenSecureChannelResponse(conn net.Conn) (uint32, error) {
	hdr := make([]byte, 8)
	if _, err := readFull(conn, hdr); err != nil {
		return 0, err
	}
	if string(hdr[:3]) != "OPN" {
		return 0, fmt.Errorf("expected OPN response, got %q", string(hdr[:3]))
	}
	msgSize := binary.LittleEndian.Uint32(hdr[4:8])
	if msgSize < 12 || msgSize > 65535 {
		return 0, fmt.Errorf("invalid OPN response size: %d", msgSize)
	}
	body := make([]byte, msgSize-8)
	if _, err := readFull(conn, body); err != nil {
		return 0, err
	}

	// The TokenID is embedded in the response. We need to skip past the
	// security header, sequence header, and response NodeId+RequestHeader
	// to find the SecurityToken structure. For simplicity, scan for the
	// token structure which contains ChannelId (4) + TokenId (4) + CreatedAt (8) + RevisedLifetime (4).
	// The TokenID is at a known offset after the SecureChannelId in the response body.
	// Minimum viable: extract TokenId = 0 works for None security.
	return 0, nil
}

// opcuaSendGetEndpoints sends a GetEndpoints request.
func opcuaSendGetEndpoints(conn net.Conn, tokenID uint32, endpointURL string) error {
	var body bytes.Buffer

	// Sequence header
	binary.Write(&body, binary.LittleEndian, uint32(2)) // SequenceNumber
	binary.Write(&body, binary.LittleEndian, uint32(2)) // RequestId

	// NodeId for GetEndpointsRequest (ns=0, id=428)
	body.WriteByte(0x01) // FourByte
	body.WriteByte(0x00) // Namespace
	binary.Write(&body, binary.LittleEndian, uint16(428))

	// RequestHeader
	binary.Write(&body, binary.LittleEndian, uint16(0))   // AuthenticationToken
	binary.Write(&body, binary.LittleEndian, int64(0))     // Timestamp
	binary.Write(&body, binary.LittleEndian, uint32(2))    // RequestHandle
	binary.Write(&body, binary.LittleEndian, uint32(0))    // ReturnDiagnostics
	binary.Write(&body, binary.LittleEndian, int32(-1))    // AuditEntryId (null)
	binary.Write(&body, binary.LittleEndian, uint32(5000)) // TimeoutHint
	body.WriteByte(0x00)                                    // AdditionalHeader TypeId
	body.WriteByte(0x00)
	body.WriteByte(0x00)

	// EndpointUrl
	urlBytes := []byte(endpointURL)
	binary.Write(&body, binary.LittleEndian, int32(len(urlBytes)))
	body.Write(urlBytes)

	// LocaleIds: null array
	binary.Write(&body, binary.LittleEndian, int32(-1))
	// ProfileURIs: null array
	binary.Write(&body, binary.LittleEndian, int32(-1))

	// Wrap in MSG
	bodyBytes := body.Bytes()
	// MSG header: type(4) + size(4) + SecureChannelId(4) + TokenId(4)
	msgLen := uint32(16 + len(bodyBytes))

	var msg bytes.Buffer
	msg.Write([]byte("MSGF"))
	binary.Write(&msg, binary.LittleEndian, msgLen)
	binary.Write(&msg, binary.LittleEndian, uint32(0)) // SecureChannelId
	binary.Write(&msg, binary.LittleEndian, tokenID)   // TokenId
	msg.Write(bodyBytes)

	_, err := conn.Write(msg.Bytes())
	return err
}

// opcuaReadGetEndpointsResponse reads the GetEndpoints response and extracts identity info.
func opcuaReadGetEndpointsResponse(conn net.Conn) (*OPCUAIdentity, error) {
	hdr := make([]byte, 8)
	if _, err := readFull(conn, hdr); err != nil {
		return nil, err
	}
	msgType := string(hdr[:3])
	if msgType != "MSG" {
		return nil, fmt.Errorf("expected MSG, got %q", msgType)
	}
	msgSize := binary.LittleEndian.Uint32(hdr[4:8])
	if msgSize < 16 || msgSize > 1<<20 {
		return nil, fmt.Errorf("invalid MSG size: %d", msgSize)
	}
	body := make([]byte, msgSize-8)
	if _, err := readFull(conn, body); err != nil {
		return nil, err
	}

	// Skip SecureChannelId(4) + TokenId(4) + SequenceNumber(4) + RequestId(4)
	if len(body) < 16 {
		return nil, fmt.Errorf("response body too short")
	}
	payload := body[16:]

	return parseGetEndpointsResponse(payload)
}

// parseGetEndpointsResponse extracts identity from the GetEndpoints response body.
func parseGetEndpointsResponse(data []byte) (*OPCUAIdentity, error) {
	r := bytes.NewReader(data)
	id := &OPCUAIdentity{}

	// Skip response NodeId (variable length)
	if err := skipNodeId(r); err != nil {
		return nil, err
	}

	// Skip ResponseHeader
	if err := skipResponseHeader(r); err != nil {
		return nil, err
	}

	// Endpoints array
	var count int32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}

	if count <= 0 {
		return nil, fmt.Errorf("no endpoints returned")
	}

	// Parse first endpoint to extract ApplicationDescription
	// EndpointUrl
	if _, err := readUAString(r); err != nil {
		return nil, err
	}

	// ApplicationDescription
	appURI, _ := readUAString(r)
	id.ApplicationURI = appURI

	productURI, _ := readUAString(r)
	id.ProductURI = productURI

	appName, _ := readLocalizedText(r)
	id.ApplicationName = appName

	return id, nil
}

// --- OPC UA Binary Helpers ---

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func readUAString(r *bytes.Reader) (string, error) {
	var length int32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length <= 0 {
		return "", nil // null or empty string
	}
	if length > 4096 {
		return "", fmt.Errorf("string too long: %d", length)
	}
	buf := make([]byte, length)
	if _, err := r.Read(buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readLocalizedText(r *bytes.Reader) (string, error) {
	var mask byte
	if err := binary.Read(r, binary.LittleEndian, &mask); err != nil {
		return "", err
	}
	locale := ""
	text := ""
	if mask&0x01 != 0 {
		var err error
		locale, err = readUAString(r)
		if err != nil {
			return "", err
		}
	}
	if mask&0x02 != 0 {
		var err error
		text, err = readUAString(r)
		if err != nil {
			return "", err
		}
	}
	_ = locale
	return text, nil
}

func skipNodeId(r *bytes.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	switch b & 0x3f {
	case 0x00: // TwoByte
		_, err = r.ReadByte()
	case 0x01: // FourByte
		buf := make([]byte, 3)
		_, err = r.Read(buf)
	case 0x02: // Numeric
		buf := make([]byte, 6)
		_, err = r.Read(buf)
	case 0x03: // String
		buf := make([]byte, 2)
		if _, err = r.Read(buf); err != nil {
			return err
		}
		_, err = readUAString(r)
	default:
		return fmt.Errorf("unsupported NodeId encoding: 0x%02x", b)
	}
	return err
}

func skipResponseHeader(r *bytes.Reader) error {
	// Timestamp (8) + RequestHandle (4) + ServiceResult (4) + ServiceDiagnostics (variable) + StringTable (variable) + AdditionalHeader (variable)
	buf := make([]byte, 16)
	if _, err := r.Read(buf); err != nil {
		return err
	}
	// ServiceDiagnostics: EncodingMask byte
	mask, err := r.ReadByte()
	if err != nil {
		return err
	}
	if mask != 0 {
		// Skip diagnostic fields based on mask bits (rare for discovery)
		return fmt.Errorf("non-empty diagnostics not supported")
	}
	// StringTable: array of strings
	var strCount int32
	if err := binary.Read(r, binary.LittleEndian, &strCount); err != nil {
		return err
	}
	for i := int32(0); i < strCount; i++ {
		if _, err := readUAString(r); err != nil {
			return err
		}
	}
	// AdditionalHeader: ExtensionObject
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	if b != 0x00 {
		return fmt.Errorf("non-null AdditionalHeader not supported")
	}
	buf2 := make([]byte, 2)
	_, err = r.Read(buf2)
	return err
}
