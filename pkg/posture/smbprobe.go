package posture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// SMBInfo holds data extracted from an SMB NTLMSSP negotiation.
type SMBInfo struct {
	Hostname string `json:"hostname,omitempty"`
	Domain   string `json:"domain,omitempty"`
	OSVer    string `json:"os_ver,omitempty"` // e.g. "10.0.19041" (Windows 10)
}

// ProbeSMB connects to port 445 and performs an unauthenticated SMB2
// negotiate + NTLMSSP challenge exchange. The server's challenge response
// contains the machine hostname, domain, and OS build version — all
// returned without credentials.
//
// This is safe for OT networks: it is a single TCP handshake followed
// by two small packets, identical to what Windows sends when browsing
// a network share. No authentication is attempted.
func ProbeSMB(ip string, timeout time.Duration) (*SMBInfo, error) {
	addr := net.JoinHostPort(ip, "445")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: Send SMB2 negotiate with NTLMSSP
	if _, err := conn.Write(smb2NegotiateReq); err != nil {
		return nil, fmt.Errorf("write negotiate: %w", err)
	}

	// Read negotiate response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read negotiate resp: %w", err)
	}
	if n < 4 {
		return nil, fmt.Errorf("negotiate response too short")
	}

	// Step 2: Send session setup with NTLMSSP_NEGOTIATE
	if _, err := conn.Write(smb2SessionSetupReq); err != nil {
		return nil, fmt.Errorf("write session setup: %w", err)
	}

	// Read session setup response — contains NTLMSSP_CHALLENGE with target info
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read session setup resp: %w", err)
	}

	return parseNTLMChallenge(buf[:n])
}

// parseNTLMChallenge extracts host information from an NTLMSSP_CHALLENGE
// embedded in an SMB2 Session Setup response.
func parseNTLMChallenge(data []byte) (*SMBInfo, error) {
	// Find NTLMSSP signature
	sig := []byte("NTLMSSP\x00")
	idx := bytes.Index(data, sig)
	if idx < 0 {
		return nil, fmt.Errorf("NTLMSSP signature not found")
	}
	ntlm := data[idx:]

	if len(ntlm) < 32 {
		return nil, fmt.Errorf("NTLMSSP message too short")
	}

	// Message type at offset 8 should be 2 (CHALLENGE)
	msgType := binary.LittleEndian.Uint32(ntlm[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("expected NTLMSSP_CHALLENGE (2), got %d", msgType)
	}

	info := &SMBInfo{}

	// Target name at offset 12: length(2) + maxlen(2) + offset(4)
	if len(ntlm) >= 20 {
		tnLen := binary.LittleEndian.Uint16(ntlm[12:14])
		tnOff := binary.LittleEndian.Uint32(ntlm[16:20])
		if int(tnOff+uint32(tnLen)) <= len(ntlm) {
			info.Hostname = decodeUTF16LE(ntlm[tnOff : tnOff+uint32(tnLen)])
		}
	}

	// OS version at offset 48 (if negotiate flags indicate version present)
	if len(ntlm) >= 56 {
		major := ntlm[48]
		minor := ntlm[49]
		build := binary.LittleEndian.Uint16(ntlm[50:52])
		if major > 0 {
			info.OSVer = fmt.Sprintf("%d.%d.%d", major, minor, build)
		}
	}

	// Target info AV_PAIRs at offset 40: length(2) + maxlen(2) + offset(4)
	if len(ntlm) >= 48 {
		tiLen := binary.LittleEndian.Uint16(ntlm[40:42])
		tiOff := binary.LittleEndian.Uint32(ntlm[44:48])
		if tiLen > 0 && int(tiOff+uint32(tiLen)) <= len(ntlm) {
			parseAVPairs(ntlm[tiOff:tiOff+uint32(tiLen)], info)
		}
	}

	return info, nil
}

// parseAVPairs walks the AV_PAIR list in the target info buffer.
func parseAVPairs(data []byte, info *SMBInfo) {
	for len(data) >= 4 {
		avID := binary.LittleEndian.Uint16(data[0:2])
		avLen := binary.LittleEndian.Uint16(data[2:4])
		if int(4+avLen) > len(data) {
			break
		}
		val := data[4 : 4+avLen]

		switch avID {
		case 0x0000: // MsvAvEOL
			return
		case 0x0001: // MsvAvNbComputerName
			info.Hostname = decodeUTF16LE(val)
		case 0x0002: // MsvAvNbDomainName
			info.Domain = decodeUTF16LE(val)
		}

		data = data[4+avLen:]
	}
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

// osVersionLabel maps Windows NT version numbers to friendly names.
func osVersionLabel(ver string) string {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	build := 0
	if len(parts) >= 3 {
		build, _ = strconv.Atoi(parts[2])
	}

	switch {
	case major == 10 && minor == 0 && build >= 22000:
		return "Windows 11"
	case major == 10 && minor == 0:
		return "Windows 10 / Server 2016+"
	case major == 6 && minor == 3:
		return "Windows 8.1 / Server 2012 R2"
	case major == 6 && minor == 2:
		return "Windows 8 / Server 2012"
	case major == 6 && minor == 1:
		return "Windows 7 / Server 2008 R2"
	case major == 6 && minor == 0:
		return "Windows Vista / Server 2008"
	case major == 5 && minor == 1:
		return "Windows XP"
	case major == 5 && minor == 2:
		return "Windows Server 2003"
	default:
		return fmt.Sprintf("Windows NT %d.%d", major, minor)
	}
}

// --- Pre-built SMB2 packets ---
//
// These are minimal, static SMB2 packets that trigger the NTLMSSP
// challenge/response exchange. They are the same bytes Windows sends
// when opening a network share — safe, lightweight, no auth.

// smb2NegotiateReq: NetBIOS session + SMB2 NEGOTIATE with dialect 0x0202-0x0311.
var smb2NegotiateReq = func() []byte {
	// SMB2 header
	smb2Header := []byte{
		0xFE, 0x53, 0x4D, 0x42, // ProtocolId: 0xFE 'SMB'
		0x40, 0x00,             // StructureSize: 64
		0x00, 0x00,             // CreditCharge: 0
		0x00, 0x00, 0x00, 0x00, // Status: 0
		0x00, 0x00, // Command: NEGOTIATE (0)
		0x00, 0x00, // CreditRequest: 0
		0x00, 0x00, 0x00, 0x00, // Flags: 0
		0x00, 0x00, 0x00, 0x00, // NextCommand: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId: 0
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeId: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
	}

	// Negotiate request body
	negotiate := []byte{
		0x24, 0x00, // StructureSize: 36
		0x02, 0x00, // DialectCount: 2
		0x01, 0x00, // SecurityMode: signing enabled
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities: 0
		// ClientGuid (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime
		// Dialects
		0x02, 0x02, // SMB 2.0.2
		0x10, 0x02, // SMB 2.1
	}

	payload := append(smb2Header, negotiate...)

	// NetBIOS session header (4 bytes)
	nb := make([]byte, 4)
	nb[0] = 0x00
	binary.BigEndian.PutUint32(nb, uint32(len(payload)))
	nb[0] = 0x00 // session message type

	return append(nb, payload...)
}()

// smb2SessionSetupReq: SMB2 SESSION_SETUP with NTLMSSP_NEGOTIATE token.
var smb2SessionSetupReq = func() []byte {
	// NTLMSSP_NEGOTIATE message
	ntlmNeg := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x01, 0x00, 0x00, 0x00, // MessageType: NEGOTIATE (1)
		// NegotiateFlags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET |
		//                 NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		0x97, 0x82, 0x08, 0xe2,
		// DomainNameFields (len, maxlen, offset) — empty
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// WorkstationFields — empty
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// Wrap in GSS-API / SPNEGO ASN.1 (simplified)
	spnegoToken := buildSPNEGO(ntlmNeg)

	// SMB2 header
	smb2Header := []byte{
		0xFE, 0x53, 0x4D, 0x42, // ProtocolId
		0x40, 0x00,             // StructureSize: 64
		0x00, 0x00,             // CreditCharge: 0
		0x00, 0x00, 0x00, 0x00, // Status: 0
		0x01, 0x00, // Command: SESSION_SETUP (1)
		0x01, 0x00, // CreditRequest: 1
		0x00, 0x00, 0x00, 0x00, // Flags: 0
		0x00, 0x00, 0x00, 0x00, // NextCommand: 0
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId: 1
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeId: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
	}

	// Session setup request body
	secBufOffset := uint16(64 + 24) // SMB2 header (64) + session setup fixed (24)
	secBufLen := uint16(len(spnegoToken))
	setup := []byte{
		0x19, 0x00, // StructureSize: 25
		0x00,       // Flags: 0
		0x01,       // SecurityMode: signing enabled
		0x00, 0x00, 0x00, 0x00, // Capabilities: 0
		0x00, 0x00, 0x00, 0x00, // Channel: 0
		0x00, 0x00, // SecurityBufferOffset (filled below)
		0x00, 0x00, // SecurityBufferLength (filled below)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PreviousSessionId
	}
	binary.LittleEndian.PutUint16(setup[12:14], secBufOffset)
	binary.LittleEndian.PutUint16(setup[14:16], secBufLen)

	payload := append(smb2Header, setup...)
	payload = append(payload, spnegoToken...)

	// NetBIOS session header
	nb := make([]byte, 4)
	binary.BigEndian.PutUint32(nb, uint32(len(payload)))
	nb[0] = 0x00

	return append(nb, payload...)
}()

// buildSPNEGO wraps an NTLMSSP token in the minimal GSS-API/SPNEGO
// envelope that SMB2 expects.
func buildSPNEGO(ntlmToken []byte) []byte {
	// OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
	ntlmOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

	// mechTypes SEQUENCE { OID }
	mechTypes := asn1Wrap(0x30, ntlmOID)

	// mechToken [2] OCTET STRING
	mechTokenInner := asn1Wrap(0x04, ntlmToken)
	mechTokenCtx := asn1Wrap(0xa2, mechTokenInner)

	// NegTokenInit SEQUENCE
	negTokenInit := append(asn1Wrap(0xa0, mechTypes), mechTokenCtx...)
	negTokenInitSeq := asn1Wrap(0x30, negTokenInit)

	// Context [0]
	ctx0 := asn1Wrap(0xa0, negTokenInitSeq)

	// APPLICATION [0] (GSS-API wrapper)
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02} // 1.3.6.1.5.5.2
	inner := append(spnegoOID, ctx0...)
	return asn1Wrap(0x60, inner)
}

func asn1Wrap(tag byte, data []byte) []byte {
	l := len(data)
	var hdr []byte
	if l < 0x80 {
		hdr = []byte{tag, byte(l)}
	} else if l < 0x100 {
		hdr = []byte{tag, 0x81, byte(l)}
	} else {
		hdr = []byte{tag, 0x82, byte(l >> 8), byte(l)}
	}
	return append(hdr, data...)
}
