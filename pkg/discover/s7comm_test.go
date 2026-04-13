package discover

import (
	"encoding/binary"
	"testing"
)

func TestBuildCOTPConnectRequest(t *testing.T) {
	// Rack 0, Slot 2 (S7-300/400 default)
	pkt := buildCOTPConnectRequest(0, 2)

	// TPKT header
	if pkt[0] != tpktVersion {
		t.Errorf("TPKT version = %d, want %d", pkt[0], tpktVersion)
	}
	length := binary.BigEndian.Uint16(pkt[2:4])
	if int(length) != len(pkt) {
		t.Errorf("TPKT length = %d, want %d", length, len(pkt))
	}

	// COTP PDU type
	if pkt[5] != cotpCR {
		t.Errorf("COTP PDU type = 0x%02X, want 0x%02X", pkt[5], cotpCR)
	}

	// Dst TSAP should encode rack 0, slot 2 → 0x0102
	// Find dst TSAP param (0xC2)
	found := false
	for i := 4; i < len(pkt)-3; i++ {
		if pkt[i] == 0xC2 && pkt[i+1] == 0x02 {
			dstTSAP := binary.BigEndian.Uint16(pkt[i+2 : i+4])
			if dstTSAP != 0x0102 {
				t.Errorf("dst TSAP = 0x%04X, want 0x0102", dstTSAP)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("dst TSAP parameter (0xC2) not found in COTP CR")
	}
}

func TestBuildCOTPConnectRequest_S71200(t *testing.T) {
	// Rack 0, Slot 0 (S7-1200/1500)
	pkt := buildCOTPConnectRequest(0, 0)

	for i := 4; i < len(pkt)-3; i++ {
		if pkt[i] == 0xC2 && pkt[i+1] == 0x02 {
			dstTSAP := binary.BigEndian.Uint16(pkt[i+2 : i+4])
			if dstTSAP != 0x0100 {
				t.Errorf("dst TSAP = 0x%04X, want 0x0100 for rack=0,slot=0", dstTSAP)
			}
			return
		}
	}
	t.Error("dst TSAP parameter not found")
}

func TestBuildS7SetupCommunication(t *testing.T) {
	pkt := buildS7SetupCommunication()

	// TPKT header
	if pkt[0] != tpktVersion {
		t.Errorf("TPKT version = %d, want %d", pkt[0], tpktVersion)
	}

	// Skip TPKT (4) + COTP (3) → S7 data starts at offset 7
	if pkt[7] != s7ProtocolID {
		t.Errorf("S7 protocol ID = 0x%02X, want 0x%02X", pkt[7], s7ProtocolID)
	}
	if pkt[8] != s7MsgJob {
		t.Errorf("S7 msg type = 0x%02X, want 0x%02X", pkt[8], s7MsgJob)
	}
	// Function code at offset 17 (7 + 10 header bytes)
	if pkt[17] != s7FuncSetup {
		t.Errorf("S7 function = 0x%02X, want 0x%02X", pkt[17], s7FuncSetup)
	}
}

func TestBuildSZLReadRequest(t *testing.T) {
	pkt := buildSZLReadRequest(szlComponentID, 0x0000)

	if pkt[0] != tpktVersion {
		t.Errorf("TPKT version = %d, want %d", pkt[0], tpktVersion)
	}

	// S7 function at offset 17
	if pkt[17] != s7FuncReadSZL {
		t.Errorf("S7 function = 0x%02X, want 0x%02X", pkt[17], s7FuncReadSZL)
	}
}

// buildTestSZLResponse constructs a synthetic SZL 0x001C response
// mimicking an S7-1200 CPU 1214C DC/DC/DC with firmware V4.5.2.
func buildTestSZLResponse() []byte {
	entryLen := 34 // SZL 0x001C entry size

	// Build SZL entries
	makeEntry := func(index uint16, value string) []byte {
		entry := make([]byte, entryLen)
		binary.BigEndian.PutUint16(entry[0:2], index)
		copy(entry[2:], []byte(value))
		return entry
	}

	entries := [][]byte{
		makeEntry(1, "6ES7 214-1AG40-0XB0"),   // Order number
		makeEntry(2, "CPU 1214C DC/DC/DC"),     // Module name
		makeEntry(3, "S C-H5N44832201"),        // Serial
		makeEntry(7, "V4.5.2"),                 // Firmware
	}

	// SZL header: SZL-ID (2) + count (2) + entry length (2)
	szlHeader := make([]byte, 6)
	binary.BigEndian.PutUint16(szlHeader[0:2], szlComponentID)
	binary.BigEndian.PutUint16(szlHeader[2:4], uint16(len(entries)))
	binary.BigEndian.PutUint16(szlHeader[4:6], uint16(entryLen))

	var szlPayload []byte
	szlPayload = append(szlPayload, szlHeader...)
	for _, e := range entries {
		szlPayload = append(szlPayload, e...)
	}

	// SZL data header: return code (1) + transport size (1) + data length (2)
	szlData := make([]byte, 4)
	szlData[0] = 0xFF // success
	szlData[1] = 0x09 // transport size: octet string
	binary.BigEndian.PutUint16(szlData[2:4], uint16(len(szlPayload)))
	szlData = append(szlData, szlPayload...)

	// S7 parameters (SZL read response)
	s7Params := []byte{
		s7FuncReadSZL,
		s7SubReadSZL,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence + reserved
	}

	// S7 header (10 bytes) + error class/code (2 bytes)
	s7Header := []byte{
		s7ProtocolID,
		s7MsgAckData,
		0x00, 0x00, // Reserved
		0x00, 0x02, // PDU reference
		0x00, 0x00, // Parameter length (placeholder)
		0x00, 0x00, // Data length (placeholder)
		0x00, 0x00, // Error class + code
	}
	binary.BigEndian.PutUint16(s7Header[6:8], uint16(len(s7Params)))
	binary.BigEndian.PutUint16(s7Header[8:10], uint16(len(szlData)))

	// COTP Data
	cotp := []byte{0x02, cotpDT, 0x80}

	// Assemble: COTP + S7 header + S7 params + SZL data
	var payload []byte
	payload = append(payload, cotp...)
	payload = append(payload, s7Header...)
	payload = append(payload, s7Params...)
	payload = append(payload, szlData...)

	return buildTPKT(payload)
}

func TestParseSZLResponse(t *testing.T) {
	data := buildTestSZLResponse()

	id, err := ParseSZLResponse(data)
	if err != nil {
		t.Fatalf("ParseSZLResponse() error: %v", err)
	}

	if id.OrderNumber != "6ES7 214-1AG40-0XB0" {
		t.Errorf("OrderNumber = %q, want %q", id.OrderNumber, "6ES7 214-1AG40-0XB0")
	}
	if id.ModuleName != "CPU 1214C DC/DC/DC" {
		t.Errorf("ModuleName = %q, want %q", id.ModuleName, "CPU 1214C DC/DC/DC")
	}
	if id.SerialNumber != "S C-H5N44832201" {
		t.Errorf("SerialNumber = %q, want %q", id.SerialNumber, "S C-H5N44832201")
	}
	if id.FirmwareVersion != "V4.5.2" {
		t.Errorf("FirmwareVersion = %q, want %q", id.FirmwareVersion, "V4.5.2")
	}
}

func TestParseSZLResponse_TooShort(t *testing.T) {
	_, err := ParseSZLResponse([]byte{0x03, 0x00, 0x00, 0x05, 0x02})
	if err == nil {
		t.Error("expected error for truncated response")
	}
}

func TestParseCOTPResponse_Confirm(t *testing.T) {
	cotp := []byte{0x05, cotpCC, 0x00, 0x01, 0x00, 0x02}
	pkt := buildTPKT(cotp)

	pduType, _, err := parseCOTPResponse(pkt)
	if err != nil {
		t.Fatalf("parseCOTPResponse() error: %v", err)
	}
	if pduType != cotpCC {
		t.Errorf("PDU type = 0x%02X, want 0x%02X", pduType, cotpCC)
	}
}

func TestParseCOTPResponse_Reject(t *testing.T) {
	cotp := []byte{0x05, cotpDR, 0x00, 0x01, 0x00, 0x02}
	pkt := buildTPKT(cotp)

	pduType, _, err := parseCOTPResponse(pkt)
	if err != nil {
		t.Fatalf("parseCOTPResponse() error: %v", err)
	}
	if pduType != cotpDR {
		t.Errorf("PDU type = 0x%02X, want 0x%02X", pduType, cotpDR)
	}
}

func TestParseTPKT_Invalid(t *testing.T) {
	// Wrong version
	_, err := ParseTPKT([]byte{0x01, 0x00, 0x00, 0x04})
	if err == nil {
		t.Error("expected error for wrong TPKT version")
	}

	// Too short
	_, err = ParseTPKT([]byte{0x03, 0x00})
	if err == nil {
		t.Error("expected error for truncated TPKT")
	}
}

func TestS7IdentityToDevice(t *testing.T) {
	id := &S7Identity{
		ModuleName:      "CPU 1214C DC/DC/DC",
		OrderNumber:     "6ES7 214-1AG40-0XB0",
		FirmwareVersion: "V4.5.2",
		SerialNumber:    "S C-H5N44832201",
	}

	dev := S7IdentityToDevice("10.0.1.50", id)

	if dev.IP != "10.0.1.50" {
		t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.50")
	}
	if dev.Vendor != "Siemens" {
		t.Errorf("Vendor = %q, want %q", dev.Vendor, "Siemens")
	}
	if dev.Model != "CPU 1214C DC/DC/DC" {
		t.Errorf("Model = %q, want %q", dev.Model, "CPU 1214C DC/DC/DC")
	}
	if dev.Firmware != "4.5.2" {
		t.Errorf("Firmware = %q, want %q (V prefix should be stripped)", dev.Firmware, "4.5.2")
	}
}

func TestS7IdentityToDevice_FallbackToOrderNumber(t *testing.T) {
	id := &S7Identity{
		OrderNumber:     "6ES7 214-1AG40-0XB0",
		FirmwareVersion: "V4.5.2",
	}

	dev := S7IdentityToDevice("10.0.1.50", id)
	if dev.Model != "6ES7 214-1AG40-0XB0" {
		t.Errorf("Model = %q, want OrderNumber fallback %q", dev.Model, "6ES7 214-1AG40-0XB0")
	}
}

func TestExtractNullTerminated(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{[]byte("hello\x00\x00\x00"), "hello"},
		{[]byte("test"), "test"},
		{[]byte("  padded  \x00"), "padded"},
		{[]byte{0x00, 0x00}, ""},
	}
	for _, tt := range tests {
		got := extractNullTerminated(tt.input)
		if got != tt.want {
			t.Errorf("extractNullTerminated(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
