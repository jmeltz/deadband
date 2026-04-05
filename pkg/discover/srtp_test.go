package discover

import (
	"encoding/binary"
	"testing"
)

func TestBuildSRTPInitFrame(t *testing.T) {
	frame := buildSRTPInitFrame()
	if len(frame) != 56 {
		t.Fatalf("init frame length = %d, want 56", len(frame))
	}
	for i, b := range frame {
		if b != 0x00 {
			t.Errorf("init frame[%d] = 0x%02X, want 0x00", i, b)
		}
	}
}

func TestBuildSRTPRequest(t *testing.T) {
	req := buildSRTPRequest(srtpSvcControllerType)
	if len(req) != 56 {
		t.Fatalf("request length = %d, want 56", len(req))
	}

	checks := []struct {
		offset int
		want   byte
		name   string
	}{
		{0, 0x02, "packet type (REQUEST)"},
		{2, 0x06, "sequence number"},
		{9, 0x01, "read constant"},
		{17, 0x01, "read constant"},
		{30, 0x06, "message sequence"},
		{31, 0xC0, "message type (SHORT)"},
		{36, 0x10, "mailbox dest high"},
		{37, 0x0E, "mailbox dest low"},
		{40, 0x01, "packet number"},
		{41, 0x01, "total packets"},
		{42, 0x43, "service code (controller type)"},
	}
	for _, c := range checks {
		if req[c.offset] != c.want {
			t.Errorf("byte[%d] (%s) = 0x%02X, want 0x%02X", c.offset, c.name, req[c.offset], c.want)
		}
	}
}

func TestBuildSRTPRequestProgramName(t *testing.T) {
	req := buildSRTPRequest(srtpSvcProgramName)
	if req[42] != 0x03 {
		t.Errorf("service code = 0x%02X, want 0x03", req[42])
	}
}

func TestParseSRTPInitResponse(t *testing.T) {
	t.Run("valid INIT_ACK", func(t *testing.T) {
		resp := make([]byte, 56)
		resp[0] = 0x01
		if err := parseSRTPInitResponse(resp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		resp := make([]byte, 56)
		resp[0] = 0x02
		if err := parseSRTPInitResponse(resp); err == nil {
			t.Fatal("expected error for wrong type")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if err := parseSRTPInitResponse(nil); err == nil {
			t.Fatal("expected error for empty response")
		}
	})
}

// buildTestSRTPResponse constructs a synthetic SRTP SHORT_ACK response.
func buildTestSRTPResponse(msgType byte, inlineData []byte) []byte {
	resp := make([]byte, 56)
	resp[0] = srtpTypeRequestACK
	resp[31] = msgType
	if len(inlineData) > 0 && len(inlineData) <= 6 {
		copy(resp[44:44+len(inlineData)], inlineData)
	}
	return resp
}

func TestParseSRTPServiceResponse(t *testing.T) {
	t.Run("valid SHORT_ACK", func(t *testing.T) {
		inline := []byte{0x60, 0x00, 0x01, 0x02, 0x03, 0x04}
		resp := buildTestSRTPResponse(srtpMsgShortACK, inline)

		data, err := parseSRTPServiceResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != 6 {
			t.Fatalf("data length = %d, want 6", len(data))
		}
		if data[0] != 0x60 {
			t.Errorf("data[0] = 0x%02X, want 0x60", data[0])
		}
	})

	t.Run("error response", func(t *testing.T) {
		resp := buildTestSRTPResponse(srtpMsgShortErr, nil)
		_, err := parseSRTPServiceResponse(resp)
		if err == nil {
			t.Fatal("expected error for SHORT_ERR")
		}
	})

	t.Run("wrong packet type", func(t *testing.T) {
		resp := make([]byte, 56)
		resp[0] = 0x02 // REQUEST, not REQUEST_ACK
		resp[31] = srtpMsgShortACK
		_, err := parseSRTPServiceResponse(resp)
		if err == nil {
			t.Fatal("expected error for wrong packet type")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := parseSRTPServiceResponse(make([]byte, 10))
		if err == nil {
			t.Fatal("expected error for short response")
		}
	})

	t.Run("extended payload", func(t *testing.T) {
		resp := make([]byte, 56+8)
		resp[0] = srtpTypeRequestACK
		resp[31] = srtpMsgShortACK
		binary.LittleEndian.PutUint16(resp[4:6], 8) // text_length = 8
		// Inline data
		resp[44] = 0x60
		resp[45] = 0x00
		// Extended payload
		copy(resp[56:], []byte("EXTDATA!"))

		data, err := parseSRTPServiceResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// 6 inline + 8 extended = 14
		if len(data) != 14 {
			t.Fatalf("data length = %d, want 14", len(data))
		}
		if string(data[6:]) != "EXTDATA!" {
			t.Errorf("extended data = %q, want %q", string(data[6:]), "EXTDATA!")
		}
	})
}

func TestParseControllerTypeData(t *testing.T) {
	tests := []struct {
		name      string
		typeCode  uint16
		wantModel string
	}{
		{"RX3i", 0x60, "PACSystems RX3i (IC695)"},
		{"RX3i CPE330", 0x62, "PACSystems RX3i CPE330"},
		{"RX3i CPE400", 0x63, "PACSystems RX3i CPE400"},
		{"RX7i", 0x70, "PACSystems RX7i (IC698)"},
		{"Series 90-30", 0x09, "Series 90-30 CPU (IC693)"},
		{"Series 90-70", 0x06, "Series 90-70 CPU (IC697)"},
		{"VersaMax", 0x20, "VersaMax (IC200)"},
		{"VersaMax Micro", 0x21, "VersaMax Micro (IC200)"},
		{"RSTi-EP CPE100", 0x80, "PACSystems RSTi-EP CPE100"},
		{"RSTi-EP CPE115", 0x81, "PACSystems RSTi-EP CPE115"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, 6)
			binary.LittleEndian.PutUint16(payload[0:2], tt.typeCode)

			id := parseControllerTypeData(payload)
			if id.TypeCode != tt.typeCode {
				t.Errorf("TypeCode = 0x%04X, want 0x%04X", id.TypeCode, tt.typeCode)
			}
			if id.Model != tt.wantModel {
				t.Errorf("Model = %q, want %q", id.Model, tt.wantModel)
			}
		})
	}

	t.Run("unknown type code", func(t *testing.T) {
		payload := make([]byte, 6)
		binary.LittleEndian.PutUint16(payload[0:2], 0xFF)
		id := parseControllerTypeData(payload)
		if id.Model != "PLC (type 0x00FF)" {
			t.Errorf("Model = %q, want %q", id.Model, "PLC (type 0x00FF)")
		}
	})

	t.Run("zero type code", func(t *testing.T) {
		payload := make([]byte, 6)
		id := parseControllerTypeData(payload)
		if id.Model != "PLC" {
			t.Errorf("Model = %q, want %q", id.Model, "PLC")
		}
	})

	t.Run("short payload", func(t *testing.T) {
		id := parseControllerTypeData([]byte{0x01})
		if id.Model != "PLC" {
			t.Errorf("Model = %q, want %q", id.Model, "PLC")
		}
	})
}

func TestParseProgramNameData(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"MY_PROGRAM\x00\x00\x00\x00", "MY_PROGRAM"},
		{"TEST_PGM   ", "TEST_PGM"},
		{"", ""},
		{"\x00\x00\x00", ""},
	}
	for _, tt := range tests {
		got := parseProgramNameData([]byte(tt.input))
		if got != tt.want {
			t.Errorf("parseProgramNameData(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSRTPControllerName(t *testing.T) {
	if got := srtpControllerName(0x60); got != "PACSystems RX3i (IC695)" {
		t.Errorf("0x60 = %q, want PACSystems RX3i (IC695)", got)
	}
	if got := srtpControllerName(0x00); got != "PLC" {
		t.Errorf("0x00 = %q, want PLC", got)
	}
	if got := srtpControllerName(0xAB); got != "PLC (type 0x00AB)" {
		t.Errorf("0xAB = %q, want PLC (type 0x00AB)", got)
	}
}

func TestSRTPIdentityToDevice(t *testing.T) {
	dev := srtpIdentityToDevice("10.0.1.100", &SRTPIdentity{
		TypeCode: 0x60,
		Model:    "PACSystems RX3i (IC695)",
	})
	if dev.IP != "10.0.1.100" {
		t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.100")
	}
	if dev.Vendor != "Emerson / GE" {
		t.Errorf("Vendor = %q, want %q", dev.Vendor, "Emerson / GE")
	}
	if dev.Model != "PACSystems RX3i (IC695)" {
		t.Errorf("Model = %q, want %q", dev.Model, "PACSystems RX3i (IC695)")
	}
}

func TestSRTPFullResponseParsing(t *testing.T) {
	// Build a complete SHORT_ACK response with RX3i type code
	resp := buildTestSRTPResponse(srtpMsgShortACK, []byte{0x62, 0x00, 0x00, 0x00, 0x00, 0x00})

	data, err := parseSRTPServiceResponse(resp)
	if err != nil {
		t.Fatalf("parseSRTPServiceResponse: %v", err)
	}

	id := parseControllerTypeData(data)
	if id.TypeCode != 0x62 {
		t.Errorf("TypeCode = 0x%04X, want 0x0062", id.TypeCode)
	}
	if id.Model != "PACSystems RX3i CPE330" {
		t.Errorf("Model = %q, want %q", id.Model, "PACSystems RX3i CPE330")
	}
}
