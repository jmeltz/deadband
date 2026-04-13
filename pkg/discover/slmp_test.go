package discover

import (
	"encoding/binary"
	"testing"
)

func TestBuildSLMPRequest(t *testing.T) {
	frame := buildSLMPRequest(slmpCmdReadTypeName, 0x0000, nil)

	// header(9) + timer(2) + command(2) + subcommand(2) = 15
	if len(frame) != 15 {
		t.Fatalf("frame length = %d, want 15", len(frame))
	}

	if frame[0] != 0x50 || frame[1] != 0x00 {
		t.Errorf("subheader = 0x%02X%02X, want 0x5000", frame[0], frame[1])
	}
	if frame[2] != 0x00 || frame[3] != 0xFF {
		t.Errorf("network/station = %02X/%02X, want 00/FF", frame[2], frame[3])
	}

	moduleIO := binary.LittleEndian.Uint16(frame[4:6])
	if moduleIO != 0x03FF {
		t.Errorf("module I/O = 0x%04X, want 0x03FF", moduleIO)
	}
	if frame[6] != 0x00 {
		t.Errorf("multidrop = 0x%02X, want 0x00", frame[6])
	}

	dataLen := binary.LittleEndian.Uint16(frame[7:9])
	if dataLen != 6 {
		t.Errorf("data length = %d, want 6", dataLen)
	}

	cmd := binary.LittleEndian.Uint16(frame[11:13])
	if cmd != 0x0101 {
		t.Errorf("command = 0x%04X, want 0x0101", cmd)
	}

	subcmd := binary.LittleEndian.Uint16(frame[13:15])
	if subcmd != 0x0000 {
		t.Errorf("subcommand = 0x%04X, want 0x0000", subcmd)
	}
}

func TestBuildSLMPRequest_WithData(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	frame := buildSLMPRequest(0x0401, 0x0000, data)

	// header(9) + timer(2) + command(2) + subcommand(2) + data(3) = 18
	if len(frame) != 18 {
		t.Fatalf("frame length = %d, want 18", len(frame))
	}

	dataLen := binary.LittleEndian.Uint16(frame[7:9])
	if dataLen != 9 { // 2+2+2+3
		t.Errorf("data length = %d, want 9", dataLen)
	}

	if frame[15] != 0x01 || frame[16] != 0x02 || frame[17] != 0x03 {
		t.Errorf("data payload mismatch: %X", frame[15:])
	}
}

func TestBuildReadTypeNameRequest(t *testing.T) {
	frame := buildReadTypeNameRequest()
	if len(frame) != 15 {
		t.Fatalf("frame length = %d, want 15", len(frame))
	}
	if frame[0] != 0x50 || frame[1] != 0x00 {
		t.Error("not a valid SLMP request subheader")
	}
}

// buildTestSLMPResponse constructs a synthetic SLMP 3E binary response.
func buildTestSLMPResponse(endCode uint16, payload []byte) []byte {
	dataLen := 2 + len(payload)
	frame := make([]byte, 9+dataLen)

	frame[0] = 0xD0
	frame[1] = 0x00
	frame[2] = 0x00
	frame[3] = 0xFF
	binary.LittleEndian.PutUint16(frame[4:6], 0x03FF)
	frame[6] = 0x00
	binary.LittleEndian.PutUint16(frame[7:9], uint16(dataLen))
	binary.LittleEndian.PutUint16(frame[9:11], endCode)

	if len(payload) > 0 {
		copy(frame[11:], payload)
	}
	return frame
}

func TestParseSLMPResponse_Success(t *testing.T) {
	payload := []byte("test data")
	frame := buildTestSLMPResponse(0x0000, payload)

	endCode, data, err := ParseSLMPResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if endCode != 0x0000 {
		t.Errorf("end code = 0x%04X, want 0x0000", endCode)
	}
	if string(data) != "test data" {
		t.Errorf("payload = %q, want %q", data, "test data")
	}
}

func TestParseSLMPResponse_ErrorEndCode(t *testing.T) {
	frame := buildTestSLMPResponse(0xC059, nil)

	endCode, _, err := ParseSLMPResponse(frame)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if endCode != 0xC059 {
		t.Errorf("end code = 0x%04X, want 0xC059", endCode)
	}
}

func TestParseSLMPResponse_TooShort(t *testing.T) {
	_, _, err := ParseSLMPResponse([]byte{0xD0, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for short frame")
	}
}

func TestParseSLMPResponse_WrongSubheader(t *testing.T) {
	frame := buildTestSLMPResponse(0x0000, nil)
	frame[0] = 0x50 // request subheader, not response
	_, _, err := ParseSLMPResponse(frame)
	if err == nil {
		t.Error("expected error for wrong subheader")
	}
}

func TestParseReadTypeNameResponse_RSeries(t *testing.T) {
	payload := make([]byte, 18)
	copy(payload, "R04CPU")
	for i := len("R04CPU"); i < 16; i++ {
		payload[i] = ' '
	}
	binary.LittleEndian.PutUint16(payload[16:18], 0x0042)

	frame := buildTestSLMPResponse(0x0000, payload)
	id, err := ParseReadTypeNameResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id.ModelName != "R04CPU" {
		t.Errorf("model = %q, want %q", id.ModelName, "R04CPU")
	}
	if id.TypeCode != 0x0042 {
		t.Errorf("type code = 0x%04X, want 0x0042", id.TypeCode)
	}
}

func TestParseReadTypeNameResponse_QSeries(t *testing.T) {
	payload := make([]byte, 18)
	copy(payload, "Q03UDVCPU")
	for i := len("Q03UDVCPU"); i < 16; i++ {
		payload[i] = ' '
	}

	frame := buildTestSLMPResponse(0x0000, payload)
	id, err := ParseReadTypeNameResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id.ModelName != "Q03UDVCPU" {
		t.Errorf("model = %q, want %q", id.ModelName, "Q03UDVCPU")
	}
}

func TestParseReadTypeNameResponse_FX5(t *testing.T) {
	payload := make([]byte, 16) // no type code
	copy(payload, "FX5U-32MT/ES")
	for i := len("FX5U-32MT/ES"); i < 16; i++ {
		payload[i] = ' '
	}

	frame := buildTestSLMPResponse(0x0000, payload)
	id, err := ParseReadTypeNameResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id.ModelName != "FX5U-32MT/ES" {
		t.Errorf("model = %q, want %q", id.ModelName, "FX5U-32MT/ES")
	}
	if id.TypeCode != 0 {
		t.Errorf("type code = 0x%04X, want 0x0000", id.TypeCode)
	}
}

func TestParseReadTypeNameResponse_NullPadded(t *testing.T) {
	payload := make([]byte, 18)
	copy(payload, "L02CPU")

	frame := buildTestSLMPResponse(0x0000, payload)
	id, err := ParseReadTypeNameResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id.ModelName != "L02CPU" {
		t.Errorf("model = %q, want %q", id.ModelName, "L02CPU")
	}
}

func TestParseReadTypeNameResponse_ErrorCode(t *testing.T) {
	frame := buildTestSLMPResponse(0xC059, nil)
	_, err := ParseReadTypeNameResponse(frame)
	if err == nil {
		t.Error("expected error for non-zero end code")
	}
}

func TestParseReadTypeNameResponse_ShortPayload(t *testing.T) {
	frame := buildTestSLMPResponse(0x0000, []byte("short"))
	_, err := ParseReadTypeNameResponse(frame)
	if err == nil {
		t.Error("expected error for short payload")
	}
}

func TestSLMPIdentityToDevice(t *testing.T) {
	id := &SLMPIdentity{ModelName: "R04CPU", TypeCode: 0x0042}
	dev := SLMPIdentityToDevice("10.0.1.50", id)

	if dev.IP != "10.0.1.50" {
		t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.50")
	}
	if dev.Vendor != "Mitsubishi Electric" {
		t.Errorf("vendor = %q, want %q", dev.Vendor, "Mitsubishi Electric")
	}
	if dev.Model != "R04CPU" {
		t.Errorf("model = %q, want %q", dev.Model, "R04CPU")
	}
	if dev.Firmware != "" {
		t.Errorf("firmware = %q, want empty", dev.Firmware)
	}
}
