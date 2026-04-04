package discover

import (
	"encoding/binary"
	"testing"
)

func TestBuildModbusMBAP(t *testing.T) {
	pdu := []byte{0x2B, 0x0E, 0x02, 0x00} // Read Device ID, Regular, Object 0
	frame := buildModbusMBAP(0x0001, 0x01, pdu)

	// MBAP: txnID(2) + protocolID(2) + length(2) + unitID(1) + PDU
	if len(frame) != 11 {
		t.Fatalf("frame length = %d, want 11", len(frame))
	}

	// Transaction ID
	txnID := binary.BigEndian.Uint16(frame[0:2])
	if txnID != 1 {
		t.Errorf("transaction ID = %d, want 1", txnID)
	}

	// Protocol ID
	protoID := binary.BigEndian.Uint16(frame[2:4])
	if protoID != 0x0000 {
		t.Errorf("protocol ID = 0x%04X, want 0x0000", protoID)
	}

	// Length = unit ID (1) + PDU (4) = 5
	length := binary.BigEndian.Uint16(frame[4:6])
	if length != 5 {
		t.Errorf("length = %d, want 5", length)
	}

	// Unit ID
	if frame[6] != 0x01 {
		t.Errorf("unit ID = 0x%02X, want 0x01", frame[6])
	}

	// PDU
	if frame[7] != 0x2B || frame[8] != 0x0E || frame[9] != 0x02 || frame[10] != 0x00 {
		t.Errorf("PDU mismatch: got %X", frame[7:])
	}
}

func TestBuildReadDeviceIDRequest(t *testing.T) {
	frame := buildReadDeviceIDRequest(0x0001, 0x01, devIDRegular, 0x00)

	if len(frame) != 11 {
		t.Fatalf("frame length = %d, want 11", len(frame))
	}

	// PDU bytes
	if frame[7] != mbFuncMEI {
		t.Errorf("function code = 0x%02X, want 0x%02X", frame[7], mbFuncMEI)
	}
	if frame[8] != meiReadDeviceID {
		t.Errorf("MEI type = 0x%02X, want 0x%02X", frame[8], meiReadDeviceID)
	}
	if frame[9] != devIDRegular {
		t.Errorf("read code = 0x%02X, want 0x%02X", frame[9], devIDRegular)
	}
	if frame[10] != 0x00 {
		t.Errorf("object ID = 0x%02X, want 0x00", frame[10])
	}
}

func TestParseMBAPHeader(t *testing.T) {
	// Build a valid MBAP + PDU
	pdu := []byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x07, byte(len("TestVendor")), 'T', 'e', 's', 't', 'V', 'e', 'n', 'd', 'o', 'r'}
	frame := buildModbusMBAP(0x0042, 0x01, pdu)

	txnID, unitID, parsedPDU, err := parseMBAPHeader(frame)
	if err != nil {
		t.Fatalf("parseMBAPHeader error: %v", err)
	}
	if txnID != 0x0042 {
		t.Errorf("transaction ID = 0x%04X, want 0x0042", txnID)
	}
	if unitID != 0x01 {
		t.Errorf("unit ID = 0x%02X, want 0x01", unitID)
	}
	if len(parsedPDU) != len(pdu) {
		t.Errorf("PDU length = %d, want %d", len(parsedPDU), len(pdu))
	}
}

func TestParseMBAPHeader_TooShort(t *testing.T) {
	_, _, _, err := parseMBAPHeader([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestParseMBAPHeader_WrongProtocol(t *testing.T) {
	data := make([]byte, 11)
	binary.BigEndian.PutUint16(data[2:4], 0x0001) // wrong protocol
	binary.BigEndian.PutUint16(data[4:6], 5)
	_, _, _, err := parseMBAPHeader(data)
	if err == nil {
		t.Error("expected error for wrong protocol ID")
	}
}

// buildTestDeviceIDResponse constructs a synthetic Read Device ID response.
func buildTestDeviceIDResponse(txnID uint16, objects map[byte]string, moreFollows bool, nextObjID byte) []byte {
	// Build the object list
	var objBytes []byte
	numObj := byte(0)
	for id, val := range objects {
		objBytes = append(objBytes, id, byte(len(val)))
		objBytes = append(objBytes, []byte(val)...)
		numObj++
	}

	mf := byte(0x00)
	if moreFollows {
		mf = 0xFF
	}

	pdu := []byte{
		mbFuncMEI,
		meiReadDeviceID,
		devIDRegular, // Read Device ID code (echo)
		0x02,         // Conformity level: regular
		mf,           // More follows
		nextObjID,    // Next object ID
		numObj,       // Number of objects
	}
	pdu = append(pdu, objBytes...)

	return buildModbusMBAP(txnID, 0x01, pdu)
}

func TestParseReadDeviceIDResponse_Basic(t *testing.T) {
	objects := map[byte]string{
		objVendorName:         "Schneider Electric",
		objProductCode:        "TM241CE40R",
		objMajorMinorRevision: "5.0.4.12",
	}
	frame := buildTestDeviceIDResponse(1, objects, false, 0)
	_, _, pdu, err := parseMBAPHeader(frame)
	if err != nil {
		t.Fatalf("MBAP parse error: %v", err)
	}

	parsed, more, _, err := parseReadDeviceIDResponse(pdu)
	if err != nil {
		t.Fatalf("parseReadDeviceIDResponse error: %v", err)
	}
	if more {
		t.Error("expected moreFollows = false")
	}
	if parsed[objVendorName] != "Schneider Electric" {
		t.Errorf("vendor = %q, want %q", parsed[objVendorName], "Schneider Electric")
	}
	if parsed[objProductCode] != "TM241CE40R" {
		t.Errorf("product code = %q, want %q", parsed[objProductCode], "TM241CE40R")
	}
	if parsed[objMajorMinorRevision] != "5.0.4.12" {
		t.Errorf("revision = %q, want %q", parsed[objMajorMinorRevision], "5.0.4.12")
	}
}

func TestParseReadDeviceIDResponse_Regular(t *testing.T) {
	objects := map[byte]string{
		objVendorName:         "ABB",
		objProductCode:        "AC500",
		objMajorMinorRevision: "3.4.1",
		objProductName:        "AC500 PM573-ETH",
		objModelName:          "PM573-ETH",
	}
	frame := buildTestDeviceIDResponse(1, objects, false, 0)
	_, _, pdu, _ := parseMBAPHeader(frame)

	parsed, _, _, err := parseReadDeviceIDResponse(pdu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if parsed[objModelName] != "PM573-ETH" {
		t.Errorf("model name = %q, want %q", parsed[objModelName], "PM573-ETH")
	}
	if parsed[objProductName] != "AC500 PM573-ETH" {
		t.Errorf("product name = %q, want %q", parsed[objProductName], "AC500 PM573-ETH")
	}
}

func TestParseReadDeviceIDResponse_MoreFollows(t *testing.T) {
	objects := map[byte]string{
		objVendorName:  "Schneider Electric",
		objProductCode: "M340",
	}
	frame := buildTestDeviceIDResponse(1, objects, true, 0x02)
	_, _, pdu, _ := parseMBAPHeader(frame)

	_, more, nextObj, err := parseReadDeviceIDResponse(pdu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !more {
		t.Error("expected moreFollows = true")
	}
	if nextObj != 0x02 {
		t.Errorf("next object ID = 0x%02X, want 0x02", nextObj)
	}
}

func TestParseReadDeviceIDResponse_Exception(t *testing.T) {
	pdu := []byte{mbFuncMEIError, 0x01} // Illegal Function exception
	_, _, _, err := parseReadDeviceIDResponse(pdu)
	if err == nil {
		t.Error("expected error for exception response")
	}
}

func TestParseReadDeviceIDResponse_WrongFuncCode(t *testing.T) {
	pdu := []byte{0x03, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x00}
	_, _, _, err := parseReadDeviceIDResponse(pdu)
	if err == nil {
		t.Error("expected error for wrong function code")
	}
}

func TestParseReadDeviceIDResponse_TooShort(t *testing.T) {
	pdu := []byte{mbFuncMEI, meiReadDeviceID, 0x01}
	_, _, _, err := parseReadDeviceIDResponse(pdu)
	if err == nil {
		t.Error("expected error for truncated response")
	}
}

func TestModbusIdentityToDevice(t *testing.T) {
	tests := []struct {
		name     string
		id       ModbusIdentity
		wantVend string
		wantMod  string
		wantFW   string
	}{
		{
			name: "schneider with model name",
			id: ModbusIdentity{
				VendorName:  "Schneider Electric",
				ProductCode: "TM241CE40R",
				Revision:    "5.0.4.12",
				ModelName:   "Modicon M241",
			},
			wantVend: "Schneider Electric",
			wantMod:  "Modicon M241",
			wantFW:   "5.0.4.12",
		},
		{
			name: "abb falls back to product name",
			id: ModbusIdentity{
				VendorName:  "ABB",
				ProductCode: "AC500-eCo",
				Revision:    "3.1.0",
				ProductName: "AC500 PM554-T",
			},
			wantVend: "ABB",
			wantMod:  "AC500 PM554-T",
			wantFW:   "3.1.0",
		},
		{
			name: "delta falls back to product code",
			id: ModbusIdentity{
				VendorName:  "Delta Electronics, Inc.",
				ProductCode: "DVP28SV",
				Revision:    "2.40",
			},
			wantVend: "Delta Electronics",
			wantMod:  "DVP28SV",
			wantFW:   "2.40",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := modbusIdentityToDevice("10.0.1.5", &tt.id)
			if dev.Vendor != tt.wantVend {
				t.Errorf("vendor = %q, want %q", dev.Vendor, tt.wantVend)
			}
			if dev.Model != tt.wantMod {
				t.Errorf("model = %q, want %q", dev.Model, tt.wantMod)
			}
			if dev.Firmware != tt.wantFW {
				t.Errorf("firmware = %q, want %q", dev.Firmware, tt.wantFW)
			}
			if dev.IP != "10.0.1.5" {
				t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.5")
			}
		})
	}
}

func TestNormalizeModbusVendor(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"Schneider Electric", "Schneider Electric"},
		{"schneider electric industries", "Schneider Electric"},
		{"ABB", "ABB"},
		{"ABB Ltd", "ABB"},
		{"Hitachi Energy Ltd", "Hitachi Energy"},
		{"Delta Electronics, Inc.", "Delta Electronics"},
		{"Moxa Inc.", "Moxa"},
		{"PHOENIX CONTACT", "Phoenix Contact"},
		{"WAGO GmbH & Co. KG", "WAGO"},
		{"Emerson Electric Co.", "Emerson"},
		{"Yokogawa Electric", "Yokogawa"},
		{"Eaton Corporation", "Eaton"},
		{"General Electric", "GE Vernova"},
		{"GE Vernova", "GE Vernova"},
		{"Beckhoff Automation", "Beckhoff"},
		{"OMRON Corporation", "Omron"},
		{"Allen-Bradley", "Rockwell Automation"},
		{"Unknown Vendor Co.", "Unknown Vendor Co."},
		{"", ""},
		{"  Moxa  ", "Moxa"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got := normalizeModbusVendor(tt.raw)
			if got != tt.want {
				t.Errorf("normalizeModbusVendor(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
