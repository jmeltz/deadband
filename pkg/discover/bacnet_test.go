package discover

import (
	"encoding/binary"
	"testing"
)

func TestBuildBVLC(t *testing.T) {
	payload := []byte{0x01, 0x04, 0x10, 0x08} // NPDU + Who-Is
	frame := buildBVLC(bvlcOrigUnicast, payload)

	if len(frame) != 8 {
		t.Fatalf("frame length = %d, want 8", len(frame))
	}
	if frame[0] != bvlcTypeBACnetIP {
		t.Errorf("type = 0x%02X, want 0x%02X", frame[0], bvlcTypeBACnetIP)
	}
	if frame[1] != bvlcOrigUnicast {
		t.Errorf("function = 0x%02X, want 0x%02X", frame[1], bvlcOrigUnicast)
	}
	length := binary.BigEndian.Uint16(frame[2:4])
	if length != 8 {
		t.Errorf("length = %d, want 8", length)
	}
}

func TestBuildWhoIsRequest(t *testing.T) {
	frame := buildWhoIsRequest()

	// BVLC(4) + NPDU(2) + APDU(2) = 8
	if len(frame) != 8 {
		t.Fatalf("frame length = %d, want 8", len(frame))
	}
	// BVLC
	if frame[0] != bvlcTypeBACnetIP || frame[1] != bvlcOrigUnicast {
		t.Errorf("BVLC header mismatch")
	}
	// NPDU
	if frame[4] != npduVersion || frame[5] != npduExpectReply {
		t.Errorf("NPDU = [%02X %02X], want [%02X %02X]", frame[4], frame[5], npduVersion, npduExpectReply)
	}
	// APDU
	if frame[6] != apduUnconfirmedReq || frame[7] != svcWhoIs {
		t.Errorf("APDU = [%02X %02X], want [%02X %02X]", frame[6], frame[7], apduUnconfirmedReq, svcWhoIs)
	}
}

func TestBuildReadPropertyRequest(t *testing.T) {
	frame := buildReadPropertyRequest(0x01, 100, propModelName)

	// BVLC(4) + NPDU(2) + APDU: header(4) + ctx0(1+4) + ctx1(1+1) = 17
	if len(frame) != 17 {
		t.Fatalf("frame length = %d, want 17", len(frame))
	}

	// APDU starts at offset 6
	apdu := frame[6:]
	if apdu[0] != apduConfirmedReq {
		t.Errorf("PDU type = 0x%02X, want 0x%02X", apdu[0], apduConfirmedReq)
	}
	if apdu[2] != 0x01 { // invoke ID
		t.Errorf("invoke ID = 0x%02X, want 0x01", apdu[2])
	}
	if apdu[3] != svcReadProperty {
		t.Errorf("service = 0x%02X, want 0x%02X", apdu[3], svcReadProperty)
	}

	// Context tag 0: Object Identifier
	if apdu[4] != 0x0C {
		t.Errorf("ctx tag 0 = 0x%02X, want 0x0C", apdu[4])
	}
	objID := binary.BigEndian.Uint32(apdu[5:9])
	wantObjID := (uint32(objTypeDevice) << 22) | 100
	if objID != wantObjID {
		t.Errorf("object ID = 0x%08X, want 0x%08X", objID, wantObjID)
	}

	// Context tag 1: Property ID
	if apdu[9] != 0x19 {
		t.Errorf("ctx tag 1 = 0x%02X, want 0x19", apdu[9])
	}
	if apdu[10] != propModelName {
		t.Errorf("property ID = %d, want %d", apdu[10], propModelName)
	}
}

func TestParseBVLC(t *testing.T) {
	frame := buildBVLC(bvlcOrigUnicast, []byte{0x01, 0x02, 0x03})
	fn, payload, err := parseBVLC(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if fn != bvlcOrigUnicast {
		t.Errorf("function = 0x%02X, want 0x%02X", fn, bvlcOrigUnicast)
	}
	if len(payload) != 3 {
		t.Errorf("payload length = %d, want 3", len(payload))
	}
}

func TestParseBVLC_TooShort(t *testing.T) {
	_, _, err := parseBVLC([]byte{0x81})
	if err == nil {
		t.Error("expected error for short frame")
	}
}

func TestParseBVLC_WrongType(t *testing.T) {
	_, _, err := parseBVLC([]byte{0x82, 0x0A, 0x00, 0x04})
	if err == nil {
		t.Error("expected error for wrong BVLC type")
	}
}

// buildTestIAmAPDU constructs a synthetic I-Am APDU.
func buildTestIAmAPDU(deviceInstance uint32, maxAPDU uint16, segmentation byte, vendorID uint16) []byte {
	apdu := []byte{apduUnconfirmedReq, svcIAm}

	// Application tag 12 (Object Identifier), 4 bytes
	objID := make([]byte, 4)
	binary.BigEndian.PutUint32(objID, (objTypeDevice<<22)|deviceInstance)
	apdu = append(apdu, (tagObjectID<<4)|4)
	apdu = append(apdu, objID...)

	// Application tag 2 (Unsigned), 2 bytes — Max APDU
	apdu = append(apdu, (tagUnsigned<<4)|2)
	maxBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(maxBuf, maxAPDU)
	apdu = append(apdu, maxBuf...)

	// Application tag 9 (Enumerated), 1 byte — Segmentation
	apdu = append(apdu, (tagEnumerated<<4)|1)
	apdu = append(apdu, segmentation)

	// Application tag 2 (Unsigned), 2 bytes — Vendor ID
	apdu = append(apdu, (tagUnsigned<<4)|2)
	vidBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(vidBuf, vendorID)
	apdu = append(apdu, vidBuf...)

	return apdu
}

func TestParseIAmResponse_Trane(t *testing.T) {
	apdu := buildTestIAmAPDU(100, 1476, 0x03, 66) // Trane vendor ID = 66
	instance, vendorID, err := parseIAmResponse(apdu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if instance != 100 {
		t.Errorf("device instance = %d, want 100", instance)
	}
	if vendorID != 66 {
		t.Errorf("vendor ID = %d, want 66 (Trane)", vendorID)
	}
}

func TestParseIAmResponse_Honeywell(t *testing.T) {
	apdu := buildTestIAmAPDU(5000, 480, 0x00, 15) // Honeywell vendor ID = 15
	instance, vendorID, err := parseIAmResponse(apdu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if instance != 5000 {
		t.Errorf("device instance = %d, want 5000", instance)
	}
	if vendorID != 15 {
		t.Errorf("vendor ID = %d, want 15 (Honeywell)", vendorID)
	}
}

func TestParseIAmResponse_SmallVendorID(t *testing.T) {
	// Vendor ID that fits in 1 byte
	apdu := []byte{apduUnconfirmedReq, svcIAm}
	objID := make([]byte, 4)
	binary.BigEndian.PutUint32(objID, (objTypeDevice<<22)|42)
	apdu = append(apdu, (tagObjectID<<4)|4)
	apdu = append(apdu, objID...)
	apdu = append(apdu, (tagUnsigned<<4)|2, 0x05, 0xC4) // Max APDU 1476
	apdu = append(apdu, (tagEnumerated<<4)|1, 0x00)       // Segmentation
	apdu = append(apdu, (tagUnsigned<<4)|1, 0x05)          // Vendor ID = 5 (Johnson Controls)

	instance, vendorID, err := parseIAmResponse(apdu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if instance != 42 {
		t.Errorf("device instance = %d, want 42", instance)
	}
	if vendorID != 5 {
		t.Errorf("vendor ID = %d, want 5", vendorID)
	}
}

func TestParseIAmResponse_NotIAm(t *testing.T) {
	apdu := []byte{apduUnconfirmedReq, svcWhoIs}
	_, _, err := parseIAmResponse(apdu)
	if err == nil {
		t.Error("expected error for non-I-Am response")
	}
}

func TestParseIAmResponse_TooShort(t *testing.T) {
	_, _, err := parseIAmResponse([]byte{apduUnconfirmedReq})
	if err == nil {
		t.Error("expected error for short APDU")
	}
}

// buildTestReadPropertyResponse constructs a synthetic Complex-Ack ReadProperty response.
func buildTestReadPropertyResponse(invokeID byte, deviceInstance uint32, propertyID byte, stringValue string) []byte {
	// APDU header
	apdu := []byte{
		apduComplexAck,
		invokeID,
		svcReadProperty,
	}

	// Context tag 0: Object Identifier
	objID := make([]byte, 4)
	binary.BigEndian.PutUint32(objID, (objTypeDevice<<22)|deviceInstance)
	apdu = append(apdu, 0x0C)
	apdu = append(apdu, objID...)

	// Context tag 1: Property Identifier
	apdu = append(apdu, 0x19, propertyID)

	// Context tag 3 opening
	apdu = append(apdu, 0x3E)

	// Application tag 7 (CharacterString): encoding(1) + string
	charLen := 1 + len(stringValue) // encoding byte + string
	if charLen <= 4 {
		apdu = append(apdu, (tagCharString<<4)|byte(charLen))
	} else {
		apdu = append(apdu, (tagCharString<<4)|5, byte(charLen))
	}
	apdu = append(apdu, 0x00) // UTF-8 encoding
	apdu = append(apdu, []byte(stringValue)...)

	// Context tag 3 closing
	apdu = append(apdu, 0x3F)

	// Wrap with NPDU + BVLC
	npdu := []byte{npduVersion, npduNoExpect}
	payload := append(npdu, apdu...)
	return buildBVLC(bvlcOrigUnicast, payload)
}

func TestParseReadPropertyResponse_ModelName(t *testing.T) {
	frame := buildTestReadPropertyResponse(1, 100, propModelName, "Tracer SC+")
	val, err := parseReadPropertyResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if val != "Tracer SC+" {
		t.Errorf("value = %q, want %q", val, "Tracer SC+")
	}
}

func TestParseReadPropertyResponse_FirmwareRevision(t *testing.T) {
	frame := buildTestReadPropertyResponse(2, 100, propFirmwareRevision, "6.2.2200")
	val, err := parseReadPropertyResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if val != "6.2.2200" {
		t.Errorf("value = %q, want %q", val, "6.2.2200")
	}
}

func TestParseReadPropertyResponse_LongString(t *testing.T) {
	longModel := "Honeywell Spyder PUB6438S"
	frame := buildTestReadPropertyResponse(1, 200, propModelName, longModel)
	val, err := parseReadPropertyResponse(frame)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if val != longModel {
		t.Errorf("value = %q, want %q", val, longModel)
	}
}

func TestParseReadPropertyResponse_ErrorPDU(t *testing.T) {
	npdu := []byte{npduVersion, npduNoExpect}
	apdu := []byte{apduError, 0x01, svcReadProperty, 0x00, 0x00}
	payload := append(npdu, apdu...)
	frame := buildBVLC(bvlcOrigUnicast, payload)

	_, err := parseReadPropertyResponse(frame)
	if err == nil {
		t.Error("expected error for error PDU")
	}
}

func TestBACnetVendorName(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{66, "Trane"},
		{15, "Honeywell"},
		{5, "Johnson Controls"},
		{343, "Schneider Electric"},
		{404, "Siemens"},
		{222, "Daikin"},
		{9999, "BACnet Vendor 9999"},
	}
	for _, tt := range tests {
		got := bacnetVendorName(tt.id)
		if got != tt.want {
			t.Errorf("bacnetVendorName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestBACnetIdentityToDevice(t *testing.T) {
	id := &BACnetIdentity{
		VendorID:         66,
		VendorName:       "Trane",
		ModelName:        "Tracer SC+",
		FirmwareRevision: "6.2.2200",
		DeviceInstance:   100,
	}
	dev := bacnetIdentityToDevice("10.0.1.50", id)

	if dev.IP != "10.0.1.50" {
		t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.50")
	}
	if dev.Vendor != "Trane" {
		t.Errorf("vendor = %q, want %q", dev.Vendor, "Trane")
	}
	if dev.Model != "Tracer SC+" {
		t.Errorf("model = %q, want %q", dev.Model, "Tracer SC+")
	}
	if dev.Firmware != "6.2.2200" {
		t.Errorf("firmware = %q, want %q", dev.Firmware, "6.2.2200")
	}
}
