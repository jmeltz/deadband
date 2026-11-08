package discover

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
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
	fn, payload, err := ParseBVLC(frame)
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
	_, _, err := ParseBVLC([]byte{0x81})
	if err == nil {
		t.Error("expected error for short frame")
	}
}

func TestParseBVLC_WrongType(t *testing.T) {
	_, _, err := ParseBVLC([]byte{0x82, 0x0A, 0x00, 0x04})
	if err == nil {
		t.Error("expected error for wrong BVLC type")
	}
}

func TestParseBVLC_ForwardedNPDU(t *testing.T) {
	// BVLC Forwarded-NPDU (0x04): 4-byte header + 6-byte originating IPv4:port + 3-byte NPDU
	frame := []byte{
		bvlcTypeBACnetIP, bvlcForwardedNPDU, 0x00, 13,
		10, 0, 1, 50, 0xBA, 0xC0, // originating BBMD client 10.0.1.50:47808
		0x01, 0x00, 0x10,
	}
	fn, payload, err := ParseBVLC(frame)
	if err != nil {
		t.Fatalf("ParseBVLC(Forwarded-NPDU): %v", err)
	}
	if fn != bvlcForwardedNPDU {
		t.Errorf("fn = 0x%02X, want 0x%02X", fn, bvlcForwardedNPDU)
	}
	if len(payload) != 3 || payload[0] != 0x01 || payload[2] != 0x10 {
		t.Errorf("payload = %x, want 010010", payload)
	}
}

func TestParseBACnetNPDU_BroadcastAndRouted(t *testing.T) {
	iam := buildTestIAmAPDU(2030, 480, 0x03, 190) // Danfoss AK-CC55

	// 1. Standard global broadcast I-Am: ctrl=0x20 (DNET=0xFFFF, DLEN=0, HopCount=0xFF)
	bcastNPDU := append([]byte{0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF}, iam...)
	apdu, snet, sadr, err := ParseBACnetNPDU(bcastNPDU)
	if err != nil {
		t.Fatalf("ParseBACnetNPDU(broadcast): %v", err)
	}
	if snet != 0 || len(sadr) != 0 {
		t.Errorf("unexpected source route snet=%d sadr=%x", snet, sadr)
	}
	inst, vid, err := ParseIAmResponse(apdu)
	if err != nil || inst != 2030 || vid != 190 {
		t.Fatalf("ParseIAmResponse after broadcast NPDU = (%d, %d, %v), want (2030, 190, nil)", inst, vid, err)
	}

	// 2. Routed MS/TP I-Am via BACnet/IP router: ctrl=0x28 (DNET=0xFFFF, DLEN=0, SNET=2000, SLEN=1, SADR=0x1E, HopCount=0xFE)
	routedNPDU := append([]byte{0x01, 0x28, 0xFF, 0xFF, 0x00, 0x07, 0xD0, 0x01, 0x1E, 0xFE}, iam...)
	apdu2, snet2, sadr2, err := ParseBACnetNPDU(routedNPDU)
	if err != nil {
		t.Fatalf("ParseBACnetNPDU(routed): %v", err)
	}
	if snet2 != 2000 || len(sadr2) != 1 || sadr2[0] != 0x1E {
		t.Fatalf("routed source = snet:%d sadr:%x, want snet:2000 sadr:1e", snet2, sadr2)
	}
	inst2, vid2, err := ParseIAmResponse(apdu2)
	if err != nil || inst2 != 2030 || vid2 != 190 {
		t.Fatalf("ParseIAmResponse after routed NPDU = (%d, %d, %v), want (2030, 190, nil)", inst2, vid2, err)
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
	apdu := buildTestIAmAPDU(100, 1476, 0x03, 2) // Official ASHRAE Trane vendor ID = 2
	instance, vendorID, err := ParseIAmResponse(apdu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if instance != 100 {
		t.Errorf("device instance = %d, want 100", instance)
	}
	if vendorID != 2 {
		t.Errorf("vendor ID = %d, want 2 (Trane)", vendorID)
	}
}

func TestParseIAmResponse_Honeywell(t *testing.T) {
	apdu := buildTestIAmAPDU(5000, 480, 0x00, 17) // Official ASHRAE Honeywell vendor ID = 17
	instance, vendorID, err := ParseIAmResponse(apdu)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if instance != 5000 {
		t.Errorf("device instance = %d, want 5000", instance)
	}
	if vendorID != 17 {
		t.Errorf("vendor ID = %d, want 17 (Honeywell)", vendorID)
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
	apdu = append(apdu, (tagEnumerated<<4)|1, 0x00)     // Segmentation
	apdu = append(apdu, (tagUnsigned<<4)|1, 0x05)       // Vendor ID = 5 (Johnson Controls)

	instance, vendorID, err := ParseIAmResponse(apdu)
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
	_, _, err := ParseIAmResponse(apdu)
	if err == nil {
		t.Error("expected error for non-I-Am response")
	}
}

func TestParseIAmResponse_TooShort(t *testing.T) {
	_, _, err := ParseIAmResponse([]byte{apduUnconfirmedReq})
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
		{2, "Trane"},
		{3, "Daikin"},
		{5, "Johnson Controls"},
		{7, "Siemens"},
		{10, "Schneider Electric"},
		{16, "Carrier"},
		{17, "Honeywell"},
		{24, "Automated Logic"},
		{36, "Tridium"},
		{53, "Daikin"},
		{56, "Vertiv"},
		{77, "CAREL"},
		{113, "Vertiv"},
		{190, "Danfoss"},
		{222, "WAGO"},
		{364, "Distech Controls"},
		{415, "Beckhoff"},
		{1193, "Copeland"},
		{9999, "BACnet Vendor 9999"},
	}
	for _, tt := range tests {
		got := BACnetVendorName(tt.id)
		if got != tt.want {
			t.Errorf("BACnetVendorName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestBACnetIdentityToDevice(t *testing.T) {
	id := &BACnetIdentity{
		VendorID:         2,
		VendorName:       "Trane",
		ModelName:        "Tracer SC+",
		FirmwareRevision: "6.2.2200",
		ObjectName:       "MDF-BMS-01",
		Location:         "Cold Storage Mezzanine",
		DeviceInstance:   100,
		SourceNet:        2000,
		SourceAddr:       []byte{0x1E},
	}
	dev := BACnetIdentityToDevice("10.0.1.50", id)

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
	if dev.Extra["device_instance"] != "100" || dev.Extra["location"] != "Cold Storage Mezzanine" {
		t.Errorf("Extra = %v, missing device_instance or location", dev.Extra)
	}
	if dev.Extra["bacnet_snet"] != "2000" || dev.Extra["bacnet_sadr"] != "1e" {
		t.Errorf("Extra = %v, missing routed MS/TP metadata", dev.Extra)
	}
}

func TestBACnetIdentifyAllPort_RouterAndRoutedMSTP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	sawRoutedReadProp := make(chan bool, 1)

	go func() {
		buf := make([]byte, 1500)
		for {
			n, clientAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, npdu, err := ParseBVLC(buf[:n])
			if err != nil || len(npdu) < 2 {
				continue
			}

			// Check if Who-Is
			apdu, _, _, err := ParseBACnetNPDU(npdu)
			if err != nil {
				continue
			}
			if len(apdu) >= 2 && apdu[0] == apduUnconfirmedReq && apdu[1] == svcWhoIs {
				// Reply 1: BACnet/IP Router (Tridium JACE-8000, instance 100, global broadcast NPDU 0x20)
				iamRouter := buildTestIAmAPDU(100, 1476, 0x00, 36)
				pkt1 := buildBVLC(bvlcOrigBroadcast, append([]byte{0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF}, iamRouter...))
				_, _ = pc.WriteTo(pkt1, clientAddr)

				// Reply 2: Downstream MS/TP controller (Danfoss AK-CC55, instance 2030, SNET=2000, SADR=0x1E)
				iamMSTP := buildTestIAmAPDU(2030, 480, 0x03, 190)
				pkt2 := buildBVLC(bvlcOrigBroadcast, append([]byte{0x01, 0x28, 0xFF, 0xFF, 0x00, 0x07, 0xD0, 0x01, 0x1E, 0xFE}, iamMSTP...))
				_, _ = pc.WriteTo(pkt2, clientAddr)
				continue
			}

			// Confirmed ReadProperty request
			if len(apdu) >= 11 && (apdu[0]&0xF0) == apduConfirmedReq && apdu[3] == svcReadProperty {
				invokeID := apdu[2]
				objID := binary.BigEndian.Uint32(apdu[5:9])
				inst := objID & 0x003FFFFF
				propID := apdu[10]

				// Verify DNET=2000 (0x07D0) + DADR=0x1E was populated for instance 2030
				if inst == 2030 && (npdu[1]&npduHasDest) != 0 && len(npdu) >= 6 {
					dnet := binary.BigEndian.Uint16(npdu[2:4])
					dlen := npdu[4]
					if dnet == 2000 && dlen == 1 && npdu[5] == 0x1E {
						select {
						case sawRoutedReadProp <- true:
						default:
						}
					}
				}

				val := ""
				switch inst {
				case 100:
					switch propID {
					case propModelName:
						val = "JACE-8000"
					case propFirmwareRevision:
						val = "4.13.1.18"
					case propObjectName:
						val = "BMS-Router-01"
					case propLocation:
						val = "MDF Room"
					}
				case 2030:
					switch propID {
					case propModelName:
						val = "AK-CC55"
					case propFirmwareRevision:
						val = "1.82"
					case propObjectName:
						val = "Evap-Bay-30"
					case propLocation:
						val = "Freezer Aisle 4"
					}
				}
				resp := buildTestReadPropertyResponse(invokeID, inst, propID, val)
				_, _ = pc.WriteTo(resp, clientAddr)
			}
		}
	}()

	ids, err := BACnetIdentifyAllPort("127.0.0.1", port, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("BACnetIdentifyAllPort: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("len(ids) = %d, want 2 (router + MS/TP device)", len(ids))
	}
	if ids[0].VendorName != "Tridium" || ids[0].ModelName != "JACE-8000" || ids[0].FirmwareRevision != "4.13.1.18" {
		t.Errorf("router identity = %+v", ids[0])
	}
	if ids[1].VendorName != "Danfoss" || ids[1].ModelName != "AK-CC55" || ids[1].FirmwareRevision != "1.82" || ids[1].SourceNet != 2000 {
		t.Errorf("routed MS/TP identity = %+v", ids[1])
	}
	select {
	case <-sawRoutedReadProp:
	default:
		t.Error("expected ReadProperty for routed MS/TP device to include DNET=2000 DADR=0x1E")
	}
}
