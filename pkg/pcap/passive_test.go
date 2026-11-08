package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoopbackCapturesAndS7Framing(t *testing.T) {
	readFixture := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "discover", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		v, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	component := readFixture("saq-s7-001c.hex")
	module := readFixture("saq-s7-0011.hex")
	for _, link := range []uint32{0, 1, 101, 108, 228} {
		t.Run(fmt.Sprint(link), func(t *testing.T) {
			var frames [][]byte
			for _, payload := range [][]byte{component, module} {
				eth := buildTestEthernetIPv4Frame("127.0.0.2", "127.0.0.1", 6, 102, 50000, payload)
				frame := eth
				switch link {
				case 0:
					frame = append([]byte{2, 0, 0, 0}, eth[14:]...)
				case 108:
					frame = append([]byte{0, 0, 0, 2}, eth[14:]...)
				case 101, 228:
					frame = eth[14:]
				}
				frames = append(frames, frame)
			}
			path := writeTestPCAP(t, frames)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			binary.LittleEndian.PutUint32(data[20:24], link)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := Analyze(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Devices) != 1 {
				t.Fatalf("devices %+v", r)
			}
			d := r.Devices[0]
			if d.Model != "CPU 1511-1 PN" || d.Serial != "S C-SAQ0000001" || d.Firmware != "2.9.4" {
				t.Fatalf("incorrect S7 component identity %+v", d)
			}
		})
	}
}

func buildTestEthernetIPv4Frame(srcIP, dstIP string, proto uint8, srcPort, dstPort uint16, payload []byte) []byte {
	var buf bytes.Buffer
	// Ethernet header (14 bytes): dst MAC(6) + src MAC(6) + EtherType IPv4 (0x0800)
	buf.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	buf.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0800))

	var l4 bytes.Buffer
	if proto == 6 {
		// Minimal 20-byte TCP header
		_ = binary.Write(&l4, binary.BigEndian, srcPort)
		_ = binary.Write(&l4, binary.BigEndian, dstPort)
		_ = binary.Write(&l4, binary.BigEndian, uint32(1)) // seq
		_ = binary.Write(&l4, binary.BigEndian, uint32(1)) // ack
		l4.WriteByte(0x50)                                 // data offset = 5 (20 bytes)
		l4.WriteByte(0x18)                                 // PSH+ACK
		_ = binary.Write(&l4, binary.BigEndian, uint16(8192))
		_ = binary.Write(&l4, binary.BigEndian, uint16(0)) // checksum
		_ = binary.Write(&l4, binary.BigEndian, uint16(0)) // urgent
		l4.Write(payload)
	} else {
		// 8-byte UDP header
		_ = binary.Write(&l4, binary.BigEndian, srcPort)
		_ = binary.Write(&l4, binary.BigEndian, dstPort)
		_ = binary.Write(&l4, binary.BigEndian, uint16(8+len(payload)))
		_ = binary.Write(&l4, binary.BigEndian, uint16(0))
		l4.Write(payload)
	}

	// IPv4 header (20 bytes)
	totalLen := uint16(20 + l4.Len())
	buf.WriteByte(0x45) // v4, IHL=5
	buf.WriteByte(0x00)
	_ = binary.Write(&buf, binary.BigEndian, totalLen)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	buf.WriteByte(64)    // TTL
	buf.WriteByte(proto) // 6=TCP, 17=UDP
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	buf.Write(net.ParseIP(srcIP).To4())
	buf.Write(net.ParseIP(dstIP).To4())
	buf.Write(l4.Bytes())

	return buf.Bytes()
}

func writeTestPCAP(t *testing.T, frames [][]byte) string {
	t.Helper()
	var f bytes.Buffer
	// PCAP global header (little-endian)
	_ = binary.Write(&f, binary.LittleEndian, uint32(magicNative))
	_ = binary.Write(&f, binary.LittleEndian, uint16(2))
	_ = binary.Write(&f, binary.LittleEndian, uint16(4))
	_ = binary.Write(&f, binary.LittleEndian, int32(0))
	_ = binary.Write(&f, binary.LittleEndian, uint32(0))
	_ = binary.Write(&f, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&f, binary.LittleEndian, uint32(1)) // DLT_EN10MB

	for idx, frame := range frames {
		_ = binary.Write(&f, binary.LittleEndian, uint32(1700000000+idx))
		_ = binary.Write(&f, binary.LittleEndian, uint32(0))
		_ = binary.Write(&f, binary.LittleEndian, uint32(len(frame)))
		_ = binary.Write(&f, binary.LittleEndian, uint32(len(frame)))
		f.Write(frame)
	}

	path := filepath.Join(t.TempDir(), "test.pcap")
	if err := os.WriteFile(path, f.Bytes(), 0644); err != nil {
		t.Fatalf("write pcap: %v", err)
	}
	return path
}

func buildBACnetReadPropAckPacket(instance uint32, propID byte, strVal string) []byte {
	objID := (uint32(8) << 22) | (instance & 0x3FFFFF)
	var apdu bytes.Buffer
	apdu.Write([]byte{0x30, 0x01, 0x0C}) // Complex-Ack, invoke=1, ReadProperty
	apdu.WriteByte(0x0C)                 // [0] Object Identifier (4 bytes)
	_ = binary.Write(&apdu, binary.BigEndian, objID)
	apdu.Write([]byte{0x19, propID}) // [1] Property Identifier
	apdu.WriteByte(0x3E)             // [3] Opening tag
	// CharacterString application tag 7, UTF-8 encoding byte 0x00 + string
	strPayload := append([]byte{0x00}, []byte(strVal)...)
	if len(strPayload) < 5 {
		apdu.WriteByte(byte((7 << 4) | len(strPayload)))
	} else {
		apdu.Write([]byte{(7 << 4) | 5, byte(len(strPayload))})
	}
	apdu.Write(strPayload)
	apdu.WriteByte(0x3F) // [3] Closing tag

	npdu := append([]byte{0x01, 0x00}, apdu.Bytes()...)
	bvlc := make([]byte, 4+len(npdu))
	bvlc[0] = 0x81
	bvlc[1] = 0x0A
	binary.BigEndian.PutUint16(bvlc[2:4], uint16(len(bvlc)))
	copy(bvlc[4:], npdu)
	return bvlc
}

func buildRoutedBACnetReadPropAckPacket(instance uint32, propID byte, value string, network uint16, address []byte) []byte {
	frame := buildBACnetReadPropAckPacket(instance, propID, value)
	npdu := []byte{1, 8, byte(network >> 8), byte(network), byte(len(address))}
	npdu = append(npdu, address...)
	npdu = append(npdu, frame[6:]...)
	out := append([]byte{0x81, 0x0a, 0, 0}, npdu...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

func buildOPCUAGetEndpointsRespPayload(appURI, productURI, appName string) []byte {
	var body bytes.Buffer
	// NodeId FourByte: ns=0, id=431 (GetEndpointsResponse)
	body.Write([]byte{0x01, 0x00})
	_ = binary.Write(&body, binary.LittleEndian, uint16(431))
	// ResponseHeader: Timestamp(8)+Handle(4)+Result(4)+DiagMask(1)+StringTableCount(4)+AddHdr(3)
	body.Write(make([]byte, 16))
	body.WriteByte(0x00)
	_ = binary.Write(&body, binary.LittleEndian, int32(0))
	body.Write([]byte{0x00, 0x00, 0x00})
	// Endpoints count = 1
	_ = binary.Write(&body, binary.LittleEndian, int32(1))
	writeUAStr := func(s string) {
		_ = binary.Write(&body, binary.LittleEndian, int32(len(s)))
		body.WriteString(s)
	}
	writeUAStr("opc.tcp://10.50.1.40:4840")
	writeUAStr(appURI)
	writeUAStr(productURI)
	// LocalizedText: mask 0x02 (text present)
	body.WriteByte(0x02)
	writeUAStr(appName)

	msgLen := uint32(24 + body.Len())
	var msg bytes.Buffer
	msg.WriteString("MSGF")
	_ = binary.Write(&msg, binary.LittleEndian, msgLen)
	_ = binary.Write(&msg, binary.LittleEndian, uint32(1)) // SecureChannelId
	_ = binary.Write(&msg, binary.LittleEndian, uint32(1)) // TokenId
	_ = binary.Write(&msg, binary.LittleEndian, uint32(2)) // Seq
	_ = binary.Write(&msg, binary.LittleEndian, uint32(2)) // ReqId
	msg.Write(body.Bytes())
	return msg.Bytes()
}

func TestPassiveAnalyze_BACnetADS_SICK_OPCUA_Fox(t *testing.T) {
	// 1. BACnet broadcast I-Am (variable NPDU 0x20: DNET=0xFFFF, DLEN=0, Hop=0xFF) + ReadProperty Complex-Ack enrichment
	obj8501 := (uint32(8) << 22) | 8501
	var iam1 bytes.Buffer
	iam1.Write([]byte{0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF}) // broadcast NPDU
	iam1.Write([]byte{0x10, 0x00, 0xC4})                   // I-Am + ObjectID tag
	_ = binary.Write(&iam1, binary.BigEndian, obj8501)
	iam1.Write([]byte{0x22, 0x05, 0xC4, 0x91, 0x00, 0x21, 190}) // MaxAPDU=1476, Seg=0, Vendor=190 (Danfoss)
	bvlcIAm1 := make([]byte, 4+iam1.Len())
	bvlcIAm1[0], bvlcIAm1[1] = 0x81, 0x0B
	binary.BigEndian.PutUint16(bvlcIAm1[2:4], uint16(len(bvlcIAm1)))
	copy(bvlcIAm1[4:], iam1.Bytes())

	// Routed MS/TP sub-device I-Am from same BACnet router IP (NPDU 0x08: SNET=20, SLEN=1, SADR=5)
	obj8502 := (uint32(8) << 22) | 8502
	var iam2 bytes.Buffer
	iam2.Write([]byte{0x01, 0x08, 0x00, 20, 0x01, 0x05})
	iam2.Write([]byte{0x10, 0x00, 0xC4})
	_ = binary.Write(&iam2, binary.BigEndian, obj8502)
	iam2.Write([]byte{0x22, 0x01, 0xE0, 0x91, 0x03, 0x21, 190})
	bvlcIAm2 := make([]byte, 4+iam2.Len())
	bvlcIAm2[0], bvlcIAm2[1] = 0x81, 0x0A
	binary.BigEndian.PutUint16(bvlcIAm2[2:4], uint16(len(bvlcIAm2)))
	copy(bvlcIAm2[4:], iam2.Bytes())

	// 2. TwinCAT ADS TCP/48898 ReadDeviceInfo response
	adsTCP := make([]byte, 62)
	binary.LittleEndian.PutUint32(adsTCP[2:6], 56)
	copy(adsTCP[14:20], []byte{10, 50, 1, 20, 1, 1})
	binary.LittleEndian.PutUint16(adsTCP[20:22], 10000)
	binary.LittleEndian.PutUint16(adsTCP[22:24], 1)      // ReadDeviceInfo
	binary.LittleEndian.PutUint16(adsTCP[24:26], 0x0005) // response
	binary.LittleEndian.PutUint32(adsTCP[26:30], 24)
	adsTCP[42], adsTCP[43] = 3, 1
	binary.LittleEndian.PutUint16(adsTCP[44:46], 4024)
	copy(adsTCP[46:62], []byte("CX5130-OSR\x00"))

	// 3. SICK SOPAS CoLa-A TCP/2111 response
	sickCoLaA := []byte("\x02sRA DeviceIdent 8 MSC800 4 2.40\x03")

	// 4. OPC UA TCP/4840 GetEndpointsResponse
	opcuaResp := buildOPCUAGetEndpointsRespPayload("urn:knapp:kisoft:wcs", "urn:knapp.com:KiSoft:WCS", "KiSoft OSR Gateway")

	// 5. Tridium Niagara Fox TCP/1911 server greeting
	foxGreeting := []byte("fox a 0 -1 fox hello\n{\nfox.version=s:1.0.1\napp.name=s:Station\napp.version=s:4.10.1.36\nstation.name=s:ColdStorage_BMS\nhostName=s:jace-hall-b\nbrandId=s:honeywell\n};\n;\n")

	frames := [][]byte{
		buildTestEthernetIPv4Frame("10.50.1.10", "10.50.1.255", 17, 47808, 47808, bvlcIAm1),
		buildTestEthernetIPv4Frame("10.50.1.10", "10.50.1.200", 17, 47808, 47808, buildBACnetReadPropAckPacket(8501, 70, "AK-SM 850A")),
		buildTestEthernetIPv4Frame("10.50.1.10", "10.50.1.200", 17, 47808, 47808, buildBACnetReadPropAckPacket(8501, 44, "4.2.1")),
		buildTestEthernetIPv4Frame("10.50.1.10", "10.50.1.200", 17, 47808, 47808, buildBACnetReadPropAckPacket(8501, 58, "Cold Room 2")),
		buildTestEthernetIPv4Frame("10.50.1.10", "10.50.1.200", 17, 47808, 47808, bvlcIAm2),
		buildTestEthernetIPv4Frame("10.50.1.10", "10.50.1.200", 17, 47808, 47808, buildRoutedBACnetReadPropAckPacket(8502, 70, "AK-CC55", 20, []byte{5})),
		buildTestEthernetIPv4Frame("10.50.1.20", "10.50.1.200", 6, 48898, 52001, adsTCP),
		buildTestEthernetIPv4Frame("10.50.1.30", "10.50.1.200", 6, 2111, 52002, sickCoLaA),
		buildTestEthernetIPv4Frame("10.50.1.40", "10.50.1.200", 6, 4840, 52003, opcuaResp),
		buildTestEthernetIPv4Frame("10.50.1.50", "10.50.1.200", 6, 1911, 52004, foxGreeting),
	}

	pcapPath := writeTestPCAP(t, frames)
	res, err := Analyze(pcapPath, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(res.Devices) != 6 {
		t.Fatalf("got %d devices (%+v), want 6 (2 BACnet instances + ADS + SICK + OPCUA + Fox)", len(res.Devices), res.Devices)
	}

	byModel := make(map[string]int)
	for i, d := range res.Devices {
		byModel[d.Model] = i
	}

	dBAC1 := res.Devices[byModel["AK-SM 850A"]]
	if dBAC1.Vendor != "Danfoss" || dBAC1.Firmware != "4.2.1" || dBAC1.Extra["location"] != "Cold Room 2" {
		t.Errorf("BACnet router device = %+v", dBAC1)
	}
	dBAC2 := res.Devices[byModel["AK-CC55"]]
	if dBAC2.Vendor != "Danfoss" || dBAC2.Extra["device_instance"] != "8502" {
		t.Errorf("BACnet routed MS/TP sub-device = %+v", dBAC2)
	}
	dADS := res.Devices[byModel["CX5130-OSR"]]
	if dADS.Vendor != "Beckhoff" || dADS.Firmware != "3.1.4024" {
		t.Errorf("ADS device = %+v", dADS)
	}
	dSICK := res.Devices[byModel["MSC800"]]
	if dSICK.Vendor != "SICK" || dSICK.Firmware != "2.40" {
		t.Errorf("SICK device = %+v", dSICK)
	}
	dOPC := res.Devices[byModel["KiSoft OSR Gateway"]]
	if dOPC.Vendor != "KNAPP" {
		t.Errorf("OPC UA device = %+v", dOPC)
	}
	dFoxIdx, ok := byModel["Niagara WEBs-N4 Supervisor"]
	if !ok {
		t.Fatalf("missing Fox device in %+v", res.Devices)
	}
	dFox := res.Devices[dFoxIdx]
	if dFox.Vendor != "Honeywell" || dFox.Firmware != "4.10.1.36" {
		t.Errorf("Fox device = %+v", dFox)
	}
}
