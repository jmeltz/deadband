package discover

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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

	// UserData CPU-functions Read SZL parameters and typed ID/index payload.
	if pkt[8] != 7 || !bytes.Equal(pkt[17:25], []byte{0, 1, 0x12, 4, 0x11, 0x44, 1, 0}) || !bytes.Equal(pkt[25:], []byte{0xff, 9, 0, 4, 0, 0x1c, 0, 0}) {
		t.Fatalf("invalid SZL request %x", pkt)
	}
}

// buildTestSZLResponse uses a recorded synthetic responder reply, independently of the
// production builder. The component layout is checked against Siemens docs.
func buildTestSZLResponse() []byte {
	b, err := os.ReadFile("testdata/saq-s7-001c.hex")
	if err != nil {
		panic(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		panic(err)
	}
	return data
}

func TestParseSZLResponse(t *testing.T) {
	data := buildTestSZLResponse()

	id, err := ParseSZLResponse(data)
	if err != nil {
		t.Fatalf("ParseSZLResponse() error: %v", err)
	}

	if id.OrderNumber != "" {
		t.Errorf("component list must not fabricate order code: %q", id.OrderNumber)
	}
	if id.ModuleName != "CPU 1511-1 PN" {
		t.Errorf("module type = %q", id.ModuleName)
	}
	if id.SerialNumber != "S C-SAQ0000001" {
		t.Errorf("serial = %q", id.SerialNumber)
	}
	if id.FirmwareVersion != "" {
		t.Errorf("module type must not be firmware: %q", id.FirmwareVersion)
	}

}

func TestParseModuleSZLRecordedReply(t *testing.T) {
	b, err := os.ReadFile("testdata/saq-s7-0011.hex")
	if err != nil {
		t.Fatal(err)
	}
	frame, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseSZLResponse(frame)
	if err != nil {
		t.Fatal(err)
	}
	if id.OrderNumber != "6ES7 511-1AK02-0AB0" || id.FirmwareVersion != "2.9.4" || id.SerialNumber != "" {
		t.Fatalf("module identity %+v", id)
	}
	for _, mutation := range []func([]byte){
		func(b []byte) { b[8] = s7MsgAckData }, // unsupported old synthetic framing
		func(b []byte) { b[26] = 1 },           // more SZL data units follow
		func(b []byte) { b[37] = 0xff },        // record length exceeds complete payload
	} {
		bad := append([]byte(nil), frame...)
		mutation(bad)
		if _, err := ParseSZLResponse(bad); err == nil {
			t.Fatal("accepted malformed/fragmented response")
		}
	}
}

func TestTPKTRejectsUnderflow(t *testing.T) {
	if _, err := ParseTPKT([]byte{3, 0, 0, 1}); err == nil {
		t.Fatal("accepted negative payload length")
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

func buildTestSNMPResponse(sysDescr string) []byte {
	oidTLV := append([]byte{0x06, byte(len(snmpSysDescrOID))}, snmpSysDescrOID...)
	strTLV := wrapBERTLV(0x04, []byte(sysDescr))
	vb := wrapBERTLV(0x30, append(oidTLV, strTLV...))
	vbl := wrapBERTLV(0x30, vb)

	pdu := append([]byte{0x02, 0x04, 0x44, 0x42, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}, vbl...)
	respPDU := wrapBERTLV(0xA2, pdu)
	msg := append([]byte{0x02, 0x01, 0x01}, wrapBERTLV(0x04, []byte("public"))...)
	msg = append(msg, respPDU...)
	return wrapBERTLV(0x30, msg)
}

func TestSNMPGetSysDescrAndParseSiemensS71500(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 512)
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := buildTestSNMPResponse("Siemens, SIMATIC S7, CPU-1500, 6ES7 516-3FN02-0AB0, HW: 3, FW: V.2.9.4, S C-M4U82914")
		_, _ = pc.WriteTo(resp, addr)
	}()

	gotDescr := SNMPGetSysDescr("127.0.0.1", port, time.Second)
	id := ParseSiemensSysDescr(gotDescr)
	if id == nil {
		t.Fatalf("ParseSiemensSysDescr(%q) = nil", gotDescr)
	}
	dev := S7IdentityToDevice("10.10.2.15", id)
	if dev.Vendor != "Siemens" || dev.Model != "SIMATIC S7-1500" || dev.OrderNum != "6ES7 516-3FN02-0AB0" || dev.Firmware != "2.9.4" {
		t.Errorf("S7-1500 SNMP fallback device = %+v", dev)
	}
}

func TestS7ProbeWebPortalURL_TIAPortal(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><title>SIMATIC S7 Web Server</title><body>CPU 1512SP F-1 PN | Order number: 6ES7 512-1SK01-0AB0 | Firmware version: V2.9.2</body></html>`))
	}))
	defer srv.Close()

	client := newAncillaryHTTPClient(time.Second)
	id := s7ProbeWebPortalURL(client, srv.URL+"/Portal/Portal.mwsl?PriNav=Ident")
	if id == nil {
		t.Fatal("expected S7Identity from TIA Portal web server, got nil")
	}
	dev := S7IdentityToDevice("10.10.2.16", id)
	if dev.OrderNum != "6ES7 512-1SK01-0AB0" || dev.Firmware != "2.9.2" {
		t.Errorf("S7 Portal fallback device = %+v", dev)
	}
}

func TestS7ProbeTCP_Slot1AndCOTPFallback(t *testing.T) {
	// Simulates a TIA Portal S7-1500F with PUT/GET disabled:
	// Rejects Rack 0 Slot 2 with COTP DR, accepts Rack 0 Slot 1 with COTP CC, then closes on 0x32 Setup.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			n, err := c.Read(buf)
			if err == nil && n >= 18 {
				// Check dst TSAP low byte: 0x02 -> DR, 0x01 -> CC
				if bytes.Index(buf[:n], []byte{0xC2, 0x02, 0x01, 0x01}) >= 0 {
					_, _ = c.Write(buildTPKT([]byte{0x05, cotpCC, 0x00, 0x01, 0x00, 0x02}))
					// Read 0x32 setup and drop (PUT/GET disabled)
					_, _ = c.Read(buf)
				} else {
					_, _ = c.Write(buildTPKT([]byte{0x05, cotpDR, 0x00, 0x01, 0x00, 0x02}))
				}
			}
			c.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	id, cotpConfirmed := s7ProbeTCP(host, port, 500*time.Millisecond)
	if id != nil || !cotpConfirmed {
		t.Fatalf("s7ProbeTCP = (id=%+v, cotpConfirmed=%v), want (nil, true)", id, cotpConfirmed)
	}
}
