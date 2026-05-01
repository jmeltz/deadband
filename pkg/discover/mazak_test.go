package discover

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// buildMazakCIPResponse constructs an EIP ListIdentity response advertising
// VendorID = 246 (Yamazaki Mazak) and a controller product name.
func buildMazakCIPResponse(productName string) []byte {
	itemDataLen := 2 + cipSocketAddrSize + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 1 + len(productName) + 1
	buf := make([]byte, eipHeaderSize+2+4+itemDataLen)

	binary.LittleEndian.PutUint16(buf[0:2], eipCommandListIdentity)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(buf)-eipHeaderSize))

	offset := eipHeaderSize
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1) // item_count
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], cipItemTypeIdentity)
	binary.LittleEndian.PutUint16(buf[offset+2:offset+4], uint16(itemDataLen))
	offset += 4
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1) // encap version
	offset += 2
	offset += cipSocketAddrSize
	binary.LittleEndian.PutUint16(buf[offset:offset+2], MazakCIPVendorID)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 12)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1)
	offset += 2
	buf[offset] = 1
	offset++
	buf[offset] = 5
	offset++
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 0x0030)
	offset += 2
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0xCAFEBABE)
	offset += 4
	buf[offset] = byte(len(productName))
	offset++
	copy(buf[offset:], productName)
	offset += len(productName)
	buf[offset] = 3
	return buf
}

func TestMazakCIPVendorID(t *testing.T) {
	if MazakCIPVendorID != 246 {
		t.Fatalf("MazakCIPVendorID = %d, want 246 per ODVA registry", MazakCIPVendorID)
	}
}

// TestMazakCIPUDPFixture stands up a UDP listener that replies with a
// Mazak CIP ListIdentity response and verifies MazakProbe identifies it.
func TestMazakCIPUDPFixture(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 1500)
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 2 || binary.LittleEndian.Uint16(buf[:2]) != eipCommandListIdentity {
			return
		}
		_, _ = conn.WriteToUDP(buildMazakCIPResponse("Integrex i-400S"), remote)
	}()

	host, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	id := mazakCIPAt(net.JoinHostPort(host, port), 500*time.Millisecond)
	if id == nil {
		t.Fatal("expected Mazak identity from fixture, got nil")
	}
	if id.Model != "Integrex i-400S" {
		t.Errorf("Model: got %q, want %q", id.Model, "Integrex i-400S")
	}
	if id.Source != "cip" {
		t.Errorf("Source = %q, want cip", id.Source)
	}
}

func mazakCIPAt(addr string, timeout time.Duration) *MazakIdentity {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildListIdentityRequest()); err != nil {
		return nil
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	cip, err := ParseListIdentityResponse(buf[:n])
	if err != nil || cip == nil {
		return nil
	}
	if cip.VendorID != MazakCIPVendorID {
		return nil
	}
	return &MazakIdentity{
		Model:  cip.ProductName,
		Source: "cip",
	}
}

// mtConnectProbeBody is a representative MTConnect /probe response for a
// Mazak Integrex. Pulled from the shape NIST and cppagent emit, with the
// `manufacturer="Mazak"` attribute present.
const mtConnectProbeBodyMazak = `<?xml version="1.0" encoding="UTF-8"?>
<MTConnectDevices xmlns="urn:mtconnect.org:MTConnectDevices:1.7">
  <Header creationTime="2026-05-01T08:00:00Z" sender="agent.local" instanceId="123" version="2.1.0" bufferSize="131072"/>
  <Devices>
    <Device id="d1" name="Integrex_i400S" uuid="MZK-IX400S-0001">
      <Description manufacturer="Mazak" model="Integrex i-400S" serialNumber="MZK-2024-0042"/>
      <DataItems>
        <DataItem category="EVENT" id="avail" type="AVAILABILITY"/>
      </DataItems>
    </Device>
  </Devices>
</MTConnectDevices>`

// mtConnectProbeBodyGeneric is a non-Mazak agent — should not match.
const mtConnectProbeBodyGeneric = `<?xml version="1.0" encoding="UTF-8"?>
<MTConnectDevices xmlns="urn:mtconnect.org:MTConnectDevices:1.7">
  <Header sender="agent.local" instanceId="999" version="2.1.0" bufferSize="131072"/>
  <Devices>
    <Device id="d1" name="GenericMill" uuid="GEN-0001">
      <Description manufacturer="ACME" model="Mill-3000" serialNumber="ACM-001"/>
    </Device>
  </Devices>
</MTConnectDevices>`

func TestMazakMTConnect(t *testing.T) {
	cases := []struct {
		name, body string
		match      bool
		wantModel  string
	}{
		{
			name:      "mazak_integrex",
			body:      mtConnectProbeBodyMazak,
			match:     true,
			wantModel: "Integrex i-400S",
		},
		{
			name:  "generic_acme",
			body:  mtConnectProbeBodyGeneric,
			match: false,
		},
		{
			name:  "non_xml_response",
			body:  "<html>404 Not Found</html>",
			match: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/probe" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			id := mazakMTConnectAt(srv.URL, 500*time.Millisecond)
			if !tc.match {
				if id != nil {
					t.Errorf("expected nil identity, got %+v", id)
				}
				return
			}
			if id == nil {
				t.Fatal("expected Mazak identity, got nil")
			}
			if tc.wantModel != "" && id.Model != tc.wantModel {
				t.Errorf("Model: got %q, want %q", id.Model, tc.wantModel)
			}
			if id.Source != "mtconnect" {
				t.Errorf("Source = %q, want mtconnect", id.Source)
			}
		})
	}
}

// buildNBSTATResponse synthesizes an NBSTAT reply with a name table
// containing the supplied 15-character names. Suffix byte and flags are
// filled with neutral defaults; the parser ignores them.
func buildNBSTATResponse(names []string) []byte {
	rdataLen := 1 + 18*len(names) + 6 // names + 6-byte trailing unit ID stub
	pkt := make([]byte, 12+38+44+rdataLen)

	// Header: response bit set, transaction ID echoed, 1 question + 1 answer
	pkt[0] = 0xAA
	pkt[1] = 0xBB
	binary.BigEndian.PutUint16(pkt[2:4], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	binary.BigEndian.PutUint16(pkt[6:8], 1)

	// Echo question section (38 bytes from offset 12)
	pkt[12] = 0x20
	pkt[13] = 'C'
	pkt[14] = 'K'
	for i := 15; i < 13+32; i++ {
		pkt[i] = 'A'
	}
	pkt[45] = 0
	binary.BigEndian.PutUint16(pkt[46:48], 0x0021)
	binary.BigEndian.PutUint16(pkt[48:50], 0x0001)

	// Answer RR (44 bytes): name (34) + type/class/TTL/RDLEN (10)
	off := 50
	pkt[off] = 0x20
	off++
	pkt[off] = 'C'
	off++
	pkt[off] = 'K'
	off++
	for i := 0; i < 30; i++ {
		pkt[off+i] = 'A'
	}
	off += 30
	pkt[off] = 0
	off++
	binary.BigEndian.PutUint16(pkt[off:off+2], 0x0021)
	off += 2
	binary.BigEndian.PutUint16(pkt[off:off+2], 0x0001)
	off += 2
	binary.BigEndian.PutUint32(pkt[off:off+4], 0)
	off += 4
	binary.BigEndian.PutUint16(pkt[off:off+2], uint16(rdataLen))
	off += 2

	// RDATA: 1-byte name count, then 18 bytes per name
	pkt[off] = byte(len(names))
	off++
	for _, n := range names {
		padded := n
		if len(padded) > 15 {
			padded = padded[:15]
		}
		copy(pkt[off:off+15], padded)
		for i := len(padded); i < 15; i++ {
			pkt[off+i] = ' '
		}
		pkt[off+15] = 0x00 // suffix (workstation)
		pkt[off+16] = 0x44 // flags (active)
		pkt[off+17] = 0x00
		off += 18
	}
	// Trailing unit ID stub (6 bytes of zero) — consumed by some parsers.
	return pkt
}

func TestParseNBSTAT(t *testing.T) {
	resp := buildNBSTATResponse([]string{"INTEGREX-I400S", "WORKGROUP"})
	names := parseNBSTATResponse(resp)
	if len(names) != 2 {
		t.Fatalf("got %d names, want 2: %v", len(names), names)
	}
	if names[0] != "INTEGREX-I400S" {
		t.Errorf("name[0] = %q, want %q", names[0], "INTEGREX-I400S")
	}
	if names[1] != "WORKGROUP" {
		t.Errorf("name[1] = %q, want %q", names[1], "WORKGROUP")
	}
}

func TestMazakNetBIOSUDPFixture(t *testing.T) {
	cases := []struct {
		name      string
		hosts     []string
		wantMatch bool
		wantModel string
	}{
		{
			name:      "integrex_match",
			hosts:     []string{"INTEGREX-I400S", "WORKGROUP"},
			wantMatch: true,
			wantModel: "INTEGREX-I400S",
		},
		{
			name:      "mazatrol_match",
			hosts:     []string{"MAZATROL-01", "MAZAK-DOMAIN"},
			wantMatch: true,
			wantModel: "MAZATROL-01",
		},
		{
			name:      "non_mazak_host",
			hosts:     []string{"DELL-PC-001", "WORKGROUP"},
			wantMatch: false,
		},
		{
			name:      "smooth_alone_not_match",
			hosts:     []string{"SMOOTH-PRINTER"}, // "smooth" alone is not in regex
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer conn.Close()

			go func() {
				buf := make([]byte, 1500)
				_, remote, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDP(buildNBSTATResponse(tc.hosts), remote)
			}()

			host, port, _ := net.SplitHostPort(conn.LocalAddr().String())
			id := mazakNetBIOSAt(net.JoinHostPort(host, port), 500*time.Millisecond)
			if !tc.wantMatch {
				if id != nil {
					t.Errorf("expected nil identity, got %+v", id)
				}
				return
			}
			if id == nil {
				t.Fatal("expected Mazak identity, got nil")
			}
			if id.Source != "netbios" {
				t.Errorf("Source = %q, want netbios", id.Source)
			}
			if tc.wantModel != "" && id.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", id.Model, tc.wantModel)
			}
		})
	}
}

// mazakNetBIOSAt is a test helper that probes an arbitrary host:port for
// NBSTAT, mirroring MazakNetBIOS's parse logic. Production helper is
// pinned to UDP/137.
func mazakNetBIOSAt(addr string, timeout time.Duration) *MazakIdentity {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildNBSTATRequest()); err != nil {
		return nil
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	for _, name := range parseNBSTATResponse(buf[:n]) {
		if mazakHostnameRE.MatchString(name) {
			return &MazakIdentity{
				Model:  name,
				Source: "netbios",
			}
		}
	}
	return nil
}

func TestMazakHTTP(t *testing.T) {
	cases := []struct {
		name, body, server string
		match              bool
		wantModelContains  string
	}{
		{
			name:              "smoothmonitor_branded",
			body:              `<html><head><title>SmoothMonitor</title></head><body>Mazak Integrex i-400S</body></html>`,
			server:            "Microsoft-IIS/8.5",
			match:             true,
			wantModelContains: "Integrex",
		},
		{
			name:   "mazatrol_in_body",
			body:   `<h1>Mazatrol Operator Portal</h1>`,
			server: "Microsoft-IIS/10.0",
			match:  true,
		},
		{
			name:   "bare_iis_welcome",
			body:   `<html><head><title>IIS Windows Server</title></head><body>Welcome</body></html>`,
			server: "Microsoft-IIS/8.5",
			match:  false,
		},
		{
			name:   "non_mazak_apache",
			body:   `<html><body>It works!</body></html>`,
			server: "Apache/2.4",
			match:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.server != "" {
					w.Header().Set("Server", tc.server)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			id := mazakHTTPAt(srv.URL, 500*time.Millisecond)
			if !tc.match {
				if id != nil {
					t.Errorf("expected nil identity, got %+v", id)
				}
				return
			}
			if id == nil {
				t.Fatal("expected Mazak identity, got nil")
			}
			if id.Source != "http" {
				t.Errorf("Source = %q, want http", id.Source)
			}
			if tc.wantModelContains != "" && !strings.Contains(id.Model, tc.wantModelContains) {
				t.Errorf("Model = %q, want substring %q", id.Model, tc.wantModelContains)
			}
		})
	}
}

func mazakHTTPAt(baseURL string, timeout time.Duration) *MazakIdentity {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	server := resp.Header.Get("Server")
	if !mazakHTTPRE.MatchString(string(body)) && !mazakHTTPRE.MatchString(server) {
		return nil
	}
	id := &MazakIdentity{
		Banner: "HTTP " + resp.Status + " server=" + server,
		Source: "http",
	}
	if m := mazakModelRE.FindString(string(body)); m != "" {
		id.Model = strings.TrimSpace(m)
	}
	return id
}

// startFirebirdListener spins up a TCP listener that responds to op_connect
// with op_accept (opcode 3) — minimum viable Firebird server for tests.
func startFirebirdListener(t *testing.T, opcode uint32) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Drain whatever the client sent (the op_connect packet)
				conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				buf := make([]byte, 256)
				_, _ = conn.Read(buf)
				// Reply with the requested opcode (4 bytes big-endian)
				resp := make([]byte, 4)
				binary.BigEndian.PutUint32(resp, opcode)
				_, _ = conn.Write(resp)
			}(c)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	_, _ = fmt.Sscanf(port, "%d", &p)
	return ln, p
}

func TestFirebirdHandshakeAccepts(t *testing.T) {
	cases := []struct {
		name      string
		opcode    uint32
		want      bool
	}{
		{"op_accept", 3, true},
		{"op_reject", 4, true},
		{"op_disconnect", 5, true},
		{"op_response", 9, true},
		{"http_garbage", 0x48545450, false}, // "HTTP" — well outside Firebird opcode range
		{"smb_negotiate", 0xFE534D42, false}, // "\xfeSMB"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, _ := startFirebirdListener(t, tc.opcode)
			defer ln.Close()

			host, portStr, _ := net.SplitHostPort(ln.Addr().String())
			var port int
			fmt.Sscanf(portStr, "%d", &port)

			got := mazakFirebirdHandshakeAt(host, port, 500*time.Millisecond)
			if got != tc.want {
				t.Errorf("opcode=0x%X: got %v, want %v", tc.opcode, got, tc.want)
			}
		})
	}
}

// mazakFirebirdHandshakeAt is a test variant of mazakFirebirdHandshake that
// targets an arbitrary port instead of the hardcoded FirebirdPort. The
// handshake protocol is otherwise identical.
func mazakFirebirdHandshakeAt(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	pkt := buildFirebirdOpConnect()
	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	opcode := binary.BigEndian.Uint32(buf)
	switch opcode {
	case 3, 4, 5, 9, 81, 87:
		return true
	}
	return opcode > 0 && opcode <= 128
}

func TestBuildFirebirdOpConnect(t *testing.T) {
	pkt := buildFirebirdOpConnect()
	// Minimum size: 4 (op_connect) + 4 (op_attach) + 4 (version) + 4 (arch)
	// + 4 (filename len) + 4 (filename "test") + 4 (proto count)
	// + 5*4 (one protocol entry) = 48 bytes
	if len(pkt) != 48 {
		t.Errorf("op_connect length = %d, want 48", len(pkt))
	}
	if binary.BigEndian.Uint32(pkt[0:4]) != 1 {
		t.Errorf("opcode = %d, want 1 (op_connect)", binary.BigEndian.Uint32(pkt[0:4]))
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != 19 {
		t.Errorf("operation = %d, want 19 (op_attach)", binary.BigEndian.Uint32(pkt[4:8]))
	}
}

// buildNTLMSSPChallenge synthesizes a minimal NTLMSSP_CHALLENGE_MESSAGE
// with a single TargetInfo AV_PAIR of type MsvAvNbComputerName containing
// the given hostname (UTF-16LE encoded).
func buildNTLMSSPChallenge(computerName string) []byte {
	// Encode hostname as UTF-16LE
	encoded := make([]byte, 0, len(computerName)*2)
	for _, r := range computerName {
		encoded = append(encoded, byte(r), byte(r>>8))
	}

	// AV_PAIR list: MsvAvNbComputerName + MsvAvEOL
	avPairs := make([]byte, 0, 8+len(encoded))
	avPairs = append(avPairs, 0x01, 0x00) // AvId = 1 (NbComputerName)
	avPairs = append(avPairs, byte(len(encoded)), byte(len(encoded)>>8))
	avPairs = append(avPairs, encoded...)
	avPairs = append(avPairs, 0x00, 0x00, 0x00, 0x00) // MsvAvEOL

	// NTLMSSP_CHALLENGE_MESSAGE: 56 bytes header + payload
	payloadOffset := 56
	pkt := make([]byte, payloadOffset+len(avPairs))
	copy(pkt[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(pkt[8:12], 2) // MessageType=2
	// TargetNameFields all zero — no target name
	binary.LittleEndian.PutUint32(pkt[20:24], 0) // NegotiateFlags
	// ServerChallenge zero, Reserved zero
	// TargetInfoFields
	binary.LittleEndian.PutUint16(pkt[40:42], uint16(len(avPairs))) // Len
	binary.LittleEndian.PutUint16(pkt[42:44], uint16(len(avPairs))) // MaxLen
	binary.LittleEndian.PutUint32(pkt[44:48], uint32(payloadOffset)) // Offset
	// Version zeros
	copy(pkt[payloadOffset:], avPairs)
	return pkt
}

func TestParseNTLMSSPChallenge(t *testing.T) {
	cases := []struct {
		name, hostname string
	}{
		{"integrex_i400s", "INTEGREX-I400S"},
		{"mazak_nexus", "MAZAK-NEXUS-450"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildNTLMSSPChallenge(tc.hostname)
			got := parseNTLMSSPChallenge(pkt)
			if got != tc.hostname {
				t.Errorf("got %q, want %q", got, tc.hostname)
			}
		})
	}
}

func TestParseNTLMSSPChallenge_Malformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"too_short", []byte("NTLMSSP\x00")},
		{"wrong_msgtype", append([]byte("NTLMSSP\x00"), make([]byte, 48)...)}, // MsgType=0
		{"truncated_targetinfo", func() []byte {
			b := make([]byte, 56)
			copy(b[0:8], []byte("NTLMSSP\x00"))
			binary.LittleEndian.PutUint32(b[8:12], 2)
			binary.LittleEndian.PutUint16(b[40:42], 100) // huge len
			binary.LittleEndian.PutUint32(b[44:48], 50)  // offset that overflows
			return b
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNTLMSSPChallenge(tc.data)
			if got != "" {
				t.Errorf("got %q, want empty (malformed input)", got)
			}
		})
	}
}

func TestSMB2NegotiateRequest(t *testing.T) {
	pkt := smb2NegotiateRequest()
	if len(pkt) != 102 {
		t.Errorf("size = %d, want 102", len(pkt))
	}
	if string(pkt[0:4]) != "\xFESMB" {
		t.Errorf("ProtocolId = % X, want FE 53 4D 42", pkt[0:4])
	}
	// Command should be NEGOTIATE (0)
	if binary.LittleEndian.Uint16(pkt[16:18]) != 0 {
		t.Errorf("Command = %d, want 0 (NEGOTIATE)", binary.LittleEndian.Uint16(pkt[16:18]))
	}
	// Dialect at offset 100
	if pkt[100] != 0x02 || pkt[101] != 0x02 {
		t.Errorf("dialect = % X, want 02 02 (SMB 2.0.2)", pkt[100:102])
	}
}

// mazakMTConnectAt is a test helper that probes an arbitrary base URL
// instead of the production helper's hard-coded ip:port form.
func mazakMTConnectAt(baseURL string, timeout time.Duration) *MazakIdentity {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(baseURL + "/probe")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if !strings.Contains(string(body), "MTConnectDevices") {
		return nil
	}
	var probe mtconnectProbe
	if err := xml.Unmarshal(body, &probe); err != nil {
		return nil
	}
	for _, d := range probe.Devices.Device {
		mfr := strings.ToLower(d.Description.Manufacturer)
		if strings.Contains(mfr, "mazak") || strings.Contains(mfr, "yamazaki") ||
			mazakModelRE.MatchString(d.Description.Model) ||
			mazakModelRE.MatchString(d.Name) {
			return &MazakIdentity{
				Model:  firstNonEmpty(d.Description.Model, d.Name),
				Source: "mtconnect",
			}
		}
	}
	return nil
}
