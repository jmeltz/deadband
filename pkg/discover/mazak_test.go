package discover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
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
		{
			// Real-world case: integrator commissioned the i-400S with just
			// the bare model designator as the Windows hostname.
			name:      "bare_model_i400s",
			hosts:     []string{"I400S", "WORKGROUP"},
			wantMatch: true,
			wantModel: "I400S",
		},
		{
			name:      "integrex_dashed_i400st",
			hosts:     []string{"I-400ST", "DOMAIN"},
			wantMatch: true,
			wantModel: "I-400ST",
		},
		{
			name:      "variaxis_j600",
			hosts:     []string{"J600", "WORKGROUP"},
			wantMatch: true,
			wantModel: "J600",
		},
		{
			name:      "machining_center_vcn_410",
			hosts:     []string{"VCN-410", "WORKGROUP"},
			wantMatch: true,
			wantModel: "VCN-410",
		},
		{
			name:      "quickturn_qtn_250",
			hosts:     []string{"QTN-250", "WORKGROUP"},
			wantMatch: true,
			wantModel: "QTN-250",
		},
		{
			// i7 CPU + 4 digits — word boundary should reject this. The
			// regex needs `i` + optional dash + 2-4 digits + word boundary,
			// but "I7000" goes i, 7, 0, 0, 0 with no boundary between
			// digits — so the [a-z]{0,4} block is empty and the trailing
			// \b can't anchor between digits. No match.
			name:      "intel_i7000_no_match",
			hosts:     []string{"I7000-SERVER", "WORKGROUP"},
			wantMatch: false,
		},
		{
			// Intel i7-7700 desktop — same word-boundary protection.
			name:      "intel_i7_7700_no_match",
			hosts:     []string{"I7-7700-PC", "WORKGROUP"},
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

// TestMazakHostnameRegex_FQDNs validates that the hostname regex matches
// PTR-record-style FQDNs (the input shape MazakReverseDNS sees from
// net.LookupAddr). Real-world examples drawn from the user's deployment.
func TestMazakHostnameRegex_FQDNs(t *testing.T) {
	cases := []struct {
		fqdn  string
		match bool
	}{
		// Positive: real PTR records seen in the field.
		{"I300S.crowncork.com", true},
		{"I400S.crowncork.com", true},
		{"INTEGREX-I400S.shopfloor.local", true},
		{"MAZAK-NEXUS.acme.corp", true},
		{"VCN-410.factory.internal", true},
		{"qtn-250.shop.lan", true}, // case-insensitive
		// Negative: ordinary corporate Windows hosts shouldn't match.
		{"DC01.corp.acme.com", false},
		{"WIN-J7K2L9.workgroup.local", false},
		{"FILESERVER.shop.lan", false},
		{"i7-7700-laptop.it.corp", false}, // Intel CPU pattern
		{"i7000-srv.dc.local", false},     // 4-digit, not Mazak
	}
	for _, tc := range cases {
		t.Run(tc.fqdn, func(t *testing.T) {
			got := mazakHostnameRE.MatchString(tc.fqdn)
			if got != tc.match {
				t.Errorf("match(%q) = %v, want %v", tc.fqdn, got, tc.match)
			}
		})
	}
}

// generateSelfSignedCert mints a self-signed ECDSA cert with the given
// CommonName — mirrors what Windows RDP does at install time.
func generateSelfSignedCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

// startFakeRDPServer accepts a single connection, performs the X.224
// negotiation (responding with NEG_RSP advertising SSL selected), then
// upgrades to TLS using a self-signed cert with the supplied CN.
func startFakeRDPServer(t *testing.T, cn string) (string, func()) {
	t.Helper()
	cert := generateSelfSignedCert(t, cn)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read the X.224 Connection Request — drain it.
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		// Send X.224 Connection Confirm + RDP_NEG_RSP indicating SSL selected.
		// TPKT(4) + COTP CC(7) + NEG_RSP(8) = 19 bytes.
		resp := []byte{
			// TPKT
			0x03, 0x00, 0x00, 0x13,
			// COTP CC: length=14, type=0xD0, dst-ref=0, src-ref=0x1234, class=0
			0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00,
			// RDP_NEG_RSP: type=0x02, flags=0x00, length=0x0008 LE,
			// selectedProto=0x00000001 LE (SSL)
			0x02, 0x00, 0x08, 0x00,
			0x01, 0x00, 0x00, 0x00,
		}
		_, _ = conn.Write(resp)

		// Upgrade to TLS.
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		tlsConn := tls.Server(conn, tlsCfg)
		_ = tlsConn.Handshake()
		_ = tlsConn.Close()
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestMazakRDPCertExtraction(t *testing.T) {
	cases := []struct {
		name, cn  string
		wantMatch bool
	}{
		{"integrex_match", "INTEGREX-I400S", true},
		{"mazak_nexus_match", "MAZAK-NEXUS-450", true},
		{"variaxis_match", "VARIAXIS-J600", true},
		{"non_mazak_no_match", "RANDOM-PC-001", false},
		{"empty_cn", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, stop := startFakeRDPServer(t, tc.cn)
			defer stop()

			host, portStr, _ := net.SplitHostPort(addr)
			var port int
			fmt.Sscanf(portStr, "%d", &port)

			id := mazakRDPAt(host, port, 2*time.Second)
			if !tc.wantMatch {
				if id != nil {
					t.Errorf("expected nil identity (CN=%q), got %+v", tc.cn, id)
				}
				return
			}
			if id == nil {
				t.Fatal("expected Mazak identity, got nil")
			}
			if id.Source != "rdp" {
				t.Errorf("Source = %q, want rdp", id.Source)
			}
			if id.Model != tc.cn {
				t.Errorf("Model = %q, want %q", id.Model, tc.cn)
			}
		})
	}
}

// mazakRDPAt mirrors MazakRDP but targets an arbitrary host:port instead
// of the hardcoded RDPPort.
func mazakRDPAt(ip string, port int, timeout time.Duration) *MazakIdentity {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(rdpConnectionRequest()); err != nil {
		conn.Close()
		return nil
	}
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 19 || resp[11] != 0x02 {
		conn.Close()
		return nil
	}
	if binary.LittleEndian.Uint32(resp[15:19])&0x00000003 == 0 {
		conn.Close()
		return nil
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: ip})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return nil
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cn := strings.TrimSpace(state.PeerCertificates[0].Subject.CommonName)
	if cn == "" || !mazakHostnameRE.MatchString(cn) {
		return nil
	}
	return &MazakIdentity{Model: cn, Source: "rdp"}
}

func TestRDPConnectionRequest(t *testing.T) {
	pkt := rdpConnectionRequest()
	// TPKT version
	if pkt[0] != 0x03 {
		t.Errorf("TPKT version = 0x%02X, want 0x03", pkt[0])
	}
	// X.224 PDU code (CR = 0xE0)
	if pkt[5] != 0xE0 {
		t.Errorf("X.224 PDU code = 0x%02X, want 0xE0 (CR)", pkt[5])
	}
	// RDP_NEG_REQ type byte should be present near the end
	if !strings.Contains(string(pkt), "Cookie: mstshash=") {
		t.Error("packet missing mstshash cookie")
	}
	// Last 8 bytes are the RDP_NEG_REQ
	negReq := pkt[len(pkt)-8:]
	if negReq[0] != 0x01 {
		t.Errorf("NEG_REQ type = 0x%02X, want 0x01", negReq[0])
	}
	requestedProto := binary.LittleEndian.Uint32(negReq[4:8])
	if requestedProto&0x00000001 == 0 {
		t.Errorf("requestedProto = 0x%X, want SSL bit set", requestedProto)
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
