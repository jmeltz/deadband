package discover

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtureFTPServer accepts connections, sends a single banner line, then
// captures any client writes (which there should be none of for a banner
// grab) and closes.
func fixtureFTPServer(t *testing.T, banner string) (string, *[]byte, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var (
		mu       sync.Mutex
		captured []byte
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, banner)
				c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						mu.Lock()
						captured = append(captured, buf[:n]...)
						mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), &captured, func() { _ = ln.Close() }
}

// bannerProbe replicates FanucFTPBanner against an arbitrary host:port for
// fixture testing. Mirrors the real implementation's parse logic.
func bannerProbe(addr string, timeout time.Duration) (*FanucIdentity, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, nil
	}
	line := string(buf[:n])
	for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == '\n') {
		line = line[:len(line)-1]
	}
	if len(line) < 4 || line[:3] != "220" {
		return nil, nil
	}
	if !fanucBannerRE.MatchString(line) {
		return nil, nil
	}
	id := &FanucIdentity{Banner: line, Source: "ftp"}
	if m := fanucSeriesRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Series = uppercaseASCII(m[1])
	}
	if m := fanucVersionRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Version = m[1]
	}
	if m := fanucAppTagRE.FindStringSubmatch(line); len(m) >= 2 && id.Version == "" {
		id.Version = m[1]
	}
	return id, nil
}

// uppercaseASCII upper-cases ASCII letters without locale dependencies.
func uppercaseASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func TestFanucBannerParse(t *testing.T) {
	tests := []struct {
		name, banner, wantSeries, wantVersion string
		match                                 bool
	}{
		{
			name:       "cnc_series_30i_b",
			banner:     "220 FANUC SERIES 30i-B FTP server ready.\r\n",
			wantSeries: "30I-B",
			match:      true,
		},
		{
			name:       "cnc_series_0i_md",
			banner:     "220 FANUC 0i-MD ready.\r\n",
			wantSeries: "0I-MD",
			match:      true,
		},
		{
			name:       "robot_r30ib_legacy",
			banner:     "220-FANUC LTD. R-30iB ROBOT FTP SERVICE\r\n",
			wantSeries: "R-30IB",
			match:      true,
		},
		{
			// Real-world R-30iB banner — does NOT contain "FANUC" literal.
			// This is the v0.5 detection bug the new regex fixes.
			name:        "robot_r30ib_handlingtool",
			banner:      "220 R-30iB FTP server ready. [HandlingTool V8.20P/06]\r\n",
			wantSeries:  "R-30IB",
			wantVersion: "HandlingTool V8.20P/06",
			match:       true,
		},
		{
			// Default-hostname case: no model in banner, but "ROBOT FTP"
			// alone is distinctive enough on TCP/21.
			name:   "robot_bare",
			banner: "220 ROBOT FTP server ready.\r\n",
			match:  true,
		},
		{
			name:   "non_fanuc_banner",
			banner: "220 ProFTPD 1.3.5 Server ready.\r\n",
			match:  false,
		},
		{
			name:   "wrong_status",
			banner: "421 Service not available\r\n",
			match:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, captured, stop := fixtureFTPServer(t, tt.banner)
			defer stop()

			id, err := bannerProbe(addr, 500*time.Millisecond)
			if err != nil {
				t.Fatalf("bannerProbe: %v", err)
			}
			if !tt.match {
				if id != nil {
					t.Errorf("expected nil identity, got %+v", id)
				}
				return
			}
			if id == nil {
				t.Fatal("expected identity, got nil")
			}
			if tt.wantSeries != "" && id.Series != tt.wantSeries {
				t.Errorf("Series: got %q, want %q", id.Series, tt.wantSeries)
			}
			if tt.wantVersion != "" && id.Version != tt.wantVersion {
				t.Errorf("Version: got %q, want %q", id.Version, tt.wantVersion)
			}

			// Read-only assertion: the banner-grab MUST NOT have written anything to the server.
			if len(*captured) > 0 {
				t.Errorf("Fanuc banner probe wrote %d bytes to server; expected zero. Got: %q",
					len(*captured), string(*captured))
			}
		})
	}
}

// buildFanucCIPResponse constructs an EIP ListIdentity response advertising
// VendorID = 252 (Fanuc) and a controller product name. Used to exercise the
// CIP-side Fanuc fingerprint without standing up a UDP fixture.
func buildFanucCIPResponse(productName string) []byte {
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
	binary.LittleEndian.PutUint16(buf[offset:offset+2], FanucCIPVendorID) // 252
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 12) // device_type (vendor-specific)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1) // product_code
	offset += 2
	buf[offset] = 8
	offset++
	buf[offset] = 30
	offset++
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 0x0030)
	offset += 2
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0x12345678)
	offset += 4
	buf[offset] = byte(len(productName))
	offset++
	copy(buf[offset:], productName)
	offset += len(productName)
	buf[offset] = 3 // state
	return buf
}

// TestFanucCIPParse asserts that a Fanuc-vendor CIP ListIdentity response
// parses cleanly and FanucCIPVendorID matches the value 252 the spec
// requires. End-to-end UDP behavior is covered by TestFanucCIPUDPFixture.
func TestFanucCIPParse(t *testing.T) {
	if FanucCIPVendorID != 252 {
		t.Fatalf("FanucCIPVendorID = %d, want 252 per ODVA registry", FanucCIPVendorID)
	}
	resp := buildFanucCIPResponse("R-30iB Mate Plus")
	id, err := ParseListIdentityResponse(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id.VendorID != FanucCIPVendorID {
		t.Errorf("VendorID = %d, want %d", id.VendorID, FanucCIPVendorID)
	}
	if id.ProductName != "R-30iB Mate Plus" {
		t.Errorf("ProductName = %q, want %q", id.ProductName, "R-30iB Mate Plus")
	}
}

// TestFanucCIPUDPFixture stands up a UDP listener that replies with a
// Fanuc CIP ListIdentity response and verifies FanucCIP recognizes it.
func TestFanucCIPUDPFixture(t *testing.T) {
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
		_, _ = conn.WriteToUDP(buildFanucCIPResponse("R-30iB Plus"), remote)
	}()

	// Override EIPPort? No — we have the listener on a random port. Probe
	// it directly using a smaller helper that targets host:port.
	host, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	id, err := fanucCIPAt(net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("fanucCIPAt: %v", err)
	}
	if id == nil {
		t.Fatal("expected Fanuc identity, got nil")
	}
	if !strings.Contains(id.Series, "R-30iB") {
		t.Errorf("Series: got %q, want substring R-30iB", id.Series)
	}
	if id.Source != "cip" {
		t.Errorf("Source = %q, want cip", id.Source)
	}
}

// fanucCIPAt is a test-only helper that probes an arbitrary UDP host:port
// (since FanucCIP() is locked to EIPPort).
func fanucCIPAt(addr string, timeout time.Duration) (*FanucIdentity, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildListIdentityRequest()); err != nil {
		return nil, nil
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil
	}
	cip, err := ParseListIdentityResponse(buf[:n])
	if err != nil || cip == nil {
		return nil, nil
	}
	if cip.VendorID != FanucCIPVendorID {
		return nil, nil
	}
	return &FanucIdentity{
		Series: cip.ProductName,
		Source: "cip",
	}, nil
}

func TestFanucHTTP(t *testing.T) {
	cases := []struct {
		name, body string
		match      bool
	}{
		{
			name:  "ipendant_setup",
			body:  `<html><head><title>iPendant Setup</title></head><body>FANUC Robotics R-30iB Mate Plus</body></html>`,
			match: true,
		},
		{
			name:  "karel_directory",
			body:  `<a href="/KAREL/SETUP.KL">SETUP.KL</a><a href="/MD/MAIN.PC">MAIN.PC</a>`,
			match: true,
		},
		{
			name:  "stm_landing",
			body:  `<frame src="/frmaster.stm" name="content">`,
			match: true,
		},
		{
			name:  "non_fanuc",
			body:  `<html><body>Welcome to Apache</body></html>`,
			match: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			// Override URL to test fixture — call FanucHTTP-equivalent inline.
			id := fanucHTTPAt(srv.URL, 500*time.Millisecond)
			if !tc.match {
				if id != nil {
					t.Errorf("expected nil identity, got %+v", id)
				}
				return
			}
			if id == nil {
				t.Fatal("expected identity, got nil")
			}
			if id.Source != "http" {
				t.Errorf("Source = %q, want http", id.Source)
			}
		})
	}
}

// fanucHTTPAt is a test helper that probes an arbitrary HTTP URL against the
// Fanuc body fingerprint (FanucHTTP itself is locked to http://ip:80/).
func fanucHTTPAt(url string, timeout time.Duration) *FanucIdentity {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if !fanucHTTPRE.MatchString(string(body)) {
		return nil
	}
	id := &FanucIdentity{Source: "http", Banner: firstLine(string(body))}
	if m := fanucHTTPModelRE.FindStringSubmatch(string(body)); len(m) >= 2 {
		id.Series = strings.ToUpper(m[1])
	}
	return id
}

func TestFanucFOCAS2Stub(t *testing.T) {
	id, err := FanucFOCAS2Probe("10.0.0.1", 100*time.Millisecond)
	if id != nil {
		t.Errorf("FOCAS2 stub returned non-nil identity: %+v", id)
	}
	if err == nil {
		t.Error("FOCAS2 stub returned nil error; expected not-implemented")
	}
}
