package discover

import (
	"bytes"
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
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
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
			name:       "robot_r30ib_plus",
			banner:     "220 R-30iB Plus FTP server ready. [HandlingTool V9.10P/23]\r\n",
			wantSeries: "R-30IB PLUS",
			wantVersion: "HandlingTool V9.10P/23",
			match:      true,
		},
		{
			name:        "robot_vxworks_multiline_220",
			banner:      "220-VxWorks (VxWorks5.5.1) FTP server ready\r\n220 FANUC R-30iB Mate Plus [ArcTool V8.30P/31] ready.\r\n",
			wantSeries:  "R-30IB MATE PLUS",
			wantVersion: "ArcTool V8.30P/31",
			match:       true,
		},
		{
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

			id, err := fanucFTPAt(addr, 500*time.Millisecond)
			if err != nil {
				t.Fatalf("fanucFTPAt: %v", err)
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
			if len(*captured) > 0 {
				t.Errorf("Fanuc FTP banner probe wrote %d bytes; expected 0", len(*captured))
			}
		})
	}
}

func buildFanucCIPResponseWithVID(vid uint16, productName string) []byte {
	itemDataLen := 2 + cipSocketAddrSize + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 1 + len(productName) + 1
	buf := make([]byte, eipHeaderSize+2+4+itemDataLen)

	binary.LittleEndian.PutUint16(buf[0:2], eipCommandListIdentity)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(buf)-eipHeaderSize))

	offset := eipHeaderSize
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], cipItemTypeIdentity)
	binary.LittleEndian.PutUint16(buf[offset+2:offset+4], uint16(itemDataLen))
	offset += 4
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1)
	offset += 2
	offset += cipSocketAddrSize
	binary.LittleEndian.PutUint16(buf[offset:offset+2], vid)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 12)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1)
	offset += 2
	buf[offset] = 9
	offset++
	buf[offset] = 10
	offset++
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 0x0030)
	offset += 2
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0x12345678)
	offset += 4
	buf[offset] = byte(len(productName))
	offset++
	copy(buf[offset:], productName)
	offset += len(productName)
	buf[offset] = 3
	return buf
}

func TestFanucCIPBothODVAVendorIDs(t *testing.T) {
	if !IsFanucCIPVendorID(591) || !IsFanucCIPVendorID(356) {
		t.Fatal("expected both VID 591 (FANUC Ltd.) and VID 356 (Fanuc Robotics America) to match")
	}
	if IsFanucCIPVendorID(252) {
		t.Fatal("VID 252 is Omron Software Co., must not match Fanuc")
	}

	for _, tc := range []struct {
		vid  uint16
		name string
	}{
		{591, "FANUC Series 32i-B"},
		{356, "R-30iB Plus"},
	} {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		go func(c *net.UDPConn, vid uint16, prod string) {
			defer c.Close()
			buf := make([]byte, 1500)
			n, remote, err := c.ReadFromUDP(buf)
			if err != nil || n < 2 || binary.LittleEndian.Uint16(buf[:2]) != eipCommandListIdentity {
				return
			}
			_, _ = c.WriteToUDP(buildFanucCIPResponseWithVID(vid, prod), remote)
		}(conn, tc.vid, tc.name)

		host, port, _ := net.SplitHostPort(conn.LocalAddr().String())
		id, err := fanucCIPAt(net.JoinHostPort(host, port), 500*time.Millisecond)
		if err != nil || id == nil {
			t.Fatalf("VID %d: expected Fanuc identity, got %v (err=%v)", tc.vid, id, err)
		}
		if id.Series != tc.name {
			t.Errorf("VID %d: Series = %q, want %q", tc.vid, id.Series, tc.name)
		}
	}
}

func fanucCIPAt(addr string, timeout time.Duration) (*FanucIdentity, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildListIdentityRequest()); err != nil {
		return nil, nil
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil
	}
	cip, err := ParseListIdentityResponse(buf[:n])
	if err != nil || cip == nil || !IsFanucCIPVendorID(cip.VendorID) {
		return nil, nil
	}
	return &FanucIdentity{
		Series: cip.ProductName,
		Source: "cip",
	}, nil
}

// TestFanucFOCAS2Fixture stands up a mock FOCAS2 CNC TCP server verifying:
// 1. 12-byte OPN_REQU (0xA0A0A0A0 0001 0101 0002 0002)
// 2. 40-byte read-only cnc_sysinfo [1,1,0x18] request -> 18-byte ODBSYS reply
// 3. Clean 10-byte CLS_REQU (0xA0A0A0A0 0001 0201 0000) handle release before close!
func TestFanucFOCAS2Fixture(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var sawCloseReq bool
	var mu sync.Mutex

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		// 1. Read OPN_REQU
		ft, payload, err := readFOCASFrame(conn)
		if err != nil || ft != focasOpenReq || !bytes.Equal(payload, []byte{0x00, 0x02}) {
			return
		}
		// Reply OPN_RESP
		_, _ = conn.Write([]byte{0xA0, 0xA0, 0xA0, 0xA0, 0x00, 0x01, 0x01, 0x02, 0x00, 0x02, 0x00, 0x01})

		// 2. Read cnc_sysinfo VAR_REQU
		ft, payload, err = readFOCASFrame(conn)
		if err != nil || ft != focasVarReq || len(payload) < 10 {
			return
		}
		// Build 18-byte ODBSYS: addinfo=2, maxAxis=8, cncType="31", mtType=" M", series="D6F1", ver="01.0", axes="05"
		odbsys := make([]byte, 18)
		binary.BigEndian.PutUint16(odbsys[0:2], 2)
		binary.BigEndian.PutUint16(odbsys[2:4], 8)
		copy(odbsys[4:6], "31")
		copy(odbsys[6:8], " M")
		copy(odbsys[8:12], "D6F1")
		copy(odbsys[12:16], "01.0")
		copy(odbsys[16:18], "05")

		var varBody bytes.Buffer
		binary.Write(&varBody, binary.BigEndian, uint16(1))  // qu=1
		binary.Write(&varBody, binary.BigEndian, uint16(34)) // sublen = 2 + 32
		varBody.Write([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x18})
		varBody.Write(make([]byte, 6))                       // status = 0
		binary.Write(&varBody, binary.BigEndian, uint16(18)) // sizeof(ODBSYS)
		varBody.Write(odbsys)

		var resp bytes.Buffer
		binary.Write(&resp, binary.BigEndian, focasFrameMagic)
		binary.Write(&resp, binary.BigEndian, uint16(1))
		binary.Write(&resp, binary.BigEndian, focasVarResp)
		binary.Write(&resp, binary.BigEndian, uint16(varBody.Len()))
		resp.Write(varBody.Bytes())
		_, _ = conn.Write(resp.Bytes())

		// 3. Read CLS_REQU
		ft, _, err = readFOCASFrame(conn)
		if err == nil && ft == focasCloseReq {
			mu.Lock()
			sawCloseReq = true
			mu.Unlock()
			_, _ = conn.Write([]byte{0xA0, 0xA0, 0xA0, 0xA0, 0x00, 0x01, 0x02, 0x02, 0x00, 0x00})
		}
	}()

	id, err := fanucFOCAS2At(ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("fanucFOCAS2At err: %v", err)
	}
	if id == nil {
		t.Fatal("expected FOCAS2 identity, got nil")
	}
	if id.Source != "focas" {
		t.Errorf("Source = %q, want focas", id.Source)
	}
	if id.Series != "Series 31i-M" {
		t.Errorf("Series = %q, want Series 31i-M", id.Series)
	}
	if id.Version != "D6F1/01.0" {
		t.Errorf("Version = %q, want D6F1/01.0", id.Version)
	}

	mu.Lock()
	closedCleanly := sawCloseReq
	mu.Unlock()
	if !closedCleanly {
		t.Error("expected client to send CLS_REQU (0x0201) to release embedded CNC socket slot")
	}
}

func TestFanucHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><head><title>iPendant Setup</title></head><body>FANUC Robotics R-30iB Mate Plus</body></html>`)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !fanucHTTPRE.MatchString(string(body)) {
		t.Fatal("expected fanucHTTPRE match")
	}
	m := fanucHTTPModelRE.FindStringSubmatch(string(body))
	if len(m) < 2 || strings.ToUpper(m[1]) != "R-30IB MATE PLUS" {
		t.Errorf("got HTTP model %v, want R-30IB MATE PLUS", m)
	}
}
