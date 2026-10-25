package discover

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestADSIdentifyReadOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req := make([]byte, 38)
		if _, err := conn.Read(req); err != nil {
			return
		}
		// Build 62-byte ADS ReadDeviceInfo response
		resp := make([]byte, 62)
		binary.LittleEndian.PutUint32(resp[2:6], 56) // AMS length
		copy(resp[6:12], req[14:20])                 // dst NetID
		copy(resp[12:14], req[20:22])                // dst port
		copy(resp[14:20], req[6:12])                 // src NetID
		copy(resp[20:22], req[12:14])                // src port
		binary.LittleEndian.PutUint16(resp[22:24], adsCmdReadDeviceInfo)
		binary.LittleEndian.PutUint16(resp[24:26], 0x0005) // response flag
		binary.LittleEndian.PutUint32(resp[26:30], 24)     // cbData
		binary.LittleEndian.PutUint32(resp[30:34], 0)      // amsErr
		copy(resp[34:38], req[34:38])                      // invokeID
		binary.LittleEndian.PutUint32(resp[38:42], 0)      // adsResult = 0
		resp[42] = 3                                       // Major
		resp[43] = 1                                       // Minor
		binary.LittleEndian.PutUint16(resp[44:46], 4024)   // Build
		copy(resp[46:62], []byte("CX5130-OSR\x00"))
		_, _ = conn.Write(resp)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	id, err := ADSIdentify(host, port, 1*time.Second)
	if err != nil || id == nil {
		t.Fatalf("ADSIdentify failed: id=%+v err=%v", id, err)
	}
	dev := adsIdentityToDevice(host, port, id)
	if dev.Vendor != "Beckhoff" {
		t.Errorf("Vendor = %q, want Beckhoff", dev.Vendor)
	}
	if dev.Model != "CX5130-OSR" {
		t.Errorf("Model = %q, want CX5130-OSR", dev.Model)
	}
	if dev.Firmware != "3.1.4024" {
		t.Errorf("Firmware = %q, want 3.1.4024", dev.Firmware)
	}
}

func TestSICKIdentifyCoLaA(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("\x02sRA DeviceIdent 6 MSC800 6 V2.40\x03"))
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	id, err := SICKIdentify(host, port, 1*time.Second)
	if err != nil || id == nil {
		t.Fatalf("SICKIdentify failed: id=%+v err=%v", id, err)
	}
	if id.Model != "MSC800" {
		t.Errorf("Model = %q, want MSC800", id.Model)
	}
	if id.Firmware != "V2.40" {
		t.Errorf("Firmware = %q, want V2.40", id.Firmware)
	}
}

func TestAncillaryHTTPAndTLSFingerprinting(t *testing.T) {
	client := newAncillaryHTTPClient(2 * time.Second)

	cases := []struct {
		name       string
		serverHdr  string
		html       string
		tls        bool
		wantNil    bool
		wantVendor string
		wantModel  string
	}{
		{
			name:       "KNAPP KiSoft WCS HTTPS",
			html:       "<html><head><title>KNAPP AG - KiSoft WCS Portal v4.12.1</title></head></html>",
			tls:        true,
			wantVendor: "KNAPP",
			wantModel:  "KiSoft WCS",
		},
		{
			name:       "Danfoss AK-SM 800A Refrigeration Manager",
			html:       "<html><head><title>Danfoss System Manager AK-SM 850A - SW: 3.12.4</title></head></html>",
			wantVendor: "Danfoss",
			wantModel:  "AK-SM 850A",
		},
		{
			name:       "Copeland XWEB500D EVO",
			html:       "<html><head><title>Dixell XWEB500D EVO Rel. 1.8.2</title></head></html>",
			wantVendor: "Copeland",
			wantModel:  "XWEB500D EVO",
		},
		{
			name:       "Schneider APC InRow Cooling",
			serverHdr:  "Allegro-Software-RomPager/4.34",
			html:       "<html><head><title>APC Web/SNMP Management Card - InRow RC ACRC301S AOS v6.9.6</title></head></html>",
			wantVendor: "Schneider Electric",
			wantModel:  "InRow RC ACRC301S",
		},
		{
			name:       "Vaisala viewLinc EMS",
			html:       "<html><head><title>Vaisala viewLinc Enterprise Server 5.1.2</title></head></html>",
			tls:        true,
			wantVendor: "Vaisala",
			wantModel:  "viewLinc Enterprise Server",
		},
		{
			name:      "Generic IT nginx returns nil",
			serverHdr: "nginx/1.25.3",
			html:      "<html><head><title>Welcome to nginx!</title></head><body>Internal Wiki</body></html>",
			wantNil:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.serverHdr != "" {
					w.Header().Set("Server", tc.serverHdr)
				}
				_, _ = w.Write([]byte(tc.html))
			})
			var srv *httptest.Server
			if tc.tls {
				srv = httptest.NewTLSServer(handler)
			} else {
				srv = httptest.NewServer(handler)
			}
			defer srv.Close()

			dev := AncillaryProbeURL(client, srv.URL, "10.50.0.10", 443, tc.tls)
			if tc.wantNil {
				if dev != nil {
					t.Fatalf("expected nil for generic server, got %+v", dev)
				}
				return
			}
			if dev == nil {
				t.Fatalf("expected device, got nil")
			}
			if dev.Vendor != tc.wantVendor {
				t.Errorf("Vendor = %q, want %q", dev.Vendor, tc.wantVendor)
			}
			if dev.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", dev.Model, tc.wantModel)
			}
		})
	}
}

func TestExpandedBACnetAndOPCUAVendors(t *testing.T) {
	if got := BACnetVendorName(138); got != "Danfoss" {
		t.Errorf("BACnetVendorName(138) = %q, want Danfoss", got)
	}
	if got := BACnetVendorName(77); got != "CAREL" {
		t.Errorf("BACnetVendorName(77) = %q, want CAREL", got)
	}
	if got := BACnetVendorName(115); got != "Vertiv" {
		t.Errorf("BACnetVendorName(115) = %q, want Vertiv", got)
	}
	if got := opcuaVendorFromURI("urn:knapp:kisoft:wcs:server"); got != "KNAPP" {
		t.Errorf("opcuaVendorFromURI(knapp) = %q, want KNAPP", got)
	}
	if got := opcuaVendorFromURI("urn:vaisala:viewlinc:ua"); got != "Vaisala" {
		t.Errorf("opcuaVendorFromURI(vaisala) = %q, want Vaisala", got)
	}
}
