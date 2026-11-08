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
	if got := BACnetVendorName(190); got != "Danfoss" {
		t.Errorf("BACnetVendorName(190) = %q, want Danfoss", got)
	}
	if got := BACnetVendorName(77); got != "CAREL" {
		t.Errorf("BACnetVendorName(77) = %q, want CAREL", got)
	}
	if got := BACnetVendorName(113); got != "Vertiv" {
		t.Errorf("BACnetVendorName(113) = %q, want Vertiv", got)
	}
	if got := BACnetVendorName(36); got != "Tridium" {
		t.Errorf("BACnetVendorName(36) = %q, want Tridium", got)
	}
	if got := BACnetVendorName(415); got != "Beckhoff" {
		t.Errorf("BACnetVendorName(415) = %q, want Beckhoff", got)
	}
	if got := BACnetVendorName(1193); got != "Copeland" {
		t.Errorf("BACnetVendorName(1193) = %q, want Copeland", got)
	}
	if got := opcuaVendorFromURI("urn:knapp:kisoft:wcs:server"); got != "KNAPP" {
		t.Errorf("opcuaVendorFromURI(knapp) = %q, want KNAPP", got)
	}
	if got := opcuaVendorFromURI("urn:vaisala:viewlinc:ua"); got != "Vaisala" {
		t.Errorf("opcuaVendorFromURI(vaisala) = %q, want Vaisala", got)
	}
}

func TestADSProbeTCP_RejectsNonADSAndConfirmsAMSRouterError(t *testing.T) {
	// 1. Non-ADS HTTP/silent listener on TCP port must NOT confirm TwinCAT
	nonADS, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer nonADS.Close()
	go func() {
		for {
			c, err := nonADS.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	h1, p1Str, _ := net.SplitHostPort(nonADS.Addr().String())
	p1, _ := strconv.Atoi(p1Str)
	id1, confirmed1, _ := adsProbeTCP(h1, p1, 300*time.Millisecond)
	if id1 != nil || confirmed1 {
		t.Fatalf("expected non-ADS listener to be rejected, got id=%+v confirmed=%v", id1, confirmed1)
	}

	// 2. Genuine TwinCAT AMS Router returning AMS error 0x0006 (Target Port Not Found)
	amsRouter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer amsRouter.Close()
	go func() {
		for {
			c, err := amsRouter.Accept()
			if err != nil {
				return
			}
			req := make([]byte, 38)
			if _, err := c.Read(req); err == nil {
				resp := make([]byte, 38)
				binary.LittleEndian.PutUint32(resp[2:6], 32)
				copy(resp[6:12], req[14:20])
				copy(resp[12:14], req[20:22])
				copy(resp[14:20], []byte{5, 80, 201, 42, 1, 1}) // PLC AMS NetID
				copy(resp[20:22], req[12:14])
				binary.LittleEndian.PutUint16(resp[22:24], adsCmdReadDeviceInfo)
				binary.LittleEndian.PutUint16(resp[24:26], 0x0005) // response bit set
				binary.LittleEndian.PutUint32(resp[30:34], 0x0006) // Target Port not found
				copy(resp[34:38], req[34:38])                      // echo invokeID
				_, _ = c.Write(resp)
			}
			c.Close()
		}
	}()
	h2, p2Str, _ := net.SplitHostPort(amsRouter.Addr().String())
	p2, _ := strconv.Atoi(p2Str)
	id2, confirmed2, netID2 := adsProbeTCP(h2, p2, 300*time.Millisecond)
	if id2 != nil || !confirmed2 || netID2 != "5.80.201.42.1.1" {
		t.Fatalf("expected confirmed AMS router with NetID 5.80.201.42.1.1, got id=%+v confirmed=%v netID=%q", id2, confirmed2, netID2)
	}
}

func TestSICKCoLaBStripsTrailingChecksum(t *testing.T) {
	// CoLa-B payload where the trailing 1-byte XOR checksum happens to be printable ASCII '9' (0x39)
	body := []byte("sRA DeviceIdent \x00\x06MSC800\x00\x05V2.40")
	frame := []byte{0x02, 0x02, 0x02, 0x02, 0, 0, 0, byte(len(body))}
	frame = append(frame, body...)
	frame = append(frame, '9') // trailing XOR checksum byte right after "V2.40"

	id, err := parseCoLaDeviceIdentResponse(frame, 2112)
	if err != nil {
		t.Fatalf("parseCoLaDeviceIdentResponse(CoLa-B): %v", err)
	}
	if id.Model != "MSC800" {
		t.Errorf("Model = %q, want MSC800", id.Model)
	}
	if id.Firmware != "V2.40" {
		t.Errorf("Firmware = %q, want V2.40 (checksum '9' must be stripped)", id.Firmware)
	}
}

func TestADSDiscoverUDPReadOnly(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	reqLenCh := make(chan int, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		reqLenCh <- n

		// Build synthetic Beckhoff ADS UDP SERVERINFO response (service 0x80000001)
		resp := make([]byte, 24)
		copy(resp[0:4], adsUDPMagic)
		binary.LittleEndian.PutUint32(resp[8:12], adsUDPServiceServerInfoResp)
		copy(resp[12:18], []byte{5, 80, 201, 42, 1, 1})
		binary.LittleEndian.PutUint16(resp[18:20], 10000)
		binary.LittleEndian.PutUint32(resp[20:24], 3) // 3 TLV tags

		appendTag := func(tagID uint16, val []byte) {
			hdr := make([]byte, 4)
			binary.LittleEndian.PutUint16(hdr[0:2], tagID)
			binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(val)))
			resp = append(resp, hdr...)
			resp = append(resp, val...)
		}
		appendTag(adsUDPTagHostName, []byte("CX5130-SHUTTLE04\x00"))
		appendTag(adsUDPTagTwinCATVer, []byte{3, 1, 0xB8, 0x0F}) // 3.1.4024
		osBuf := make([]byte, 12)
		binary.LittleEndian.PutUint32(osBuf[0:4], 10)
		binary.LittleEndian.PutUint32(osBuf[4:8], 0)
		appendTag(adsUDPTagOSVersion, osBuf)

		_, _ = pc.WriteTo(resp, addr)
	}()

	id, meta, err := ADSDiscoverUDP("127.0.0.1", port, time.Second)
	if err != nil || id == nil {
		t.Fatalf("ADSDiscoverUDP = (%+v, %v)", id, err)
	}
	if gotLen := <-reqLenCh; gotLen != 24 {
		t.Errorf("ADS UDP request length = %d, want 24 (never 0-byte)", gotLen)
	}
	dev := adsIdentityToDevice("127.0.0.1", port, id)
	if dev.Vendor != "Beckhoff" || dev.Model != "CX5130-SHUTTLE04" || dev.Firmware != "3.1.4024" {
		t.Errorf("ADS UDP device = %+v", dev)
	}
	if meta["ams_net_id"] != "5.80.201.42.1.1" || meta["os"] != "Windows 10.0" {
		t.Errorf("ADS UDP meta = %v", meta)
	}
}

func TestSICKIdentifyCoLaBFallbackAndCoLa2(t *testing.T) {
	// 1. Sensor configured strictly for CoLa-B (closes CoLa-A connection, replies to CoLa-B)
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnB.Close()
	go func() {
		for {
			c, err := lnB.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 128)
			n, _ := c.Read(buf)
			if n >= 8 && buf[0] == 0x02 && buf[1] == 0x02 && buf[2] == 0x02 && buf[3] == 0x02 {
				body := []byte("sRA DeviceIdent \x00\x07CLV650\x00\x00\x05V5.22")
				var xor byte
				for _, b := range body {
					xor ^= b
				}
				resp := []byte{0x02, 0x02, 0x02, 0x02, 0, 0, 0, byte(len(body))}
				resp = append(resp, body...)
				resp = append(resp, xor)
				_, _ = c.Write(resp)
			}
			c.Close()
		}
	}()
	hB, pBStr, _ := net.SplitHostPort(lnB.Addr().String())
	pB, _ := strconv.Atoi(pBStr)
	idB, err := SICKIdentify(hB, pB, time.Second)
	if err != nil || idB == nil {
		t.Fatalf("SICKIdentify(CoLa-B fallback) = (%+v, %v)", idB, err)
	}
	if idB.Model != "CLV650" || idB.Firmware != "V5.22" {
		t.Errorf("CoLa-B identity = %+v, want CLV650 / V5.22", idB)
	}

	// 2. CoLa-2 responder (Lector654 on CoLa-2 binary protocol)
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 128)
			n, _ := c.Read(buf)
			// Only respond to CoLa-2 "RN" command (body[8:10] == "RN")
			if n >= 18 && buf[0] == 0x02 && buf[1] == 0x02 && buf[16] == 'R' && buf[17] == 'N' {
				name := "Lector654"
				ver := "2.3.1"
				payload := make([]byte, 0, 10+2+len(name)+2+len(ver))
				payload = append(payload, 0x00, 0x00)             // HubCntr, NoC
				payload = append(payload, 0x01, 0x00, 0x00, 0x00) // SessionID
				payload = append(payload, 0x01, 0x00)             // ReqID
				payload = append(payload, 'R', 'A')               // Cmd = RA
				payload = append(payload, byte(len(name)), 0x00)
				payload = append(payload, []byte(name)...)
				payload = append(payload, byte(len(ver)), 0x00)
				payload = append(payload, []byte(ver)...)

				frame := []byte{0x02, 0x02, 0x02, 0x02, 0, 0, 0, byte(len(payload))}
				frame = append(frame, payload...)
				_, _ = c.Write(frame)
			}
			c.Close()
		}
	}()
	h2, p2Str, _ := net.SplitHostPort(ln2.Addr().String())
	p2, _ := strconv.Atoi(p2Str)
	id2, err := SICKIdentify(h2, p2, time.Second)
	if err != nil || id2 == nil {
		t.Fatalf("SICKIdentify(CoLa-2 fallback) = (%+v, %v)", id2, err)
	}
	if id2.Model != "Lector654" || id2.Firmware != "2.3.1" {
		t.Errorf("CoLa-2 identity = %+v, want Lector654 / 2.3.1", id2)
	}
}

func TestAncillaryOIDCRedirectAndExpandedSignatures(t *testing.T) {
	// 1. KNAPP KiSoft OIDC redirect chain (302 -> /ui -> /sso -> Location: /auth/realms/kisoft)
	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})
	mux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/sso", http.StatusFound)
	})
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://sso.internal/auth/realms/kisoft/protocol/openid-connect/auth")
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()

	client := newAncillaryHTTPClient(2 * time.Second)
	dev := AncillaryProbeURL(client, srv.URL, "10.20.1.50", 80, false)
	if dev == nil {
		t.Fatal("expected KNAPP device from OIDC Location redirect header, got nil")
	}
	if dev.Vendor != "KNAPP" {
		t.Errorf("OIDC redirect Vendor = %q, want KNAPP", dev.Vendor)
	}

	// 2. Expanded WCS, Conveyor, Refrigeration, and BMS corpus signatures
	cases := []struct {
		name       string
		corpus     string
		wantVendor string
		wantModel  string
		wantFW     string
	}{
		{
			name:       "JCI Metasys SNE",
			corpus:     "<title>Metasys UI</title><div>SNE22000-0 Release: 12.0.2</div>",
			wantVendor: "Johnson Controls",
			wantModel:  "Metasys UI",
			wantFW:     "12.0.2",
		},
		{
			name:       "JCI Frick Quantum HD ammonia compressor",
			corpus:     "<title>Frick Quantum HD</title><span>Version: 10.22</span>",
			wantVendor: "Johnson Controls",
			wantModel:  "Frick Quantum HD",
			wantFW:     "10.22",
		},
		{
			name:       "Trane Tracer SC+",
			corpus:     "<title>Tracer SC+</title><meta content=\"Firmware: 5.5.0\">",
			wantVendor: "Trane",
			wantModel:  "Tracer SC+",
			wantFW:     "5.5.0",
		},
		{
			name:       "Carrier ALC WebCTRL",
			corpus:     "Server: WebCTRL/8.5\n<title>Automated Logic WebCTRL</title>",
			wantVendor: "Carrier",
			wantModel:  "WebCTRL",
			wantFW:     "8.5",
		},
		{
			name:       "Siemens Desigo CC",
			corpus:     "<title>Desigo CC Web Client</title><div>Version: 5.1.2</div>",
			wantVendor: "Siemens",
			wantModel:  "Desigo CC",
			wantFW:     "5.1.2",
		},
		{
			name:       "Tridium Niagara session cookie",
			corpus:     "Set-Cookie: niagara_session=abc123; Path=/\nLocation: /prelogin",
			wantVendor: "Tridium",
			wantModel:  "Niagara Framework",
		},
		{
			name:       "Interroll MultiControl conveyor",
			corpus:     "<title>Interroll MultiControl BI</title><span>FW: 4.9.1</span>",
			wantVendor: "Interroll",
			wantModel:  "MultiControl BI",
			wantFW:     "4.9.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := MatchAncillaryCorpus("10.20.2.10", 443, true, tc.corpus, "")
			if d == nil {
				t.Fatalf("MatchAncillaryCorpus(%s) = nil", tc.name)
			}
			if d.Vendor != tc.wantVendor {
				t.Errorf("Vendor = %q, want %q", d.Vendor, tc.wantVendor)
			}
			if d.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", d.Model, tc.wantModel)
			}
			if tc.wantFW != "" && d.Firmware != tc.wantFW {
				t.Errorf("Firmware = %q, want %q", d.Firmware, tc.wantFW)
			}
		})
	}

	// 3. SNMP sysDescr enrichment for APC Network Management Card when HTTP login hides firmware
	apc := MatchAncillaryCorpus("10.20.3.15", 443, true, "Server: Allegro-Software-RomPager/4.34\nWWW-Authenticate: Basic realm=\"APC Management Card\"", "")
	if apc == nil {
		t.Fatal("expected Schneider Electric APC match")
	}
	enrichDeviceFromSysDescr(apc, "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin AF1:v6.9.6 AN1:apc_hw05_sumx_696.bin MN:AP9631 HR:05)")
	if apc.Model != "AP9631" || apc.Firmware != "6.9.6" {
		t.Errorf("enriched APC = (%q, %q), want (AP9631, 6.9.6)", apc.Model, apc.Firmware)
	}
}
