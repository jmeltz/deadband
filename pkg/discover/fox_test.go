package discover

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const sampleFoxHelloVykon = "fox a 0 1 fox hello\n{\nfox.version=s:1.0.1\nid=i:1\napp.name=s:Station\napp.version=s:4.13.1.18\nos.name=s:QNX\nos.version=s:7.1.0\nstation.name=s:ColdStorage_BMS_01\nhostId=s:Qnx-NPM8-0000-1122-3344\nbrandId=s:vykon\nhostName=s:jace8000-mdf01\n};\n;\n"

func TestParseFoxHelloAndBrandMapping(t *testing.T) {
	id, err := ParseFoxHello(sampleFoxHelloVykon)
	if err != nil {
		t.Fatalf("ParseFoxHello: %v", err)
	}
	dev := FoxIdentityToDevice("10.20.0.15", FoxPort, false, id)
	if dev.Vendor != "Tridium" {
		t.Errorf("Vendor = %q, want Tridium", dev.Vendor)
	}
	if dev.Model != "Niagara JACE-8000" {
		t.Errorf("Model = %q, want Niagara JACE-8000", dev.Model)
	}
	if dev.Firmware != "4.13.1.18" {
		t.Errorf("Firmware = %q, want 4.13.1.18", dev.Firmware)
	}
	if dev.Hostname != "jace8000-mdf01" {
		t.Errorf("Hostname = %q, want jace8000-mdf01", dev.Hostname)
	}
	if dev.Extra["station_name"] != "ColdStorage_BMS_01" {
		t.Errorf("Extra station_name = %q", dev.Extra["station_name"])
	}

	// Honeywell WEBs-N4 OEM JACE
	hwID := *id
	hwID.BrandID = "honeywell"
	hwDev := FoxIdentityToDevice("10.20.0.16", FoxSPort, true, &hwID)
	if hwDev.Vendor != "Honeywell" || hwDev.Model != "Niagara WEBs-N4 JACE-8000" || hwDev.Extra["tls"] != "true" {
		t.Errorf("Honeywell Fox device = %+v", hwDev)
	}

	// Non-Fox HTTP response must be rejected
	if _, err := ParseFoxHello("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"); err == nil {
		t.Error("expected error for non-Fox payload")
	}
}

func TestFoxIdentifyPlaintextAndTLS(t *testing.T) {
	// 1. Plaintext Fox TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	sawReadOnlyHello := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		sawReadOnlyHello <- string(buf[:n])
		_, _ = c.Write([]byte(sampleFoxHelloVykon))
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	id, err := FoxIdentify(host, port, false, time.Second)
	if err != nil || id == nil {
		t.Fatalf("FoxIdentify(plaintext) = (%+v, %v)", id, err)
	}
	if id.AppVersion != "4.13.1.18" {
		t.Errorf("AppVersion = %q, want 4.13.1.18", id.AppVersion)
	}
	gotWire := <-sawReadOnlyHello
	if !strings.HasPrefix(gotWire, "fox a 1 -1 fox hello") {
		t.Errorf("unexpected Fox request wire payload: %q", gotWire)
	}

	// 2. TLS FoxS listener (Distech EC-Net 4 Supervisor on Windows)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecnet-sup01"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer tlsLn.Close()

	go func() {
		c, err := tlsLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		resp := "fox a 0 1 fox hello\n{\nfox.version=s:1.0.1\napp.name=s:Station\napp.version=s:4.12.2.16\nos.name=s:Windows Server 2022\nstation.name=s:ASRS_HVAC_Supervisor\nhostId=s:Win-ABCD-1234\nbrandId=s:distech\nhostName=s:ecnet-sup01\n};\n;\n"
		_, _ = c.Write([]byte(resp))
	}()

	thost, tportStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	tport, _ := strconv.Atoi(tportStr)

	tid, err := FoxIdentify(thost, tport, true, time.Second)
	if err != nil || tid == nil {
		t.Fatalf("FoxIdentify(TLS) = (%+v, %v)", tid, err)
	}
	tdev := FoxIdentityToDevice(thost, tport, true, tid)
	if tdev.Vendor != "Distech Controls" || tdev.Model != "Niagara EC-Net 4 Supervisor" || tdev.Firmware != "4.12.2.16" {
		t.Errorf("TLS FoxS device = %+v", tdev)
	}
}
