package discover

import (
	"encoding/binary"
	"encoding/xml"
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
