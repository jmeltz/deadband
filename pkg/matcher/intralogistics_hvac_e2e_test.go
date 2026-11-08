package matcher_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

func buildE2EADSUDPFrame(host string, maj, min uint8, build uint16) []byte {
	var pkt bytes.Buffer
	pkt.Write([]byte{0x03, 0x66, 0x14, 71}) // wait: 0x71 = 113! Let's write 0x71 explicitly below
	pkt.Reset()
	pkt.Write([]byte{0x03, 0x66, 0x14, 0x71})
	_ = binary.Write(&pkt, binary.LittleEndian, uint32(0))
	_ = binary.Write(&pkt, binary.LittleEndian, uint32(0x80000001)) // SERVERINFO response
	pkt.Write([]byte{10, 10, 1, 2, 1, 1})                           // AMS NetID
	_ = binary.Write(&pkt, binary.LittleEndian, uint16(10000))
	_ = binary.Write(&pkt, binary.LittleEndian, uint32(2)) // 2 TLV tags: HostName(5) + TwinCATVer(4)

	hostZ := append([]byte(host), 0)
	_ = binary.Write(&pkt, binary.LittleEndian, uint16(5))
	_ = binary.Write(&pkt, binary.LittleEndian, uint16(len(hostZ)))
	pkt.Write(hostZ)

	var tcVer [4]byte
	tcVer[0] = maj
	tcVer[1] = min
	binary.LittleEndian.PutUint16(tcVer[2:4], build)
	_ = binary.Write(&pkt, binary.LittleEndian, uint16(4))
	_ = binary.Write(&pkt, binary.LittleEndian, uint16(4))
	pkt.Write(tcVer[:])

	return pkt.Bytes()
}

func buildE2ESICKCoLaBFrame(payloadStr string) []byte {
	body := []byte(payloadStr)
	var xor byte
	for _, b := range body {
		xor ^= b
	}
	frame := make([]byte, 8+len(body)+1)
	copy(frame[0:4], []byte{0x02, 0x02, 0x02, 0x02})
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[8:], body)
	frame[len(frame)-1] = xor
	return frame
}

func TestEndToEnd_KNAPP_ASRS_And_HVAC_DiscoveryToVulnerabilityMatching(t *testing.T) {
	var discovered []inventory.Device

	// 1. KNAPP KiSoft WCS / OSR Gateway via Ancillary HTTPS
	knappDev := discover.MatchAncillaryCorpus(
		"10.10.1.10", 443, true,
		"Location: /auth/realms/kisoft\n<title>KNAPP KiSoft WCS</title><div>Version: 4.10.1</div>",
		"kisoft-wcs.warehouse.local",
	)
	if knappDev == nil {
		t.Fatal("failed to discover KNAPP KiSoft WCS")
	}
	discovered = append(discovered, *knappDev)

	// 2. Beckhoff CX5130 Shuttle Aisle IPC via UDP/48899 Route-Less ADS Discovery (vulnerable 3.1.4024)
	adsID, adsMeta, err := discover.ParseADSUDPDiscoveryResponse(buildE2EADSUDPFrame("CX5130-OSR01", 3, 1, 4024))
	if err != nil || adsID == nil {
		t.Fatalf("ParseADSUDPDiscoveryResponse failed: %v", err)
	}
	beckhoffVuln := discover.ADSIdentityToDevice("10.10.1.11", 48899, adsID)
	beckhoffVuln.Hostname = adsMeta["hostname"]
	discovered = append(discovered, beckhoffVuln)

	// 2b. Patched Beckhoff CX5130 (3.1.4026) — must NOT trigger BECKHOFF-2024-004 (<3.1.4025)
	adsPatchedID, _, err := discover.ParseADSUDPDiscoveryResponse(buildE2EADSUDPFrame("CX5130-OSR02", 3, 1, 4026))
	if err != nil {
		t.Fatal(err)
	}
	discovered = append(discovered, discover.ADSIdentityToDevice("10.10.1.12", 48899, adsPatchedID))

	// 3. SICK CLV650 Conveyor Tunnel Scanner via CoLa-B (with trailing XOR checksum)
	sickID, err := discover.ParseSICKCoLaFrame(buildE2ESICKCoLaBFrame("sRA DeviceIdent 6 CLV650 5 2.04.1"), 2112)
	if err != nil || sickID == nil {
		t.Fatalf("ParseSICKCoLaFrame failed: %v", err)
	}
	discovered = append(discovered, inventory.Device{
		IP: "10.10.1.13", Vendor: "SICK", Model: sickID.Model, Firmware: sickID.Firmware, Protocol: "sick-cola", Port: 2112,
	})

	// 4. B&R X20CP3586 Shuttle Controller via SDM HTTP -> matched against ABB CSAF advisory
	brDev := discover.MatchAncillaryCorpus(
		"10.10.1.14", 80, false,
		"<title>B&R Industrial Automation - System Diagnostics Manager</title><div>CPU: X20CP3586 Automation Runtime D4.91</div>",
		"",
	)
	if brDev == nil {
		t.Fatal("failed to discover B&R X20CP3586")
	}
	discovered = append(discovered, *brDev)

	// 5. Siemens SIMATIC S7-1516F (PUT/GET disabled -> SNMP sysDescr fallback)
	s7ID := discover.ParseSiemensSysDescr("Siemens, SIMATIC S7, CPU 1516F-3 PN/DP, 6ES7 516-3FN02-0AB0, HW: 2, FW: V.2.9.4, SZ001122")
	if s7ID == nil {
		t.Fatal("failed to parse Siemens S7-1516F sysDescr")
	}
	discovered = append(discovered, discover.S7IdentityToDevice("10.10.1.15", s7ID))

	// 6. Danfoss AK-SM 850A Cold-Chain Manager + Routed MS/TP AK-CC55 Case Controller via BACnet (Vendor ID 190)
	danfossMgr := discover.BACnetIdentityToDevice("10.10.2.10", &discover.BACnetIdentity{
		DeviceInstance:   8501,
		VendorID:         190,
		VendorName:       discover.BACnetVendorName(190),
		ModelName:        "AK-SM 850A",
		FirmwareRevision: "4.1.2",
		Location:         "Cold Storage Hall A",
	})
	danfossCase := discover.BACnetIdentityToDevice("10.10.2.10", &discover.BACnetIdentity{
		DeviceInstance:   8502,
		VendorID:         190,
		VendorName:       discover.BACnetVendorName(190),
		ModelName:        "AK-CC55",
		FirmwareRevision: "1.82",
		SourceNet:        20,
		SourceAddr:       []byte{0x04},
	})
	discovered = append(discovered, danfossMgr, danfossCase)

	// 7. CAREL pCOWeb Chiller Card via Modbus FC 43/14
	carelDev := discover.ModbusIdentityToDevice("10.10.2.11", &discover.ModbusIdentity{
		VendorName:  "CAREL INDUSTRIES S.p.A.",
		ModelName:   "pCOWeb",
		Revision:    "1.6.8",
	})
	discovered = append(discovered, carelDev)

	// 8. Copeland (Dixell / Emerson) XWEB500D EVO via Ancillary HTTPS -> matched against Emerson XWEB CSAF advisory
	xwebDev := discover.MatchAncillaryCorpus(
		"10.10.2.12", 443, true,
		"<title>Dixell XWEB500D EVO</title><span>Release: 1.9.0</span>",
		"",
	)
	if xwebDev == nil {
		t.Fatal("failed to discover Copeland XWEB500D EVO")
	}
	discovered = append(discovered, *xwebDev)

	// 9. Tridium Niagara JACE-8000 via Niagara Fox (TCP/1911)
	foxTridium, err := discover.ParseFoxHello("fox a 0 -1 fox hello\n{\nfox.version=s:1.0.1\napp.name=s:Station\napp.version=s:4.10.2.18\nstation.name=s:Plant_HVAC\nhostId=s:QNX-NPM8-0001\nbrandId=s:vykon\n};\n;\n")
	if err != nil {
		t.Fatalf("ParseFoxHello(Tridium) failed: %v", err)
	}
	discovered = append(discovered, discover.FoxIdentityToDevice("10.10.2.13", 1911, false, foxTridium))

	// 10. Honeywell WEBs-N4 Supervisor via Niagara Fox -> cross-matches upstream Tridium Niagara Framework advisory
	foxHoneywell, err := discover.ParseFoxHello("fox a 0 -1 fox hello\n{\nfox.version=s:1.0.1\napp.name=s:Station\napp.version=s:4.9.0.198\nstation.name=s:Freezer_BMS\nbrandId=s:honeywell\n};\n;\n")
	if err != nil {
		t.Fatalf("ParseFoxHello(Honeywell) failed: %v", err)
	}
	discovered = append(discovered, discover.FoxIdentityToDevice("10.10.2.14", 1911, false, foxHoneywell))

	// 11. Trane Tracer SC+, Carrier/ALC WebCTRL, JCI Metasys, Siemens Desigo CC via Ancillary HTTPS
	for _, spec := range []struct {
		ip     string
		corpus string
	}{
		{"10.10.2.15", "<title>Tracer SC+</title><meta content=\"Firmware: 5.4.0\">"},
		{"10.10.2.16", "Server: WebCTRL/8.0\n<title>Automated Logic WebCTRL</title>"},
		{"10.10.2.17", "<title>Metasys Server</title><div>Release: 11.0.1</div>"},
		{"10.10.2.18", "<title>Desigo CC</title><div>Version: 5.0.1</div>"},
	} {
		d := discover.MatchAncillaryCorpus(spec.ip, 443, true, spec.corpus, "")
		if d == nil {
			t.Fatalf("failed to discover %s", spec.ip)
		}
		discovered = append(discovered, *d)
	}

	// Build multi-source advisory database (CISA ICS-CERT + OASIS CSAF ROLIE + Targeted NVD 2.0)
	db := &advisory.Database{
		Source: "deadband-snapshot+csaf-rolie+nvd-2.0",
		Advisories: []advisory.Advisory{
			{
				ID:               "CVE-2024-55010",
				Vendor:           "KNAPP",
				Products:         []string{"KiSoft WCS"},
				AffectedVersions: []string{">=4.0.0|<4.12.2"},
				CVSSv3Max:        8.1,
				CVEs:             []string{"CVE-2024-55010"},
			},
			{
				ID:               "BECKHOFF-2024-004",
				Vendor:           "Beckhoff Automation",
				Products:         []string{"CX5130", "TwinCAT 3"},
				AffectedVersions: []string{"vers:all/<3.1.4025"},
				CVSSv3Max:        9.8,
				CVEs:             []string{"CVE-2024-7123"},
			},
			{
				ID:               "SICK-2024-0003",
				Vendor:           "SICK AG",
				Products:         []string{"CLV65x"},
				AffectedVersions: []string{"vers:generic/<=2.10.0"},
				CVSSv3Max:        8.6,
				CVEs:             []string{"CVE-2024-39001"},
			},
			{
				ID:               "ICSA-23-BR-01",
				Vendor:           "ABB",
				Products:         []string{"B&R X20CP3586"},
				AffectedVersions: []string{"<= D4.93"},
				CVSSv3Max:        8.8,
				CVEs:             []string{"CVE-2023-3901"},
			},
			{
				ID:               "SSA-431678",
				Vendor:           "Siemens",
				Products:         []string{"SIMATIC S7-1500 CPU family"},
				AffectedVersions: []string{"vers:all/<3.0.0"},
				CVSSv3Max:        7.5,
				CVEs:             []string{"CVE-2023-28489"},
			},
			{
				ID:               "ICSA-22-202-04",
				Vendor:           "Danfoss",
				Products:         []string{"AK-SM 800A Series", "AK-CC55"},
				AffectedVersions: []string{"<4.3.0", "<2.00"},
				CVSSv3Max:        9.8,
				CVEs:             []string{"CVE-2022-3224"},
			},
			{
				ID:               "ICSA-23-CAREL-01",
				Vendor:           "CAREL",
				Products:         []string{"pCOWeb"},
				AffectedVersions: []string{"<1.7.0"},
				CVSSv3Max:        9.1,
				CVEs:             []string{"CVE-2023-2910"},
			},
			{
				ID:               "ICSA-24-XWEB-01",
				Vendor:           "Emerson",
				Products:         []string{"XWEB 300D/500D PRO/EVO"},
				AffectedVersions: []string{"<=1.10.2"},
				CVSSv3Max:        9.8,
				CVEs:             []string{"CVE-2024-4100"},
			},
			{
				ID:               "ICSA-23-NIAGARA-01",
				Vendor:           "Tridium",
				Products:         []string{"Niagara Framework"},
				AffectedVersions: []string{">=4.4|<4.10.9"},
				CVSSv3Max:        8.8,
				CVEs:             []string{"CVE-2023-34362"},
			},
			{
				ID:               "ICSA-23-TRANE-01",
				Vendor:           "Trane",
				Products:         []string{"Tracer SC+"},
				AffectedVersions: []string{"<5.5.0"},
				CVSSv3Max:        8.0,
				CVEs:             []string{"CVE-2023-4501"},
			},
			{
				ID:               "ICSA-23-ALC-01",
				Vendor:           "Automated Logic",
				Products:         []string{"WebCTRL"},
				AffectedVersions: []string{"<8.5"},
				CVSSv3Max:        8.6,
				CVEs:             []string{"CVE-2023-4602"},
			},
			{
				ID:               "ICSA-23-JCI-01",
				Vendor:           "Johnson Controls",
				Products:         []string{"Metasys Server"},
				AffectedVersions: []string{"<12.0.0"},
				CVSSv3Max:        9.1,
				CVEs:             []string{"CVE-2023-4703"},
			},
			{
				ID:               "SSA-881204",
				Vendor:           "Siemens",
				Products:         []string{"Desigo CC"},
				AffectedVersions: []string{"vers:all/<5.1.0"},
				CVSSv3Max:        8.2,
				CVEs:             []string{"CVE-2023-4804"},
			},
		},
	}

	results := matcher.MatchAll(discovered, db, matcher.FilterOpts{MinConfidence: matcher.ConfidenceLow})

	matchedByIPAndModel := make(map[string]string)
	for _, r := range results {
		if len(r.Matches) > 0 {
			matchedByIPAndModel[r.Device.IP+"|"+r.Device.Model] = r.Matches[0].Advisory.ID
		}
	}

	wantMatches := []struct {
		key      string
		wantAdv  string
	}{
		{"10.10.1.10|KiSoft WCS", "CVE-2024-55010"},
		{"10.10.1.11|CX5130-OSR01", "BECKHOFF-2024-004"},
		{"10.10.1.13|CLV650", "SICK-2024-0003"},
		{"10.10.1.14|X20CP3586", "ICSA-23-BR-01"},
		{"10.10.1.15|CPU 1516F-3 PN/DP", "SSA-431678"},
		{"10.10.2.10|AK-SM 850A", "ICSA-22-202-04"},
		{"10.10.2.10|AK-CC55", "ICSA-22-202-04"},
		{"10.10.2.11|pCOWeb", "ICSA-23-CAREL-01"},
		{"10.10.2.12|XWEB500D EVO", "ICSA-24-XWEB-01"},
		{"10.10.2.13|Niagara JACE-8000", "ICSA-23-NIAGARA-01"},
		{"10.10.2.14|Niagara WEBs-N4 Supervisor", "ICSA-23-NIAGARA-01"},
		{"10.10.2.15|Tracer SC+", "ICSA-23-TRANE-01"},
		{"10.10.2.16|WebCTRL", "ICSA-23-ALC-01"},
		{"10.10.2.17|Metasys Server", "ICSA-23-JCI-01"},
		{"10.10.2.18|Desigo CC", "SSA-881204"},
	}

	for _, tc := range wantMatches {
		gotAdv, ok := matchedByIPAndModel[tc.key]
		if !ok {
			t.Errorf("missing expected match for %s (want %s); got map=%v", tc.key, tc.wantAdv, matchedByIPAndModel)
			continue
		}
		if gotAdv != tc.wantAdv {
			t.Errorf("match for %s = %s, want %s", tc.key, gotAdv, tc.wantAdv)
		}
	}

	// Ensure patched Beckhoff CX5130 (10.10.1.12, build 4026) was NOT flagged
	if badAdv, flagged := matchedByIPAndModel["10.10.1.12|CX5130-OSR02"]; flagged {
		t.Errorf("patched Beckhoff CX5130 (3.1.4026) falsely matched %s", badAdv)
	}
}
