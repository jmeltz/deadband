package posture

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestProbeBACnetUDP_AndNewOTPostureRules(t *testing.T) {
	// 1. Verify UDP BACnet probe detects a responsive BACnet/IP responder
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 128)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n < 4 {
			return
		}
		// Reply with minimal valid BVLC I-Am frame
		iam := []byte{0x81, 0x0B, 0x00, 0x0C, 0x01, 0x00, 0x10, 0x00, 0xC4, 0x02, 0x00, 0x01}
		_, _ = pc.WriteTo(iam, addr)
	}()

	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)
	if !probeBACnetUDP(host, port, time.Second) {
		t.Error("expected probeBACnetUDP to detect responsive BACnet UDP endpoint")
	}

	// 2. Verify classification of ADS, SICK CoLa-2, and Niagara Fox hosts as ClassOT
	classified := ClassifyHostsWithProgress([]HostResult{
		{IP: "10.40.1.10", OpenPorts: []int{48898, 3389, 445}}, // TwinCAT IPC with RDP + SMB
		{IP: "10.40.1.20", OpenPorts: []int{47808, 80}},        // BACnet refrigeration supervisor with HTTP only
		{IP: "10.40.1.21", OpenPorts: []int{1911, 443}},        // Niagara Fox supervisor with HTTPS only
		{IP: "10.40.1.30", OpenPorts: []int{2122}},             // SICK Lector654 CoLa-2
	}, nil, 200*time.Millisecond, 4, nil)

	for _, ch := range classified {
		if ch.DeviceClass != ClassOT {
			t.Errorf("host %s ports %v classified as %q, want ClassOT", ch.IP, ch.OpenPorts, ch.DeviceClass)
		}
	}

	// 3. Verify EvalRules fires ads_it_coexposure (for 10.40.1.10) and cleartext_ot_web (for 10.40.1.20, NOT 10.40.1.21)
	subnets := AnalyzeSubnets(classified)
	findings := EvalRules(DefaultRules, subnets)

	byType := make(map[string][]Finding)
	for _, f := range findings {
		byType[f.Type] = append(byType[f.Type], f)
	}

	if len(byType["ads_it_coexposure"]) != 1 {
		t.Errorf("ads_it_coexposure findings = %+v, want 1 (for 10.40.1.10)", byType["ads_it_coexposure"])
	} else if len(byType["ads_it_coexposure"][0].Controls) == 0 {
		t.Error("expected IEC 62443 / NIST CSF controls on ads_it_coexposure finding")
	}

	if len(byType["cleartext_ot_web"]) != 1 {
		t.Errorf("cleartext_ot_web findings = %+v, want 1 (for HTTP-only 10.40.1.20, excluding HTTPS 10.40.1.21)", byType["cleartext_ot_web"])
	} else if len(byType["cleartext_ot_web"][0].Controls) == 0 {
		t.Error("expected IEC 62443 SR 4.1 controls on cleartext_ot_web finding")
	}
}
