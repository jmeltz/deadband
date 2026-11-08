package discover

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// Beckhoff TwinCAT AMS/ADS Read-Only Probe (TCP/48898).
//
// Strictly read-only: sends ADS CommandId 0x0001 (ADS ReadDeviceInfo) to the
// TwinCAT System Service (port 10000) or TwinCAT 3 PLC Runtime 1 (port 851).
// Never issues ADS Write (0x0003) or ADS WriteControl (0x0005).

const (
	adsCmdReadDeviceInfo = 0x0001
	adsStateReq          = 0x0004 // ADS command request flag
	adsPortSystemService = 10000
	adsPortTc3Plc1       = 851
	adsPortTc2Plc1       = 801
)

// ADSIdentity holds device identity returned by TwinCAT ADS ReadDeviceInfo.
type ADSIdentity struct {
	DeviceName string
	Major      uint8
	Minor      uint8
	Build      uint16
	TargetPort uint16
	AMSNetID   string
}

func ipToAMSNetID(ipStr string) ([6]byte, bool) {
	var netID [6]byte
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return netID, false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return netID, false
	}
	copy(netID[0:4], v4)
	netID[4] = 1
	netID[5] = 1
	return netID, true
}

func buildADSReadDeviceInfoRequest(targetNetID, sourceNetID [6]byte, targetPort uint16, invokeID uint32) []byte {
	// 6-byte AMS/TCP header + 32-byte AMS header = 38 bytes (ReadDeviceInfo request has 0 data bytes)
	buf := make([]byte, 38)
	// AMS/TCP header: 2 reserved zero bytes + 4-byte LE length (32)
	binary.LittleEndian.PutUint32(buf[2:6], 32)
	// AMS header
	copy(buf[6:12], targetNetID[:])
	binary.LittleEndian.PutUint16(buf[12:14], targetPort)
	copy(buf[14:20], sourceNetID[:])
	binary.LittleEndian.PutUint16(buf[20:22], 32905) // ephemeral client AMS port
	binary.LittleEndian.PutUint16(buf[22:24], adsCmdReadDeviceInfo)
	binary.LittleEndian.PutUint16(buf[24:26], adsStateReq)
	binary.LittleEndian.PutUint32(buf[26:30], 0) // cbData = 0
	binary.LittleEndian.PutUint32(buf[30:34], 0) // errorCode = 0
	binary.LittleEndian.PutUint32(buf[34:38], invokeID)
	return buf
}

func formatAMSNetID(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	allZero := true
	for i := 0; i < 6; i++ {
		if b[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.%d.%d", b[0], b[1], b[2], b[3], b[4], b[5])
}

// isConfirmedAMSResponse validates that frame is a genuine Beckhoff AMS/TCP response
// (either a full ReadDeviceInfo payload or an AMS router error reply echoing our invokeID).
func isConfirmedAMSResponse(frame []byte, expectedInvokeID uint32) (routerNetID string, ok bool) {
	if len(frame) < 38 {
		return "", false
	}
	if frame[0] != 0 || frame[1] != 0 {
		return "", false
	}
	amsLen := binary.LittleEndian.Uint32(frame[2:6])
	if amsLen < 32 || amsLen > 4096 || int(6+amsLen) > len(frame) {
		return "", false
	}
	cmdID := binary.LittleEndian.Uint16(frame[22:24])
	stateFlags := binary.LittleEndian.Uint16(frame[24:26])
	invokeID := binary.LittleEndian.Uint32(frame[34:38])
	if cmdID != adsCmdReadDeviceInfo || (stateFlags&0x0001) == 0 || invokeID != expectedInvokeID {
		return "", false
	}
	return formatAMSNetID(frame[14:20]), true
}

// ParseADSReadDeviceInfoFrame parses a 62+ byte AMS/TCP ReadDeviceInfo response frame
// (used by both active discovery and passive PCAP dissection).
func ParseADSReadDeviceInfoFrame(frame []byte) (*ADSIdentity, error) {
	if len(frame) < 22 {
		return nil, fmt.Errorf("ADS frame too short")
	}
	srcAMSPort := binary.LittleEndian.Uint16(frame[20:22])
	return parseADSReadDeviceInfoResponse(frame, srcAMSPort)
}

func parseADSReadDeviceInfoResponse(frame []byte, targetPort uint16) (*ADSIdentity, error) {
	// AMS/TCP(6) + AMS(32) + ADS ReadDeviceInfo payload(24: result[4] + major[1] + minor[1] + build[2] + name[16]) = 62 bytes
	if len(frame) < 62 {
		return nil, fmt.Errorf("ADS response too short: %d bytes", len(frame))
	}
	if frame[0] != 0 || frame[1] != 0 {
		return nil, fmt.Errorf("ADS invalid TCP reserved bytes: %x", frame[0:2])
	}
	cmdID := binary.LittleEndian.Uint16(frame[22:24])
	stateFlags := binary.LittleEndian.Uint16(frame[24:26])
	amsErr := binary.LittleEndian.Uint32(frame[30:34])
	if cmdID != adsCmdReadDeviceInfo || (stateFlags&0x0001) == 0 || amsErr != 0 {
		return nil, fmt.Errorf("ADS invalid header cmd=%d flags=0x%x err=%d", cmdID, stateFlags, amsErr)
	}
	adsResult := binary.LittleEndian.Uint32(frame[38:42])
	if adsResult != 0 {
		return nil, fmt.Errorf("ADS ReadDeviceInfo returned error 0x%x", adsResult)
	}
	maj := frame[42]
	min := frame[43]
	build := binary.LittleEndian.Uint16(frame[44:46])
	rawName := frame[46:62]
	if nul := bytes.IndexByte(rawName, 0); nul >= 0 {
		rawName = rawName[:nul]
	}
	name := strings.TrimSpace(string(rawName))
	if name == "" {
		name = "TwinCAT Runtime"
	}
	return &ADSIdentity{
		DeviceName: name,
		Major:      maj,
		Minor:      min,
		Build:      build,
		TargetPort: targetPort,
		AMSNetID:   formatAMSNetID(frame[14:20]),
	}, nil
}

// adsProbeTCP queries ip:port over TCP/48898 and reports both full ReadDeviceInfo
// identity and whether a valid AMS/TCP response header confirmed a TwinCAT router.
func adsProbeTCP(ip string, port int, timeout time.Duration) (id *ADSIdentity, confirmedRouter bool, routerNetID string) {
	targetNetID, ok := ipToAMSNetID(ip)
	if !ok {
		targetNetID = [6]byte{127, 0, 0, 1, 1, 1}
	}
	sourceNetID := [6]byte{10, 254, 254, 1, 1, 1}

	candidatePorts := []uint16{adsPortSystemService, adsPortTc3Plc1, adsPortTc2Plc1}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	for idx, amsPort := range candidatePorts {
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return nil, confirmedRouter, routerNetID
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))

		// Attempt to derive source AMS NetID from local socket IP so strict AMS routers match it
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			if localNetID, ok2 := ipToAMSNetID(tcpAddr.IP.String()); ok2 {
				sourceNetID = localNetID
			}
		}

		invokeID := uint32(idx + 1)
		req := buildADSReadDeviceInfoRequest(targetNetID, sourceNetID, amsPort, invokeID)
		if _, err := conn.Write(req); err != nil {
			conn.Close()
			continue
		}

		hdr := make([]byte, 6)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			conn.Close()
			continue
		}
		if hdr[0] != 0 || hdr[1] != 0 {
			conn.Close()
			continue
		}
		amsLen := binary.LittleEndian.Uint32(hdr[2:6])
		if amsLen < 32 || amsLen > 4096 {
			conn.Close()
			continue
		}
		body := make([]byte, amsLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			conn.Close()
			continue
		}
		conn.Close()

		full := append(hdr, body...)
		if netID, validHdr := isConfirmedAMSResponse(full, invokeID); validHdr {
			confirmedRouter = true
			if netID != "" {
				routerNetID = netID
			}
		}
		if parsed, err := parseADSReadDeviceInfoResponse(full, amsPort); err == nil && parsed != nil {
			return parsed, true, parsed.AMSNetID
		}
	}
	return nil, confirmedRouter, routerNetID
}

// ADSIdentify queries a host on TCP/48898 (or custom port for testing) using ADS ReadDeviceInfo.
func ADSIdentify(ip string, port int, timeout time.Duration) (*ADSIdentity, error) {
	id, _, _ := adsProbeTCP(ip, port, timeout)
	return id, nil
}

// --- Beckhoff ADS UDP Discovery (UDP/48899) ---
//
// Strictly read-only: sends a 24-byte SERVERINFO discovery request
// (header 03 66 14 71, serviceId=1, 0 tags — never a 0-byte packet, never ADDROUTE=6).

var adsUDPMagic = []byte{0x03, 0x66, 0x14, 0x71}

const (
	adsUDPServiceServerInfoReq  uint32 = 0x00000001
	adsUDPServiceServerInfoResp uint32 = 0x80000001

	adsUDPTagRouteName   uint16 = 2
	adsUDPTagOSVersion   uint16 = 3
	adsUDPTagTwinCATVer  uint16 = 4
	adsUDPTagHostName    uint16 = 5
	adsUDPTagDescription uint16 = 7
)

func buildADSUDPDiscoveryRequest(sourceNetID [6]byte) []byte {
	pkt := make([]byte, 24)
	copy(pkt[0:4], adsUDPMagic)
	binary.LittleEndian.PutUint32(pkt[4:8], 0) // invoke / enquire = 0
	binary.LittleEndian.PutUint32(pkt[8:12], adsUDPServiceServerInfoReq)
	copy(pkt[12:18], sourceNetID[:])
	binary.LittleEndian.PutUint16(pkt[18:20], adsPortSystemService)
	binary.LittleEndian.PutUint32(pkt[20:24], 0) // 0 TLV blocks
	return pkt
}

// ParseADSUDPDiscoveryResponse parses a 24+ byte Beckhoff ADS UDP/48899 SERVERINFO response.
func ParseADSUDPDiscoveryResponse(pkt []byte) (*ADSIdentity, map[string]string, error) {
	if len(pkt) < 24 {
		return nil, nil, fmt.Errorf("ADS UDP packet too short: %d bytes", len(pkt))
	}
	if !bytes.Equal(pkt[0:4], adsUDPMagic) {
		return nil, nil, fmt.Errorf("invalid ADS UDP magic: %x", pkt[0:4])
	}
	svc := binary.LittleEndian.Uint32(pkt[8:12])
	if svc != adsUDPServiceServerInfoResp {
		return nil, nil, fmt.Errorf("unexpected ADS UDP service 0x%08x", svc)
	}

	netID := formatAMSNetID(pkt[12:18])
	amsPort := binary.LittleEndian.Uint16(pkt[18:20])
	tagCount := binary.LittleEndian.Uint32(pkt[20:24])
	if tagCount > 64 {
		tagCount = 64
	}

	id := &ADSIdentity{
		TargetPort: amsPort,
		AMSNetID:   netID,
	}
	meta := make(map[string]string)
	if netID != "" {
		meta["ams_net_id"] = netID
	}

	off := 24
	var hostName, routeName, desc string
	for i := uint32(0); i < tagCount && off+4 <= len(pkt); i++ {
		tagID := binary.LittleEndian.Uint16(pkt[off : off+2])
		tagLen := int(binary.LittleEndian.Uint16(pkt[off+2 : off+4]))
		off += 4
		if off+tagLen > len(pkt) {
			break
		}
		val := pkt[off : off+tagLen]
		off += tagLen

		cleanStr := func(b []byte) string {
			if nul := bytes.IndexByte(b, 0); nul >= 0 {
				b = b[:nul]
			}
			return strings.TrimSpace(string(b))
		}

		switch tagID {
		case adsUDPTagHostName:
			hostName = cleanStr(val)
		case adsUDPTagRouteName:
			routeName = cleanStr(val)
		case adsUDPTagDescription:
			desc = cleanStr(val)
		case adsUDPTagTwinCATVer:
			if len(val) >= 4 {
				id.Major = val[0]
				id.Minor = val[1]
				id.Build = binary.LittleEndian.Uint16(val[2:4])
			}
		case adsUDPTagOSVersion:
			if len(val) >= 8 {
				osMaj := binary.LittleEndian.Uint32(val[0:4])
				osMin := binary.LittleEndian.Uint32(val[4:8])
				if osMaj > 0 && osMaj < 100 {
					meta["os"] = fmt.Sprintf("Windows %d.%d", osMaj, osMin)
				}
			}
		}
	}

	if hostName == "" {
		hostName = routeName
	}
	if hostName != "" {
		meta["hostname"] = hostName
	}
	if desc != "" {
		meta["description"] = desc
	}

	upperHost := strings.ToUpper(hostName)
	switch {
	case strings.HasPrefix(upperHost, "CX") || strings.HasPrefix(upperHost, "C6") || strings.HasPrefix(upperHost, "CP"):
		id.DeviceName = hostName
	case desc != "" && (strings.Contains(strings.ToUpper(desc), "CX") || strings.Contains(strings.ToLower(desc), "twincat")):
		id.DeviceName = desc
	default:
		id.DeviceName = "TwinCAT System"
	}

	return id, meta, nil
}

// ADSDiscoverUDP sends a read-only Beckhoff ADS UDP SERVERINFO query to ip:port (default 48899).
func ADSDiscoverUDP(ip string, port int, timeout time.Duration) (*ADSIdentity, map[string]string, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if port <= 0 {
		port = ADSUDPPort
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, nil, nil
	}
	defer conn.Close()

	sourceNetID := [6]byte{10, 254, 254, 1, 1, 1}
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if localNetID, ok2 := ipToAMSNetID(udpAddr.IP.String()); ok2 {
			sourceNetID = localNetID
		}
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildADSUDPDiscoveryRequest(sourceNetID)); err != nil {
		return nil, nil, nil
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, nil, nil
	}
	return ParseADSUDPDiscoveryResponse(buf[:n])
}

func isBeckhoffHardwarePrefix(s string) bool {
	u := strings.ToUpper(strings.TrimSpace(s))
	return strings.HasPrefix(u, "CX") || strings.HasPrefix(u, "C6") || strings.HasPrefix(u, "CP")
}

// ADSIdentityToDevice converts a parsed ADSIdentity into an inventory.Device.
func ADSIdentityToDevice(ip string, port int, id *ADSIdentity) inventory.Device {
	return adsIdentityToDevice(ip, port, id)
}

func adsIdentityToDevice(ip string, port int, id *ADSIdentity) inventory.Device {
	fw := ""
	if id.Major > 0 || id.Minor > 0 || id.Build > 0 {
		fw = fmt.Sprintf("%d.%d.%d", id.Major, id.Minor, id.Build)
	}
	model := id.DeviceName
	if !strings.Contains(strings.ToLower(model), "twincat") && !isBeckhoffHardwarePrefix(model) {
		model = "TwinCAT " + model
	}
	var extra map[string]string
	if id.AMSNetID != "" {
		extra = map[string]string{"ams_net_id": id.AMSNetID}
	}
	return inventory.Device{
		IP:       ip,
		Vendor:   "Beckhoff",
		Model:    strings.TrimSpace(model),
		Firmware: fw,
		Protocol: "ads",
		Port:     port,
		Extra:    extra,
	}
}

func discoverADS(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	// Phase 1: Route-less UDP/48899 ADS Discovery across all hosts (succeeds even when TCP/48898 blocks unrouted NetIDs)
	udpTimeout := timeout
	if udpTimeout > 750*time.Millisecond {
		udpTimeout = 750 * time.Millisecond
	}
	udpByIP := make(map[string]inventory.Device)
	var (
		udpMu sync.Mutex
		udpWg sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for _, ip := range ips {
		udpWg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer udpWg.Done()
			defer func() { <-sem }()

			id, meta, err := ADSDiscoverUDP(ip, ADSUDPPort, udpTimeout)
			if err != nil || id == nil {
				return
			}
			dev := adsIdentityToDevice(ip, ADSUDPPort, id)
			if h := meta["hostname"]; h != "" {
				dev.Hostname = h
			}
			if osStr := meta["os"]; osStr != "" {
				if dev.Extra == nil {
					dev.Extra = make(map[string]string)
				}
				dev.Extra["os"] = osStr
			}
			udpMu.Lock()
			udpByIP[ip] = dev
			udpMu.Unlock()
		}(ip)
	}
	udpWg.Wait()

	// Phase 2: TCP/48898 AMS/ADS probe (catches firewalled TCP-only hosts & enriches PLC runtime name)
	open := ScanPorts(ips, ADSPort, timeout, concurrency)
	if progress != nil {
		progress(fmt.Sprintf("TwinCAT ADS: %d UDP/%d responders, %d/%d hosts with TCP/%d open", len(udpByIP), ADSUDPPort, len(open), len(ips), ADSPort))
	}

	var (
		tcpMu sync.Mutex
		tcpWg sync.WaitGroup
	)
	tcpByIP := make(map[string]inventory.Device)

	for _, ip := range open {
		tcpWg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer tcpWg.Done()
			defer func() { <-sem }()

			id, confirmedRouter, routerNetID := adsProbeTCP(ip, ADSPort, timeout)
			var dev inventory.Device
			if id != nil {
				dev = adsIdentityToDevice(ip, ADSPort, id)
			} else if confirmedRouter {
				// AMS router replied with a valid AMS/TCP error header — confirmed Beckhoff TwinCAT
				dev = inventory.Device{
					IP:       ip,
					Vendor:   "Beckhoff",
					Model:    "TwinCAT ADS Router",
					Protocol: "ads",
					Port:     ADSPort,
				}
				if routerNetID != "" {
					dev.Extra = map[string]string{"ams_net_id": routerNetID}
				}
			} else {
				// Non-ADS listener on TCP/48898 — do not emit a false-positive Beckhoff device
				return
			}
			tcpMu.Lock()
			tcpByIP[ip] = dev
			tcpMu.Unlock()
		}(ip)
	}
	tcpWg.Wait()

	// Combine UDP + TCP findings per IP (preferring concrete hardware/firmware fields from whichever responded)
	seenIP := make(map[string]bool)
	var devices []inventory.Device
	for _, ip := range ips {
		uDev, hasUDP := udpByIP[ip]
		tDev, hasTCP := tcpByIP[ip]
		if !hasUDP && !hasTCP {
			continue
		}
		seenIP[ip] = true
		switch {
		case hasTCP && hasUDP:
			merged := tDev
			if isPlaceholderModel(merged.Model) || merged.Model == "TwinCAT System" {
				if uDev.Model != "" && !isPlaceholderModel(uDev.Model) {
					merged.Model = uDev.Model
				}
			}
			if merged.Firmware == "" {
				merged.Firmware = uDev.Firmware
			}
			if merged.Hostname == "" {
				merged.Hostname = uDev.Hostname
			}
			if len(uDev.Extra) > 0 {
				if merged.Extra == nil {
					merged.Extra = make(map[string]string)
				}
				for k, v := range uDev.Extra {
					if merged.Extra[k] == "" {
						merged.Extra[k] = v
					}
				}
			}
			devices = append(devices, merged)
		case hasUDP:
			devices = append(devices, uDev)
		case hasTCP:
			devices = append(devices, tDev)
		}
	}
	return devices
}
