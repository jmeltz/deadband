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

func parseADSReadDeviceInfoResponse(frame []byte, targetPort uint16) (*ADSIdentity, error) {
	// AMS/TCP(6) + AMS(32) + ADS ReadDeviceInfo payload(24: result[4] + major[1] + minor[1] + build[2] + name[16]) = 62 bytes
	if len(frame) < 62 {
		return nil, fmt.Errorf("ADS response too short: %d bytes", len(frame))
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
	}, nil
}

// ADSIdentify queries a host on TCP/48898 (or custom port for testing) using ADS ReadDeviceInfo.
func ADSIdentify(ip string, port int, timeout time.Duration) (*ADSIdentity, error) {
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
			return nil, nil
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))

		// Attempt to derive source AMS NetID from local socket IP so strict AMS routers match it
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			if localNetID, ok2 := ipToAMSNetID(tcpAddr.IP.String()); ok2 {
				sourceNetID = localNetID
			}
		}

		req := buildADSReadDeviceInfoRequest(targetNetID, sourceNetID, amsPort, uint32(idx+1))
		if _, err := conn.Write(req); err != nil {
			conn.Close()
			continue
		}

		hdr := make([]byte, 6)
		if _, err := io.ReadFull(conn, hdr); err != nil {
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
		if id, err := parseADSReadDeviceInfoResponse(full, amsPort); err == nil && id != nil {
			return id, nil
		}
	}
	return nil, nil
}

func adsIdentityToDevice(ip string, port int, id *ADSIdentity) inventory.Device {
	fw := ""
	if id.Major > 0 || id.Minor > 0 || id.Build > 0 {
		fw = fmt.Sprintf("%d.%d.%d", id.Major, id.Minor, id.Build)
	}
	model := id.DeviceName
	if !strings.Contains(strings.ToLower(model), "twincat") && !strings.HasPrefix(strings.ToUpper(model), "CX") {
		model = "TwinCAT " + model
	}
	return inventory.Device{
		IP:       ip,
		Vendor:   "Beckhoff",
		Model:    strings.TrimSpace(model),
		Firmware: fw,
		Protocol: "ads",
		Port:     port,
	}
}

func discoverADS(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	open := ScanPorts(ips, ADSPort, timeout, concurrency)
	if progress != nil {
		progress(fmt.Sprintf("TwinCAT ADS: %d/%d hosts with TCP/%d open", len(open), len(ips), ADSPort))
	}
	if len(open) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		devices []inventory.Device
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for _, ip := range open {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id, err := ADSIdentify(ip, ADSPort, timeout)
			var dev inventory.Device
			if err == nil && id != nil {
				dev = adsIdentityToDevice(ip, ADSPort, id)
			} else {
				// AMS router rejected unrouted client NetID — still confirm TwinCAT ADS presence
				dev = inventory.Device{
					IP:       ip,
					Vendor:   "Beckhoff",
					Model:    "TwinCAT ADS Router",
					Protocol: "ads",
					Port:     ADSPort,
				}
			}
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return devices
}
