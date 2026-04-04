package discover

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// Modbus TCP protocol constants
const (
	modbusProtocolID  = 0x0000 // Modbus protocol identifier
	modbusDefaultUnit = 0x01   // Default slave/unit address

	// Function codes
	mbFuncMEI      = 0x2B // Encapsulated Interface Transport (FC 43)
	mbFuncMEIError = 0xAB // Error response (0x2B | 0x80)

	// MEI types
	meiReadDeviceID = 0x0E // Read Device Identification

	// Read Device ID codes
	devIDBasic   = 0x01 // Objects 0x00-0x02
	devIDRegular = 0x02 // Objects 0x00-0x06

	// Standard object IDs
	objVendorName         = 0x00
	objProductCode        = 0x01
	objMajorMinorRevision = 0x02
	objVendorUrl          = 0x03
	objProductName        = 0x04
	objModelName          = 0x05
)

// ModbusIdentity holds parsed device identification from Modbus TCP FC 43/14.
type ModbusIdentity struct {
	VendorName  string // Object 0x00
	ProductCode string // Object 0x01
	Revision    string // Object 0x02 (MajorMinorRevision)
	VendorUrl   string // Object 0x03
	ProductName string // Object 0x04
	ModelName   string // Object 0x05
}

// --- Frame builders ---

// buildModbusMBAP wraps a PDU with the 7-byte MBAP header.
func buildModbusMBAP(transactionID uint16, unitID byte, pdu []byte) []byte {
	buf := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(buf[0:2], transactionID)
	binary.BigEndian.PutUint16(buf[2:4], modbusProtocolID)
	binary.BigEndian.PutUint16(buf[4:6], uint16(1+len(pdu))) // unit ID + PDU length
	buf[6] = unitID
	copy(buf[7:], pdu)
	return buf
}

// buildReadDeviceIDRequest builds a Modbus Read Device Identification request (FC 43 / MEI 14).
func buildReadDeviceIDRequest(transactionID uint16, unitID byte, readCode byte, objectID byte) []byte {
	pdu := []byte{
		mbFuncMEI,      // Function code 0x2B
		meiReadDeviceID, // MEI type 0x0E
		readCode,        // Basic (0x01) or Regular (0x02)
		objectID,        // Starting object ID
	}
	return buildModbusMBAP(transactionID, unitID, pdu)
}

// --- Parsers ---

// parseMBAPHeader validates and parses the 7-byte MBAP header.
func parseMBAPHeader(data []byte) (transactionID uint16, unitID byte, pdu []byte, err error) {
	if len(data) < 7 {
		return 0, 0, nil, fmt.Errorf("MBAP too short: %d bytes", len(data))
	}
	transactionID = binary.BigEndian.Uint16(data[0:2])
	protocolID := binary.BigEndian.Uint16(data[2:4])
	if protocolID != modbusProtocolID {
		return 0, 0, nil, fmt.Errorf("MBAP protocol ID 0x%04X, want 0x%04X", protocolID, modbusProtocolID)
	}
	length := binary.BigEndian.Uint16(data[4:6])
	if int(length)+6 > len(data) {
		return 0, 0, nil, fmt.Errorf("MBAP length %d exceeds data %d", length, len(data)-6)
	}
	unitID = data[6]
	pdu = data[7 : 6+int(length)]
	return transactionID, unitID, pdu, nil
}

// parseReadDeviceIDResponse parses a Read Device Identification response PDU.
// Returns parsed object map, whether more objects follow, and the next object ID.
func parseReadDeviceIDResponse(pdu []byte) (objects map[byte]string, moreFollows bool, nextObjID byte, err error) {
	if len(pdu) < 1 {
		return nil, false, 0, fmt.Errorf("empty PDU")
	}

	funcCode := pdu[0]
	if funcCode == mbFuncMEIError {
		if len(pdu) >= 2 {
			return nil, false, 0, fmt.Errorf("Modbus exception: code %d", pdu[1])
		}
		return nil, false, 0, fmt.Errorf("Modbus exception response")
	}
	if funcCode != mbFuncMEI {
		return nil, false, 0, fmt.Errorf("function code 0x%02X, want 0x%02X", funcCode, mbFuncMEI)
	}

	// FC(1) + MEI(1) + ReadCode(1) + Conformity(1) + MoreFollows(1) + NextObj(1) + NumObj(1) = 7
	if len(pdu) < 7 {
		return nil, false, 0, fmt.Errorf("Read Device ID response too short: %d bytes", len(pdu))
	}

	if pdu[1] != meiReadDeviceID {
		return nil, false, 0, fmt.Errorf("MEI type 0x%02X, want 0x%02X", pdu[1], meiReadDeviceID)
	}

	moreFollows = pdu[4] == 0xFF
	nextObjID = pdu[5]
	numObjects := int(pdu[6])

	objects = make(map[byte]string)
	offset := 7

	for i := 0; i < numObjects; i++ {
		if offset+2 > len(pdu) {
			break
		}
		objID := pdu[offset]
		objLen := int(pdu[offset+1])
		offset += 2

		if offset+objLen > len(pdu) {
			break
		}
		objects[objID] = string(pdu[offset : offset+objLen])
		offset += objLen
	}

	return objects, moreFollows, nextObjID, nil
}

// --- Scanner ---

// ModbusTCPIdentify performs Modbus TCP Read Device Identification against a single IP.
// Tries regular identification first (objects 0x00-0x06), falls back to basic (0x00-0x02).
// Returns nil, nil if the host doesn't support device identification.
func ModbusTCPIdentify(ip string, timeout time.Duration) (*ModbusIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", ModbusTCPPort))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Try regular identification first (gets model name, product name, etc.)
	id, err := modbusReadDeviceID(conn, devIDRegular, 0x00)
	if err == nil {
		return id, nil
	}

	// Fall back to basic identification on a fresh connection
	conn.Close()
	conn2, err2 := net.DialTimeout("tcp", addr, timeout)
	if err2 != nil {
		return nil, nil
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(timeout))

	id, err = modbusReadDeviceID(conn2, devIDBasic, 0x00)
	if err != nil {
		return nil, nil
	}
	return id, nil
}

// modbusReadDeviceID performs one or more Read Device ID transactions,
// following "More Follows" continuations until all objects are collected.
func modbusReadDeviceID(conn net.Conn, readCode byte, startObjID byte) (*ModbusIdentity, error) {
	allObjects := make(map[byte]string)
	objID := startObjID
	txnID := uint16(1)

	for {
		req := buildReadDeviceIDRequest(txnID, modbusDefaultUnit, readCode, objID)
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}

		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}

		_, _, pdu, err := parseMBAPHeader(buf[:n])
		if err != nil {
			return nil, err
		}

		objects, moreFollows, nextObjID, err := parseReadDeviceIDResponse(pdu)
		if err != nil {
			return nil, err
		}

		for k, v := range objects {
			allObjects[k] = v
		}

		if !moreFollows {
			break
		}

		objID = nextObjID
		txnID++
		if txnID > 10 { // safety limit
			break
		}
	}

	if _, ok := allObjects[objVendorName]; !ok {
		return nil, fmt.Errorf("no vendor name in response")
	}

	return &ModbusIdentity{
		VendorName:  allObjects[objVendorName],
		ProductCode: allObjects[objProductCode],
		Revision:    allObjects[objMajorMinorRevision],
		VendorUrl:   allObjects[objVendorUrl],
		ProductName: allObjects[objProductName],
		ModelName:   allObjects[objModelName],
	}, nil
}

// modbusIdentityToDevice converts a ModbusIdentity to an inventory.Device.
func modbusIdentityToDevice(ip string, id *ModbusIdentity) inventory.Device {
	vendor := normalizeModbusVendor(id.VendorName)

	// Use the most specific model name available
	model := id.ModelName
	if model == "" {
		model = id.ProductName
	}
	if model == "" {
		model = id.ProductCode
	}

	return inventory.Device{
		IP:       ip,
		Vendor:   vendor,
		Model:    model,
		Firmware: id.Revision,
	}
}

// normalizeModbusVendor maps Modbus vendor name strings to canonical names
// used in the CISA advisory database. Longer/more-specific patterns are
// checked first so "Hitachi Energy" beats a bare "hitachi" match, etc.
func normalizeModbusVendor(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return strings.TrimSpace(raw)
	}

	vendors := []struct {
		pattern   string
		canonical string
	}{
		{"schneider", "Schneider Electric"},
		{"hitachi energy", "Hitachi Energy"},
		{"delta electron", "Delta Electronics"},
		{"phoenix contact", "Phoenix Contact"},
		{"general electric", "GE Vernova"},
		{"ge vernova", "GE Vernova"},
		{"mitsubishi", "Mitsubishi Electric"},
		{"rockwell", "Rockwell Automation"},
		{"allen-bradley", "Rockwell Automation"},
		{"yokogawa", "Yokogawa"},
		{"honeywell", "Honeywell"},
		{"beckhoff", "Beckhoff"},
		{"emerson", "Emerson"},
		{"siemens", "Siemens"},
		{"phoenix", "Phoenix Contact"},
		{"moxa", "Moxa"},
		{"wago", "WAGO"},
		{"eaton", "Eaton"},
		{"omron", "Omron"},
		{"abb", "ABB"},
	}

	for _, v := range vendors {
		if strings.Contains(lower, v.pattern) {
			return v.canonical
		}
	}

	return strings.TrimSpace(raw)
}

// discoverModbusTCP performs Modbus TCP device identification across a set of IPs.
// Port-scans TCP 502 first, then runs FC 43/14 Read Device ID on responsive hosts.
func discoverModbusTCP(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("Modbus TCP scanning %d hosts on port %d...", len(ips), ModbusTCPPort))
	}

	openHosts := ScanPorts(ips, ModbusTCPPort, timeout, concurrency)

	if progress != nil {
		progress(fmt.Sprintf("Modbus TCP found %d hosts with port %d open", len(openHosts), ModbusTCPPort))
	}

	if len(openHosts) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		devices []inventory.Device
	)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range openHosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id, err := ModbusTCPIdentify(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := modbusIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	if progress != nil {
		progress(fmt.Sprintf("Modbus TCP identified %d devices", len(devices)))
	}

	return devices
}
