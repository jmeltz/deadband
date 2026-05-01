package discover

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

const (
	eipCommandListIdentity      uint16 = 0x0063
	eipCommandRegisterSession   uint16 = 0x0065
	eipCommandSendRRData        uint16 = 0x006F
	eipHeaderSize                      = 24
	cipItemTypeIdentity         uint16 = 0x000C
	cipSocketAddrSize                  = 16

	cipServiceGetAttrAll      byte = 0x01
	cipServiceUnconnectedSend byte = 0x52

	cipClassIdentity byte = 0x01
	cipClassConnMgr  byte = 0x06

	cipMaxSlots = 17 // ControlLogix chassis: up to 17 slots (0-16)
)

// CIPIdentity holds parsed fields from an EIP ListIdentity response.
type CIPIdentity struct {
	VendorID    uint16
	DeviceType  uint16
	ProductCode uint16
	RevMajor    uint8
	RevMinor    uint8
	Serial      uint32
	ProductName string
	State       uint8
}

// vendorNames maps CIP vendor IDs to canonical vendor names. Source: ODVA
// EtherNet/IP Vendor ID registry. Used by both the generic CIP scan path and
// vendor-specific probes (e.g. Fanuc treats VendorID 252 as a positive hit).
var vendorNames = map[uint16]string{
	1:   "Rockwell Automation",
	2:   "Neles (Metso)",
	5:   "ODVA",
	40:  "ABB",
	56:  "Molex",
	90:  "Turck",
	266: "Schneider Electric",
	283: "Siemens",
	591: "Fanuc",
	671: "Honeywell",
}

// FanucCIPVendorID is FANUC CORPORATION's ODVA EtherNet/IP Vendor ID.
// Verified against a real Fanuc 32i EDS file: VendCode=591, VendName=
// "FANUC CORPORATION". Used by the Fanuc-specific probe to confirm a CIP
// responder is in fact a Fanuc controller.
const FanucCIPVendorID uint16 = 591

// buildListIdentityRequest returns a 24-byte EIP ListIdentity request.
func buildListIdentityRequest() []byte {
	buf := make([]byte, eipHeaderSize)
	binary.LittleEndian.PutUint16(buf[0:2], eipCommandListIdentity)
	// length, session, status, sender_context, options all remain zero
	return buf
}

// ParseListIdentityResponse parses an EIP ListIdentity response into a CIPIdentity.
func ParseListIdentityResponse(data []byte) (*CIPIdentity, error) {
	if len(data) < eipHeaderSize+2 {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	cmd := binary.LittleEndian.Uint16(data[0:2])
	if cmd != eipCommandListIdentity {
		return nil, fmt.Errorf("unexpected command 0x%04X, want 0x%04X", cmd, eipCommandListIdentity)
	}

	offset := eipHeaderSize
	itemCount := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	if itemCount == 0 {
		return nil, fmt.Errorf("response contains 0 items")
	}

	// Parse first item
	if len(data) < offset+4 {
		return nil, fmt.Errorf("response truncated at item header")
	}
	itemType := binary.LittleEndian.Uint16(data[offset : offset+2])
	itemLen := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
	offset += 4

	if itemType != cipItemTypeIdentity {
		return nil, fmt.Errorf("unexpected item type 0x%04X, want 0x%04X", itemType, cipItemTypeIdentity)
	}

	if len(data) < offset+int(itemLen) {
		return nil, fmt.Errorf("response truncated: need %d bytes for item, have %d", itemLen, len(data)-offset)
	}

	// Skip encapsulation protocol version (2 bytes) + socket address (16 bytes)
	minItemSize := 2 + cipSocketAddrSize + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 1 // up to name_len
	if int(itemLen) < minItemSize {
		return nil, fmt.Errorf("item too short: %d bytes", itemLen)
	}

	offset += 2 + cipSocketAddrSize // skip encap version + socket addr

	id := &CIPIdentity{}
	id.VendorID = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	id.DeviceType = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	id.ProductCode = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	id.RevMajor = data[offset]
	offset++
	id.RevMinor = data[offset]
	offset++
	// Status word (2 bytes)
	offset += 2
	id.Serial = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	nameLen := int(data[offset])
	offset++

	if len(data) < offset+nameLen {
		return nil, fmt.Errorf("response truncated at product name")
	}
	id.ProductName = string(data[offset : offset+nameLen])
	offset += nameLen

	if len(data) > offset {
		id.State = data[offset]
	}

	return id, nil
}

// ListIdentityUnicast sends a ListIdentity request to a single IP via UDP
// and returns the parsed identity.
func ListIdentityUnicast(ip string, timeout time.Duration) (*CIPIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", EIPPort))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", ip, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildListIdentityRequest()); err != nil {
		return nil, fmt.Errorf("write to %s: %w", ip, err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from %s: %w", ip, err)
	}

	return ParseListIdentityResponse(buf[:n])
}

// ListIdentityBroadcast sends a ListIdentity to the subnet broadcast address
// and collects all responses within the timeout window.
func ListIdentityBroadcast(broadcastAddr string, timeout time.Duration) (map[string]*CIPIdentity, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(broadcastAddr, fmt.Sprintf("%d", EIPPort)))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.WriteToUDP(buildListIdentityRequest(), addr); err != nil {
		return nil, fmt.Errorf("broadcast send: %w", err)
	}

	results := make(map[string]*CIPIdentity)
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	buf := make([]byte, 1500)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout or error, done collecting
		}
		id, parseErr := ParseListIdentityResponse(buf[:n])
		if parseErr != nil {
			continue
		}
		results[remote.IP.String()] = id
	}

	return results, nil
}

// CIPIdentityToDevice converts a CIPIdentity to an inventory.Device.
func CIPIdentityToDevice(ip string, id *CIPIdentity) inventory.Device {
	vendor, ok := vendorNames[id.VendorID]
	if !ok {
		vendor = fmt.Sprintf("Vendor(%d)", id.VendorID)
	}

	return inventory.Device{
		IP:       ip,
		Vendor:   vendor,
		Model:    id.ProductName,
		Firmware: fmt.Sprintf("%d.%03d", id.RevMajor, id.RevMinor),
		Serial:   fmt.Sprintf("%08X", id.Serial),
		Protocol: "cip",
		Port:     EIPPort,
	}
}

// discoverCIP performs CIP ListIdentity discovery across a set of IPs.
// For single hosts (/32), uses unicast. For subnets, attempts broadcast first
// then falls back to concurrent unicast for any IPs that didn't respond.
func discoverCIP(ips []string, broadcastAddr string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	responded := make(map[string]*CIPIdentity)

	// Try broadcast first if we have a broadcast address (subnet, not /32)
	if broadcastAddr != "" {
		if progress != nil {
			progress(fmt.Sprintf("Sending CIP ListIdentity broadcast to %s...", broadcastAddr))
		}
		if results, err := ListIdentityBroadcast(broadcastAddr, timeout); err == nil {
			for ip, id := range results {
				responded[ip] = id
			}
		}
		if progress != nil {
			progress(fmt.Sprintf("Broadcast discovered %d devices", len(responded)))
		}
	}

	// Unicast to any IPs that didn't respond to broadcast
	var remaining []string
	for _, ip := range ips {
		if _, ok := responded[ip]; !ok {
			remaining = append(remaining, ip)
		}
	}

	if len(remaining) > 0 {
		if progress != nil {
			progress(fmt.Sprintf("Sending CIP ListIdentity unicast to %d remaining hosts...", len(remaining)))
		}

		var mu sync.Mutex
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for _, ip := range remaining {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string) {
				defer wg.Done()
				defer func() { <-sem }()

				id, err := ListIdentityUnicast(ip, timeout)
				if err != nil {
					return
				}
				mu.Lock()
				responded[ip] = id
				mu.Unlock()
			}(ip)
		}
		wg.Wait()
	}

	var devices []inventory.Device
	for ip, id := range responded {
		// Try to enumerate the full backplane via CIP/TCP
		if progress != nil {
			progress(fmt.Sprintf("Enumerating backplane at %s...", ip))
		}
		modules, err := EnumerateBackplane(ip, timeout)
		if err == nil && len(modules) > 0 {
			if progress != nil {
				progress(fmt.Sprintf("Found %d modules in chassis at %s", len(modules), ip))
			}
			// Deduplicate by model+firmware (multiple identical cards share the same advisory profile)
			seen := make(map[string]bool)
			for i := range modules {
				dev := BackplaneModuleToDevice(ip, &modules[i])
				key := dev.Model + "|" + dev.Firmware
				if !seen[key] {
					seen[key] = true
					devices = append(devices, dev)
				}
			}
		} else {
			// Fall back to the ListIdentity result
			devices = append(devices, CIPIdentityToDevice(ip, id))
		}
	}
	return devices
}

// --- CIP over TCP: Backplane Enumeration ---

// BackplaneModule represents a module discovered in a ControlLogix backplane slot.
type BackplaneModule struct {
	Slot        int
	VendorID    uint16
	DeviceType  uint16
	ProductCode uint16
	RevMajor    uint8
	RevMinor    uint8
	Serial      uint32
	ProductName string
}

// cipSession holds an open EIP/TCP session.
type cipSession struct {
	conn   net.Conn
	handle uint32
}

// cipConnect opens a TCP connection to the EIP port and registers a session.
func cipConnect(ip string, timeout time.Duration) (*cipSession, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", EIPPort))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(timeout))

	// RegisterSession: 24-byte header + 4 bytes data (protocol version + options)
	req := make([]byte, eipHeaderSize+4)
	binary.LittleEndian.PutUint16(req[0:2], eipCommandRegisterSession)
	binary.LittleEndian.PutUint16(req[2:4], 4)
	binary.LittleEndian.PutUint16(req[eipHeaderSize:], 1) // protocol version 1

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("register session write: %w", err)
	}

	resp := make([]byte, eipHeaderSize+4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("register session read: %w", err)
	}

	if binary.LittleEndian.Uint16(resp[0:2]) != eipCommandRegisterSession {
		conn.Close()
		return nil, fmt.Errorf("unexpected response command 0x%04X", binary.LittleEndian.Uint16(resp[0:2]))
	}
	if status := binary.LittleEndian.Uint32(resp[8:12]); status != 0 {
		conn.Close()
		return nil, fmt.Errorf("register session status 0x%08X", status)
	}

	handle := binary.LittleEndian.Uint32(resp[4:8])
	conn.SetDeadline(time.Time{}) // clear deadline

	return &cipSession{conn: conn, handle: handle}, nil
}

func (s *cipSession) close() {
	// UnregisterSession (best-effort)
	buf := make([]byte, eipHeaderSize)
	binary.LittleEndian.PutUint16(buf[0:2], 0x0066)
	binary.LittleEndian.PutUint32(buf[4:8], s.handle)
	s.conn.Write(buf)
	s.conn.Close()
}

// getSlotIdentity queries the CIP Identity Object in a backplane slot via
// Unconnected Send (service 0x52) through the Connection Manager.
func (s *cipSession) getSlotIdentity(slot int, timeout time.Duration) (*BackplaneModule, error) {
	s.conn.SetDeadline(time.Now().Add(timeout))

	// Embedded CIP message: Get Attributes All on Identity Object (class 1, instance 1)
	embedded := []byte{
		cipServiceGetAttrAll,
		0x02,                   // path size: 2 words
		0x20, cipClassIdentity, // 8-bit class segment: class 1
		0x24, 0x01,             // 8-bit instance segment: instance 1
	}

	// Unconnected Send request to Connection Manager (class 6, instance 1)
	cip := []byte{
		cipServiceUnconnectedSend,
		0x02,                  // path size: 2 words
		0x20, cipClassConnMgr, // class 6
		0x24, 0x01,            // instance 1
		0x0A,                  // priority / time tick
		0x04,                  // timeout ticks
	}
	cip = append(cip, byte(len(embedded)), byte(len(embedded)>>8)) // embedded msg length (uint16 LE)
	cip = append(cip, embedded...)
	if len(embedded)%2 != 0 {
		cip = append(cip, 0x00) // pad to even
	}
	// Route path: port 1 (backplane), link address = slot number
	cip = append(cip, 0x01, 0x00) // route path size (1 word) + reserved
	cip = append(cip, 0x01, byte(slot))

	// Wrap in SendRRData with Common Packet Format
	cpf := make([]byte, 0, 16+len(cip))
	cpf = appendUint32LE(cpf, 0)              // interface handle
	cpf = appendUint16LE(cpf, 0)              // timeout
	cpf = appendUint16LE(cpf, 2)              // item count
	cpf = appendUint16LE(cpf, 0x0000)         // item 1: null address type
	cpf = appendUint16LE(cpf, 0)              // item 1: length 0
	cpf = appendUint16LE(cpf, 0x00B2)         // item 2: unconnected data type
	cpf = appendUint16LE(cpf, uint16(len(cip))) // item 2: data length
	cpf = append(cpf, cip...)

	pkt := make([]byte, eipHeaderSize+len(cpf))
	binary.LittleEndian.PutUint16(pkt[0:2], eipCommandSendRRData)
	binary.LittleEndian.PutUint16(pkt[2:4], uint16(len(cpf)))
	binary.LittleEndian.PutUint32(pkt[4:8], s.handle)
	copy(pkt[eipHeaderSize:], cpf)

	if _, err := s.conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("write slot %d: %w", slot, err)
	}

	// Read EIP response header
	hdr := make([]byte, eipHeaderSize)
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return nil, fmt.Errorf("read header slot %d: %w", slot, err)
	}

	dataLen := binary.LittleEndian.Uint16(hdr[2:4])
	if dataLen == 0 {
		return nil, fmt.Errorf("empty response for slot %d", slot)
	}

	data := make([]byte, dataLen)
	if _, err := io.ReadFull(s.conn, data); err != nil {
		return nil, fmt.Errorf("read data slot %d: %w", slot, err)
	}

	if status := binary.LittleEndian.Uint32(hdr[8:12]); status != 0 {
		return nil, fmt.Errorf("EIP error 0x%08X for slot %d", status, slot)
	}

	// Skip CPF overhead: interface_handle(4) + timeout(2) + item_count(2) +
	//   null_addr_type(2) + null_addr_len(2) + data_type(2) + data_len(2) = 16 bytes
	if len(data) < 20 {
		return nil, fmt.Errorf("response too short for slot %d: %d bytes", slot, len(data))
	}

	return parseCIPIdentityReply(data[16:], slot)
}

// parseCIPIdentityReply parses a CIP reply containing Identity Object attributes.
func parseCIPIdentityReply(data []byte, slot int) (*BackplaneModule, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("CIP reply too short for slot %d", slot)
	}

	generalStatus := data[2]
	addlWords := int(data[3])

	if generalStatus != 0 {
		return nil, fmt.Errorf("CIP status 0x%02X for slot %d", generalStatus, slot)
	}

	offset := 4 + addlWords*2

	// If we got a Connection Manager reply (0xD2), unwrap to get the embedded reply
	if data[0] == (cipServiceUnconnectedSend|0x80) && len(data) > offset+4 {
		inner := data[offset:]
		if inner[2] != 0 {
			return nil, fmt.Errorf("embedded CIP error 0x%02X for slot %d", inner[2], slot)
		}
		innerAddl := int(inner[3])
		offset = 4 + innerAddl*2
		data = inner
	}

	attr := data[offset:]

	// Identity Object attributes (Get Attributes All):
	// VendorID(2) + DeviceType(2) + ProductCode(2) + RevMajor(1) + RevMinor(1) +
	// Status(2) + Serial(4) + NameLen(1) = 15 bytes minimum
	if len(attr) < 15 {
		return nil, fmt.Errorf("identity data too short for slot %d: %d bytes", slot, len(attr))
	}

	mod := &BackplaneModule{Slot: slot}
	mod.VendorID = binary.LittleEndian.Uint16(attr[0:2])
	mod.DeviceType = binary.LittleEndian.Uint16(attr[2:4])
	mod.ProductCode = binary.LittleEndian.Uint16(attr[4:6])
	mod.RevMajor = attr[6]
	mod.RevMinor = attr[7]
	// skip status word at 8:10
	mod.Serial = binary.LittleEndian.Uint32(attr[10:14])

	nameLen := int(attr[14])
	if len(attr) >= 15+nameLen {
		mod.ProductName = string(attr[15 : 15+nameLen])
	}

	return mod, nil
}

// EnumerateBackplane opens a CIP/TCP session to the given IP and queries
// the Identity Object in each possible backplane slot (0 through cipMaxSlots-1).
func EnumerateBackplane(ip string, timeout time.Duration) ([]BackplaneModule, error) {
	sess, err := cipConnect(ip, timeout)
	if err != nil {
		return nil, err
	}
	defer sess.close()

	slotTimeout := time.Second
	if timeout < 2*time.Second {
		slotTimeout = timeout
	}

	var modules []BackplaneModule
	for slot := 0; slot < cipMaxSlots; slot++ {
		mod, err := sess.getSlotIdentity(slot, slotTimeout)
		if err != nil {
			continue
		}
		modules = append(modules, *mod)
	}

	return modules, nil
}

// BackplaneModuleToDevice converts a BackplaneModule to an inventory.Device.
func BackplaneModuleToDevice(ip string, mod *BackplaneModule) inventory.Device {
	vendor, ok := vendorNames[mod.VendorID]
	if !ok {
		vendor = fmt.Sprintf("Vendor(%d)", mod.VendorID)
	}
	return inventory.Device{
		IP:       ip,
		Vendor:   vendor,
		Model:    mod.ProductName,
		Firmware: fmt.Sprintf("%d.%03d", mod.RevMajor, mod.RevMinor),
		Serial:   fmt.Sprintf("%08X", mod.Serial),
		Protocol: "cip",
		Port:     EIPPort,
		Slot:     mod.Slot,
	}
}

func appendUint16LE(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendUint32LE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// broadcastAddrForCIDR computes the broadcast address for a CIDR range.
// Returns empty string for /32 single hosts.
func broadcastAddrForCIDR(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		return "" // /32, no broadcast
	}

	// Compute broadcast: network OR (NOT mask)
	broadcast := make(net.IP, len(ipNet.IP))
	for i := range ipNet.IP {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	return broadcast.String()
}
