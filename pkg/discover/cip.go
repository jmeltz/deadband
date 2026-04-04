package discover

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

const (
	eipCommandListIdentity uint16 = 0x0063
	eipHeaderSize                 = 24
	cipItemTypeIdentity    uint16 = 0x000C
	cipSocketAddrSize             = 16
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

// vendorNames maps CIP vendor IDs to canonical vendor names.
var vendorNames = map[uint16]string{
	1:   "Rockwell Automation",
	2:   "Neles (Metso)",
	5:   "ODVA",
	40:  "ABB",
	56:  "Molex",
	90:  "Turck",
	266: "Schneider Electric",
	283: "Siemens",
	671: "Honeywell",
}

// buildListIdentityRequest returns a 24-byte EIP ListIdentity request.
func buildListIdentityRequest() []byte {
	buf := make([]byte, eipHeaderSize)
	binary.LittleEndian.PutUint16(buf[0:2], eipCommandListIdentity)
	// length, session, status, sender_context, options all remain zero
	return buf
}

// parseListIdentityResponse parses an EIP ListIdentity response into a CIPIdentity.
func parseListIdentityResponse(data []byte) (*CIPIdentity, error) {
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

	return parseListIdentityResponse(buf[:n])
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
		id, parseErr := parseListIdentityResponse(buf[:n])
		if parseErr != nil {
			continue
		}
		results[remote.IP.String()] = id
	}

	return results, nil
}

// identityToDevice converts a CIPIdentity to an inventory.Device.
func identityToDevice(ip string, id *CIPIdentity) inventory.Device {
	vendor, ok := vendorNames[id.VendorID]
	if !ok {
		vendor = fmt.Sprintf("Vendor(%d)", id.VendorID)
	}

	return inventory.Device{
		IP:       ip,
		Vendor:   vendor,
		Model:    id.ProductName,
		Firmware: fmt.Sprintf("%d.%03d", id.RevMajor, id.RevMinor),
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
		devices = append(devices, identityToDevice(ip, id))
	}
	return devices
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
