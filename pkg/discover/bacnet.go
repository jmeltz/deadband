package discover

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// BACnet/IP protocol constants
const (
	// BVLC
	bvlcTypeBACnetIP  = 0x81
	bvlcOrigUnicast   = 0x0A
	bvlcOrigBroadcast = 0x0B

	// NPDU
	npduVersion      = 0x01
	npduExpectReply  = 0x04
	npduNoExpect     = 0x00

	// APDU PDU types (upper 4 bits of first byte)
	apduConfirmedReq   = 0x00
	apduUnconfirmedReq = 0x10
	apduComplexAck     = 0x30
	apduError          = 0x50

	// Service choices
	svcIAm          = 0x00
	svcWhoIs        = 0x08
	svcReadProperty = 0x0C

	// BACnet application tag numbers
	tagUnsigned    = 2
	tagCharString  = 7
	tagEnumerated  = 9
	tagObjectID    = 12

	// BACnet object types
	objTypeDevice = 8

	// Property IDs
	propFirmwareRevision = 44
	propModelName        = 70
	propVendorIdentifier = 120
	propVendorName       = 121
)

// BACnetIdentity holds parsed identity from BACnet Who-Is/ReadProperty responses.
type BACnetIdentity struct {
	VendorID         uint16
	VendorName       string
	ModelName        string
	FirmwareRevision string
	DeviceInstance   uint32
}

// --- Frame builders ---

// buildBVLC wraps a payload with the 4-byte BVLC header.
func buildBVLC(function byte, payload []byte) []byte {
	length := 4 + len(payload)
	buf := make([]byte, length)
	buf[0] = bvlcTypeBACnetIP
	buf[1] = function
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	copy(buf[4:], payload)
	return buf
}

// buildWhoIsRequest builds a BACnet/IP Who-Is request (unicast, no range limits).
func buildWhoIsRequest() []byte {
	npdu := []byte{npduVersion, npduExpectReply}
	apdu := []byte{apduUnconfirmedReq, svcWhoIs}
	payload := append(npdu, apdu...)
	return buildBVLC(bvlcOrigUnicast, payload)
}

// buildReadPropertyRequest builds a BACnet/IP ReadProperty confirmed request.
func buildReadPropertyRequest(invokeID byte, deviceInstance uint32, propertyID uint8) []byte {
	npdu := []byte{npduVersion, npduExpectReply}

	// Confirmed Request APDU header
	apdu := []byte{
		apduConfirmedReq, // PDU type: Confirmed-Request, no segmentation
		0x05,             // Max segments=unspecified, Max APDU=1476
		invokeID,         // Invoke ID
		svcReadProperty,  // Service: ReadProperty
	}

	// Context tag 0: Object Identifier (4 bytes) — Device object
	objectID := make([]byte, 4)
	binary.BigEndian.PutUint32(objectID, (objTypeDevice<<22)|deviceInstance)
	apdu = append(apdu, 0x0C)          // Context tag 0, length 4
	apdu = append(apdu, objectID...)

	// Context tag 1: Property Identifier (1 byte)
	apdu = append(apdu, 0x19)        // Context tag 1, length 1
	apdu = append(apdu, propertyID)

	payload := append(npdu, apdu...)
	return buildBVLC(bvlcOrigUnicast, payload)
}

// --- Parsers ---

// parseBVLC validates the BVLC header and returns the function code and payload.
func parseBVLC(data []byte) (function byte, payload []byte, err error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("BVLC too short: %d bytes", len(data))
	}
	if data[0] != bvlcTypeBACnetIP {
		return 0, nil, fmt.Errorf("BVLC type 0x%02X, want 0x%02X", data[0], bvlcTypeBACnetIP)
	}
	function = data[1]
	length := binary.BigEndian.Uint16(data[2:4])
	if int(length) > len(data) {
		return 0, nil, fmt.Errorf("BVLC length %d exceeds data %d", length, len(data))
	}
	return function, data[4:length], nil
}

// parseIAmResponse parses an I-Am unconfirmed response from the APDU payload.
// Returns the device instance and vendor ID.
func parseIAmResponse(apdu []byte) (deviceInstance uint32, vendorID uint16, err error) {
	if len(apdu) < 2 {
		return 0, 0, fmt.Errorf("APDU too short for I-Am")
	}
	if apdu[0] != apduUnconfirmedReq || apdu[1] != svcIAm {
		return 0, 0, fmt.Errorf("not an I-Am response: PDU=0x%02X svc=0x%02X", apdu[0], apdu[1])
	}

	// Parse I-Am parameters using BACnet application tags
	offset := 2

	// Parameter 1: Object Identifier (application tag 12, 4 bytes)
	if offset >= len(apdu) {
		return 0, 0, fmt.Errorf("I-Am: missing object identifier")
	}
	tag := apdu[offset]
	tagNum := (tag >> 4) & 0x0F
	tagLen := int(tag & 0x07)

	if tagNum != tagObjectID || tagLen != 4 {
		return 0, 0, fmt.Errorf("I-Am: expected Object ID tag, got tag=%d len=%d", tagNum, tagLen)
	}
	offset++
	if offset+4 > len(apdu) {
		return 0, 0, fmt.Errorf("I-Am: object identifier truncated")
	}
	objID := binary.BigEndian.Uint32(apdu[offset : offset+4])
	objType := objID >> 22
	if objType != objTypeDevice {
		return 0, 0, fmt.Errorf("I-Am: object type %d, want %d (Device)", objType, objTypeDevice)
	}
	deviceInstance = objID & 0x003FFFFF
	offset += 4

	// Parameter 2: Max APDU Length Accepted (application tag 2, 1-4 bytes)
	if offset >= len(apdu) {
		return deviceInstance, 0, nil // partial parse OK
	}
	tag = apdu[offset]
	tagLen = int(tag & 0x07)
	offset += 1 + tagLen // skip tag + value

	// Parameter 3: Segmentation Supported (application tag 9, 1 byte)
	if offset >= len(apdu) {
		return deviceInstance, 0, nil
	}
	tag = apdu[offset]
	tagLen = int(tag & 0x07)
	offset += 1 + tagLen

	// Parameter 4: Vendor ID (application tag 2, 1-2 bytes)
	if offset >= len(apdu) {
		return deviceInstance, 0, nil
	}
	tag = apdu[offset]
	tagNum = (tag >> 4) & 0x0F
	tagLen = int(tag & 0x07)
	if tagNum != tagUnsigned {
		return deviceInstance, 0, nil // unexpected tag, skip
	}
	offset++
	if offset+tagLen > len(apdu) {
		return deviceInstance, 0, nil
	}
	switch tagLen {
	case 1:
		vendorID = uint16(apdu[offset])
	case 2:
		vendorID = binary.BigEndian.Uint16(apdu[offset : offset+2])
	}

	return deviceInstance, vendorID, nil
}

// parseReadPropertyResponse parses a Complex-Ack ReadProperty response.
// Returns the string value for CharacterString properties, or raw bytes description.
func parseReadPropertyResponse(data []byte) (string, error) {
	_, payload, err := parseBVLC(data)
	if err != nil {
		return "", err
	}
	if len(payload) < 2 {
		return "", fmt.Errorf("NPDU too short")
	}

	// Skip NPDU header (2 bytes for simple case)
	apdu := payload[2:]
	if len(apdu) < 3 {
		return "", fmt.Errorf("APDU too short for Complex-Ack")
	}

	pduType := apdu[0] & 0xF0
	if pduType == apduError {
		return "", fmt.Errorf("BACnet error response")
	}
	if pduType != apduComplexAck {
		return "", fmt.Errorf("PDU type 0x%02X, want Complex-Ack (0x%02X)", pduType, apduComplexAck)
	}

	// apdu[1] = invoke ID, apdu[2] = service choice
	if apdu[2] != svcReadProperty {
		return "", fmt.Errorf("service 0x%02X, want ReadProperty", apdu[2])
	}

	// Parse tagged parameters to find context tag 3 (property value)
	offset := 3

	// Skip context tag 0 (Object Identifier)
	if offset < len(apdu) && (apdu[offset]&0x0F) == 0x0C { // context 0, len 4
		offset += 5
	}
	// Skip context tag 1 (Property Identifier)
	if offset < len(apdu) && (apdu[offset]&0xF8) == 0x18 { // context 1
		pLen := int(apdu[offset] & 0x07)
		offset += 1 + pLen
	}

	// Look for context tag 3 opening (0x3E) and closing (0x3F)
	if offset >= len(apdu) || apdu[offset] != 0x3E {
		return "", fmt.Errorf("missing property value opening tag")
	}
	offset++ // skip opening tag

	// Find closing tag to bound the value
	closeIdx := -1
	for i := offset; i < len(apdu); i++ {
		if apdu[i] == 0x3F {
			closeIdx = i
			break
		}
	}
	if closeIdx < 0 {
		return "", fmt.Errorf("missing property value closing tag")
	}

	valueData := apdu[offset:closeIdx]
	return parseApplicationValue(valueData)
}

// parseApplicationValue extracts a value from a BACnet application-tagged field.
func parseApplicationValue(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("application value too short")
	}

	tag := data[0]
	tagNum := (tag >> 4) & 0x0F
	length := int(tag & 0x07)

	// Handle extended length
	if length == 5 && len(data) > 1 {
		length = int(data[1])
		data = data[2:]
	} else {
		data = data[1:]
	}

	if len(data) < length {
		return "", fmt.Errorf("application value truncated")
	}

	switch tagNum {
	case tagCharString:
		if length < 1 {
			return "", nil
		}
		// First byte is encoding: 0 = ANSI/UTF-8
		return string(data[1:length]), nil
	case tagUnsigned:
		switch length {
		case 1:
			return fmt.Sprintf("%d", data[0]), nil
		case 2:
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(data[:2])), nil
		case 4:
			return fmt.Sprintf("%d", binary.BigEndian.Uint32(data[:4])), nil
		}
	}

	return fmt.Sprintf("(tag%d:%x)", tagNum, data[:length]), nil
}

// --- Vendor ID mapping ---

// bacnetVendorName maps a BACnet vendor ID to the canonical vendor name
// used in the CISA advisory database.
var bacnetVendorMap = map[uint16]string{
	5:   "Johnson Controls",
	15:  "Honeywell",
	24:  "Delta Controls",
	66:  "Trane",
	85:  "Carrier",
	95:  "Distech Controls",
	222: "Daikin",
	343: "Schneider Electric",
	404: "Siemens",
	555: "Automated Logic",
}

func bacnetVendorName(vendorID uint16) string {
	if name, ok := bacnetVendorMap[vendorID]; ok {
		return name
	}
	return fmt.Sprintf("BACnet Vendor %d", vendorID)
}

// --- Scanner ---

// BACnetIdentify performs BACnet/IP identification against a single IP.
// Sends Who-Is, waits for I-Am, then reads model-name and firmware-revision.
// Returns nil, nil if the host doesn't respond.
func BACnetIdentify(ip string, timeout time.Duration) (*BACnetIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", BACnetPort))

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	buf := make([]byte, 1500)

	// Phase 1: Who-Is → I-Am
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildWhoIsRequest()); err != nil {
		return nil, nil
	}

	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil
	}

	_, payload, err := parseBVLC(buf[:n])
	if err != nil {
		return nil, nil
	}
	if len(payload) < 4 {
		return nil, nil
	}

	// NPDU (2 bytes min) + APDU
	apdu := payload[2:]
	deviceInstance, vendorID, err := parseIAmResponse(apdu)
	if err != nil {
		return nil, nil
	}

	id := &BACnetIdentity{
		VendorID:       vendorID,
		VendorName:     bacnetVendorName(vendorID),
		DeviceInstance: deviceInstance,
	}

	// Phase 2: ReadProperty for model-name (property 70)
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildReadPropertyRequest(1, deviceInstance, propModelName)); err == nil {
		n, err = conn.Read(buf)
		if err == nil {
			if val, err := parseReadPropertyResponse(buf[:n]); err == nil {
				id.ModelName = val
			}
		}
	}

	// Phase 3: ReadProperty for firmware-revision (property 44)
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildReadPropertyRequest(2, deviceInstance, propFirmwareRevision)); err == nil {
		n, err = conn.Read(buf)
		if err == nil {
			if val, err := parseReadPropertyResponse(buf[:n]); err == nil {
				id.FirmwareRevision = val
			}
		}
	}

	return id, nil
}

// bacnetIdentityToDevice converts a BACnetIdentity to an inventory.Device.
func bacnetIdentityToDevice(ip string, id *BACnetIdentity) inventory.Device {
	return inventory.Device{
		IP:       ip,
		Vendor:   id.VendorName,
		Model:    id.ModelName,
		Firmware: id.FirmwareRevision,
	}
}

// discoverBACnet performs BACnet/IP device identification across a set of IPs.
// Sends Who-Is (UDP) to each IP directly — no TCP port pre-scan.
func discoverBACnet(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("BACnet/IP scanning %d hosts on UDP %d...", len(ips), BACnetPort))
	}

	var (
		mu      sync.Mutex
		devices []inventory.Device
	)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id, err := BACnetIdentify(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := bacnetIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	if progress != nil {
		progress(fmt.Sprintf("BACnet/IP identified %d devices", len(devices)))
	}

	return devices
}
