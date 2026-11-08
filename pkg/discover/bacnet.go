package discover

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// BACnet/IP protocol constants (ASHRAE 135)
const (
	// BVLC
	bvlcTypeBACnetIP  = 0x81
	bvlcForwardedNPDU = 0x04
	bvlcOrigUnicast   = 0x0A
	bvlcOrigBroadcast = 0x0B

	// NPDU
	npduVersion     = 0x01
	npduExpectReply = 0x04
	npduNoExpect    = 0x00
	npduHasDest     = 0x20
	npduHasSrc      = 0x08
	npduNetLayerMsg = 0x80

	// APDU PDU types (upper 4 bits of first byte)
	apduConfirmedReq   = 0x00
	apduUnconfirmedReq = 0x10
	apduComplexAck     = 0x30
	apduError          = 0x50
	apduReject         = 0x60
	apduAbort          = 0x70

	// Service choices
	svcIAm          = 0x00
	svcWhoIs        = 0x08
	svcReadProperty = 0x0C

	// BACnet application tag numbers
	tagUnsigned   = 2
	tagCharString = 7
	tagEnumerated = 9
	tagObjectID   = 12

	// BACnet object types
	objTypeDevice = 8

	// Property IDs
	propAppSoftwareVersion = 12
	propFirmwareRevision   = 44
	propLocation           = 58
	propModelName          = 70
	propObjectName         = 77
	propVendorIdentifier   = 120
	propVendorName         = 121

	maxRoutedBACnetDevicesPerIP = 64
)

// BACnetIdentity holds parsed identity from BACnet Who-Is/ReadProperty responses.
type BACnetIdentity struct {
	VendorID                   uint16
	VendorName                 string
	ModelName                  string
	FirmwareRevision           string
	ApplicationSoftwareVersion string
	ObjectName                 string
	Location                   string
	DeviceInstance             uint32
	SourceNet                  uint16
	SourceAddr                 []byte
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

// buildReadPropertyRequest builds a direct (non-routed) BACnet/IP ReadProperty confirmed request.
func buildReadPropertyRequest(invokeID byte, deviceInstance uint32, propertyID uint8) []byte {
	return buildRoutedReadPropertyRequest(invokeID, deviceInstance, propertyID, 0, nil)
}

// buildRoutedReadPropertyRequest builds a BACnet/IP ReadProperty confirmed request,
// optionally adding DNET/DLEN/DADR/HopCount when querying a routed MS/TP controller.
func buildRoutedReadPropertyRequest(invokeID byte, deviceInstance uint32, propertyID uint8, dstNet uint16, dstAddr []byte) []byte {
	var npdu []byte
	if dstNet > 0 && len(dstAddr) > 0 {
		npdu = make([]byte, 0, 6+len(dstAddr))
		npdu = append(npdu, npduVersion, npduHasDest|npduExpectReply)
		npdu = append(npdu, byte(dstNet>>8), byte(dstNet), byte(len(dstAddr)))
		npdu = append(npdu, dstAddr...)
		npdu = append(npdu, 0xFF) // Hop Count
	} else {
		npdu = []byte{npduVersion, npduExpectReply}
	}

	// Confirmed Request APDU header
	apdu := []byte{
		apduConfirmedReq, // PDU type: Confirmed-Request, no segmentation
		0x05,             // Max segments=unspecified, Max APDU=1476
		invokeID,         // Invoke ID
		svcReadProperty,  // Service: ReadProperty
	}

	// Context tag 0: Object Identifier (4 bytes) — Device object
	objectID := make([]byte, 4)
	binary.BigEndian.PutUint32(objectID, (objTypeDevice<<22)|(deviceInstance&0x003FFFFF))
	apdu = append(apdu, 0x0C) // Context tag 0, length 4
	apdu = append(apdu, objectID...)

	// Context tag 1: Property Identifier (1 byte)
	apdu = append(apdu, 0x19) // Context tag 1, length 1
	apdu = append(apdu, propertyID)

	payload := append(npdu, apdu...)
	return buildBVLC(bvlcOrigUnicast, payload)
}

// --- Parsers ---

// ParseBVLC validates the BVLC header and returns the function code and NPDU payload.
// Handles Forwarded-NPDU (0x04), which carries a 6-byte originating IPv4:port prefix.
func ParseBVLC(data []byte) (function byte, payload []byte, err error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("BVLC too short: %d bytes", len(data))
	}
	if data[0] != bvlcTypeBACnetIP {
		return 0, nil, fmt.Errorf("BVLC type 0x%02X, want 0x%02X", data[0], bvlcTypeBACnetIP)
	}
	function = data[1]
	length := binary.BigEndian.Uint16(data[2:4])
	if length < 4 || int(length) > len(data) {
		return 0, nil, fmt.Errorf("BVLC length %d invalid for data %d", length, len(data))
	}
	if function == bvlcForwardedNPDU {
		if length < 10 {
			return 0, nil, fmt.Errorf("Forwarded-NPDU BVLC too short: %d", length)
		}
		return function, data[10:length], nil
	}
	return function, data[4:length], nil
}

// ParseBACnetNPDU strips a variable-length ASHRAE 135 Clause 6.2.2 NPDU header
// (handling broadcast DNET=0xFFFF, routed DNET/DADR, SNET/SADR, and HopCount)
// and returns the APDU slice along with optional source network routing info.
func ParseBACnetNPDU(npdu []byte) (apdu []byte, srcNet uint16, srcAddr []byte, err error) {
	if len(npdu) < 2 {
		return nil, 0, nil, fmt.Errorf("NPDU too short: %d bytes", len(npdu))
	}
	if npdu[0] != npduVersion {
		return nil, 0, nil, fmt.Errorf("NPDU version 0x%02X, want 0x%02X", npdu[0], npduVersion)
	}
	ctrl := npdu[1]
	if ctrl&npduNetLayerMsg != 0 {
		return nil, 0, nil, fmt.Errorf("NPDU network-layer message carries no APDU")
	}

	off := 2
	if ctrl&npduHasDest != 0 {
		if off+3 > len(npdu) {
			return nil, 0, nil, fmt.Errorf("NPDU destination specifier truncated")
		}
		dlen := int(npdu[off+2])
		off += 3 + dlen
	}
	if ctrl&npduHasSrc != 0 {
		if off+3 > len(npdu) {
			return nil, 0, nil, fmt.Errorf("NPDU source specifier truncated")
		}
		srcNet = binary.BigEndian.Uint16(npdu[off : off+2])
		slen := int(npdu[off+2])
		if off+3+slen > len(npdu) {
			return nil, 0, nil, fmt.Errorf("NPDU SADR truncated")
		}
		if slen > 0 {
			srcAddr = append([]byte(nil), npdu[off+3:off+3+slen]...)
		}
		off += 3 + slen
	}
	if ctrl&npduHasDest != 0 {
		if off+1 > len(npdu) {
			return nil, 0, nil, fmt.Errorf("NPDU hop count truncated")
		}
		off++ // Hop Count follows SADR when destination specifier bit is set
	}
	if off >= len(npdu) {
		return nil, 0, nil, fmt.Errorf("NPDU contains empty APDU")
	}
	return npdu[off:], srcNet, srcAddr, nil
}

// ParseIAmResponse parses an I-Am unconfirmed response from the APDU payload.
// Returns the device instance and vendor ID.
func ParseIAmResponse(apdu []byte) (deviceInstance uint32, vendorID uint16, err error) {
	if len(apdu) < 2 {
		return 0, 0, fmt.Errorf("APDU too short for I-Am")
	}
	if apdu[0] != apduUnconfirmedReq || apdu[1] != svcIAm {
		return 0, 0, fmt.Errorf("not an I-Am response: PDU=0x%02X svc=0x%02X", apdu[0], apdu[1])
	}

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
		return deviceInstance, 0, nil
	}
	tag = apdu[offset]
	tagLen = int(tag & 0x07)
	offset += 1 + tagLen

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
		return deviceInstance, 0, nil
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

// ParseReadPropertyAck parses a Complex-Ack ReadProperty APDU and returns
// the invoke ID, device instance, property ID, and decoded string value.
func ParseReadPropertyAck(apdu []byte) (invokeID byte, deviceInstance uint32, propID uint8, val string, err error) {
	if len(apdu) < 3 {
		return 0, 0, 0, "", fmt.Errorf("APDU too short for Complex-Ack")
	}
	pduType := apdu[0] & 0xF0
	if pduType == apduError || pduType == apduReject || pduType == apduAbort {
		return apdu[1], 0, 0, "", fmt.Errorf("BACnet error/reject/abort PDU 0x%02X", pduType)
	}
	if pduType != apduComplexAck {
		return 0, 0, 0, "", fmt.Errorf("PDU type 0x%02X, want Complex-Ack (0x%02X)", pduType, apduComplexAck)
	}

	// Handle segmented Complex-Ack header (2 extra bytes: sequence number + window size)
	hdrLen := 3
	if apdu[0]&0x08 != 0 {
		hdrLen = 5
	}
	if len(apdu) < hdrLen {
		return 0, 0, 0, "", fmt.Errorf("segmented Complex-Ack truncated")
	}
	invokeID = apdu[1]
	if apdu[hdrLen-1] != svcReadProperty {
		return invokeID, 0, 0, "", fmt.Errorf("service 0x%02X, want ReadProperty", apdu[hdrLen-1])
	}

	offset := hdrLen
	// Context tag 0: Object Identifier
	if offset+5 <= len(apdu) && (apdu[offset]&0xF8) == 0x08 && (apdu[offset]&0x07) == 4 {
		rawObj := binary.BigEndian.Uint32(apdu[offset+1 : offset+5])
		deviceInstance = rawObj & 0x003FFFFF
		offset += 5
	}
	// Context tag 1: Property Identifier
	if offset < len(apdu) && (apdu[offset]&0xF8) == 0x18 {
		pLen := int(apdu[offset] & 0x07)
		if offset+1+pLen <= len(apdu) && pLen >= 1 {
			propID = apdu[offset+pLen]
			offset += 1 + pLen
		}
	}
	// Optional Context tag 2: Property Array Index
	if offset < len(apdu) && (apdu[offset]&0xF8) == 0x28 {
		aLen := int(apdu[offset] & 0x07)
		offset += 1 + aLen
	}

	// Context tag 3 opening (0x3E) and closing (0x3F)
	if offset >= len(apdu) || apdu[offset] != 0x3E {
		return invokeID, deviceInstance, propID, "", fmt.Errorf("missing property value opening tag")
	}
	offset++

	closeIdx := -1
	for i := len(apdu) - 1; i >= offset; i-- {
		if apdu[i] == 0x3F {
			closeIdx = i
			break
		}
	}
	if closeIdx < 0 {
		return invokeID, deviceInstance, propID, "", fmt.Errorf("missing property value closing tag")
	}

	v, err := parseApplicationValue(apdu[offset:closeIdx])
	return invokeID, deviceInstance, propID, v, err
}

// parseReadPropertyResponse parses a full BVLC+NPDU+Complex-Ack ReadProperty packet.
func parseReadPropertyResponse(data []byte) (string, error) {
	_, npdu, err := ParseBVLC(data)
	if err != nil {
		return "", err
	}
	apdu, _, _, err := ParseBACnetNPDU(npdu)
	if err != nil {
		return "", err
	}
	_, _, _, val, err := ParseReadPropertyAck(apdu)
	return val, err
}

// parseApplicationValue extracts a value from a BACnet application-tagged field.
func parseApplicationValue(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("application value too short")
	}

	tag := data[0]
	tagNum := (tag >> 4) & 0x0F
	length := int(tag & 0x07)

	// Handle extended BACnet length encoding (lvt == 5)
	if length == 5 {
		if len(data) < 2 {
			return "", fmt.Errorf("extended length truncated")
		}
		if data[1] == 254 {
			if len(data) < 4 {
				return "", fmt.Errorf("16-bit extended length truncated")
			}
			length = int(binary.BigEndian.Uint16(data[2:4]))
			data = data[4:]
		} else {
			length = int(data[1])
			data = data[2:]
		}
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
		encoding := data[0]
		raw := data[1:length]
		if encoding == 4 && len(raw)%2 == 0 {
			// UCS-2 / UTF-16BE
			var sb strings.Builder
			for i := 0; i+1 < len(raw); i += 2 {
				r := rune(binary.BigEndian.Uint16(raw[i : i+2]))
				if r != 0 {
					sb.WriteRune(r)
				}
			}
			return sb.String(), nil
		}
		return strings.TrimRight(string(raw), "\x00"), nil
	case tagUnsigned:
		switch length {
		case 1:
			return fmt.Sprintf("%d", data[0]), nil
		case 2:
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(data[:2])), nil
		case 3:
			return fmt.Sprintf("%d", uint32(data[0])<<16|uint32(data[1])<<8|uint32(data[2])), nil
		case 4:
			return fmt.Sprintf("%d", binary.BigEndian.Uint32(data[:4])), nil
		}
	}

	return fmt.Sprintf("(tag%d:%x)", tagNum, data[:length]), nil
}

// --- Vendor ID mapping (Official ASHRAE SSPC 135 Registry) ---

var bacnetVendorMap = map[uint16]string{
	2:    "Trane",               // The Trane Company
	3:    "Daikin",              // McQuay International (Daikin Applied)
	5:    "Johnson Controls",    // Johnson Controls, Inc.
	6:    "ABB",                 // American Auto-Matrix / ABB Cylon
	7:    "Siemens",             // Siemens Schweiz AG (Landis & Staefa)
	8:    "Delta Controls",      // Delta Controls Inc.
	9:    "Siemens",             // Siemens Schweiz AG
	10:   "Schneider Electric",  // Schneider Electric (Tour & Andover Controls)
	16:   "Carrier",             // United Technologies Carrier
	17:   "Honeywell",           // Honeywell Inc.
	18:   "Honeywell",           // Alerton / Honeywell
	24:   "Automated Logic",     // Automated Logic Corporation
	28:   "KMC Controls",        // KMC Controls, Inc.
	35:   "Reliable Controls",   // Reliable Controls Corporation
	36:   "Tridium",             // Tridium Inc. (Niagara)
	39:   "Kieback & Peter",     // Kieback & Peter GmbH & Co. KG
	53:   "Daikin",              // Daikin Industries Ltd.
	56:   "Vertiv",              // Liebert Corporation (Vertiv)
	77:   "CAREL",               // CAREL Industries S.p.A.
	80:   "SAUTER",              // Fr. Sauter AG
	82:   "Mitsubishi Electric", // Mitsubishi Electric Corp. (Inazawa)
	105:  "Priva",               // PRIVA B.V.
	113:  "Vertiv",              // Vertiv (formerly Emerson Network Power)
	178:  "LOYTEC",              // LOYTEC electronics GmbH
	190:  "Danfoss",             // Danfoss Drives A/S
	222:  "WAGO",                // WAGO Kontakttechnik GmbH & Co. KG
	332:  "Distech Controls",    // Distech Controls SAS
	333:  "Honeywell",           // Novar / Honeywell
	335:  "Schneider Electric",  // Schneider Electric
	364:  "Distech Controls",    // Distech Controls Inc.
	415:  "Beckhoff",            // Beckhoff Automation GmbH & Co. KG
	423:  "Belimo",              // BELIMO Automation AG
	434:  "Mitsubishi Electric", // Mitsubishi Electric Corp. (Nagoya)
	781:  "Mitsubishi Electric", // Mitsubishi Electric Australia
	1193: "Copeland",            // Copeland LP
}

// BACnetVendorName maps an ASHRAE BACnet Vendor ID to Deadband's canonical vendor name.
func BACnetVendorName(vendorID uint16) string {
	if name, ok := bacnetVendorMap[vendorID]; ok {
		return name
	}
	return fmt.Sprintf("BACnet Vendor %d", vendorID)
}

// --- Scanner ---

func readPropertyValue(conn net.Conn, buf []byte, invokeID byte, deviceInstance uint32, propID uint8, dstNet uint16, dstAddr []byte, timeout time.Duration) (string, bool) {
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	req := buildRoutedReadPropertyRequest(invokeID, deviceInstance, propID, dstNet, dstAddr)
	if _, err := conn.Write(req); err != nil {
		return "", false
	}

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return "", false
		}
		_, npdu, err := ParseBVLC(buf[:n])
		if err != nil {
			continue
		}
		apdu, _, _, err := ParseBACnetNPDU(npdu)
		if err != nil {
			continue
		}
		// Ignore late unconfirmed I-Am packets while awaiting Confirmed-Request Ack
		if len(apdu) >= 1 && (apdu[0]&0xF0) == apduUnconfirmedReq {
			continue
		}
		gotInvoke, _, _, val, err := ParseReadPropertyAck(apdu)
		if err != nil {
			if gotInvoke == invokeID {
				// Device explicitly returned Error/Reject/Abort for this property
				return "", false
			}
			continue
		}
		if gotInvoke == invokeID {
			return val, true
		}
	}
}

// BACnetIdentifyAllPort performs BACnet/IP identification against ip:port,
// collecting both the primary controller and any routed MS/TP devices behind a BACnet router.
func BACnetIdentifyAllPort(ip string, port int, timeout time.Duration) ([]BACnetIdentity, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	buf := make([]byte, 1500)

	// Phase 1: Send Who-Is and collect 1..N I-Am responses
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildWhoIsRequest()); err != nil {
		return nil, nil
	}

	var candidates []BACnetIdentity
	seenInstances := make(map[uint32]bool)

	for len(candidates) < maxRoutedBACnetDevicesPerIP {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		_, npdu, err := ParseBVLC(buf[:n])
		if err != nil {
			continue
		}
		apdu, srcNet, srcAddr, err := ParseBACnetNPDU(npdu)
		if err != nil {
			continue
		}
		deviceInstance, vendorID, err := ParseIAmResponse(apdu)
		if err != nil {
			continue
		}
		if !seenInstances[deviceInstance] {
			seenInstances[deviceInstance] = true
			candidates = append(candidates, BACnetIdentity{
				VendorID:       vendorID,
				VendorName:     BACnetVendorName(vendorID),
				DeviceInstance: deviceInstance,
				SourceNet:      srcNet,
				SourceAddr:     srcAddr,
			})
		}
		// Once the first responder replies, switch to a short burst drain window
		// to capture downstream MS/TP I-Am frames without stalling single controllers.
		if len(candidates) == 1 {
			drain := timeout / 5
			if drain < 40*time.Millisecond {
				drain = 40 * time.Millisecond
			}
			if drain > 150*time.Millisecond {
				drain = 150 * time.Millisecond
			}
			_ = conn.SetDeadline(time.Now().Add(drain))
		}
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	invokeSeq := byte(1)
	nextInvoke := func() byte {
		id := invokeSeq
		invokeSeq++
		if invokeSeq == 0 {
			invokeSeq = 1
		}
		return id
	}

	propTimeout := timeout
	if len(candidates) > 1 && propTimeout > 750*time.Millisecond {
		propTimeout = 750 * time.Millisecond
	}

	for i := range candidates {
		c := &candidates[i]

		// Phase 2: ReadProperty model-name (70)
		if val, ok := readPropertyValue(conn, buf, nextInvoke(), c.DeviceInstance, propModelName, c.SourceNet, c.SourceAddr, propTimeout); ok {
			c.ModelName = strings.TrimSpace(val)
		}

		// Preserve application software separately; it is not firmware evidence.
		if val, ok := readPropertyValue(conn, buf, nextInvoke(), c.DeviceInstance, propFirmwareRevision, c.SourceNet, c.SourceAddr, propTimeout); ok {
			c.FirmwareRevision = strings.TrimSpace(val)
		}
		if c.FirmwareRevision == "" {
			if val, ok := readPropertyValue(conn, buf, nextInvoke(), c.DeviceInstance, propAppSoftwareVersion, c.SourceNet, c.SourceAddr, propTimeout); ok {
				c.ApplicationSoftwareVersion = strings.TrimSpace(val)
			}
		}

		// Phase 4: ReadProperty vendor-name (121) if VendorID was unmapped
		if strings.HasPrefix(c.VendorName, "BACnet Vendor ") {
			if val, ok := readPropertyValue(conn, buf, nextInvoke(), c.DeviceInstance, propVendorName, c.SourceNet, c.SourceAddr, propTimeout); ok && strings.TrimSpace(val) != "" {
				c.VendorName = strings.TrimSpace(val)
			}
		}

		// Phase 5: ReadProperty object-name (77) + location (58)
		if val, ok := readPropertyValue(conn, buf, nextInvoke(), c.DeviceInstance, propObjectName, c.SourceNet, c.SourceAddr, propTimeout); ok {
			c.ObjectName = strings.TrimSpace(val)
		}
		if val, ok := readPropertyValue(conn, buf, nextInvoke(), c.DeviceInstance, propLocation, c.SourceNet, c.SourceAddr, propTimeout); ok {
			c.Location = strings.TrimSpace(val)
		}
	}

	return candidates, nil
}

// BACnetIdentifyAll queries standard UDP/47808 and returns all responding BACnet identities on that IP.
func BACnetIdentifyAll(ip string, timeout time.Duration) ([]BACnetIdentity, error) {
	return BACnetIdentifyAllPort(ip, BACnetPort, timeout)
}

// BACnetIdentify queries a single IP on UDP/47808 and returns the primary responder.
func BACnetIdentify(ip string, timeout time.Duration) (*BACnetIdentity, error) {
	all, err := BACnetIdentifyAll(ip, timeout)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	first := all[0]
	return &first, nil
}

// BACnetIdentityToDevice converts a BACnetIdentity to an inventory.Device.
func BACnetIdentityToDevice(ip string, id *BACnetIdentity) inventory.Device {
	model := strings.TrimSpace(id.ModelName)
	if model == "" {
		model = fmt.Sprintf("BACnet Device #%d", id.DeviceInstance)
	}
	extra := map[string]string{
		"device_instance": strconv.FormatUint(uint64(id.DeviceInstance), 10),
		"component_kind":  "routed_device",
		"component_path":  fmt.Sprintf("bacnet/device/%d", id.DeviceInstance),
	}
	if id.FirmwareRevision != "" {
		extra["version_kind"] = "bacnet_firmware_revision"
	}
	if id.ApplicationSoftwareVersion != "" {
		extra["application_software_version"] = id.ApplicationSoftwareVersion
	}
	if id.Location != "" {
		extra["location"] = id.Location
	}
	if id.SourceNet > 0 {
		extra["bacnet_snet"] = strconv.FormatUint(uint64(id.SourceNet), 10)
		extra["source_network"] = extra["bacnet_snet"]
		if len(id.SourceAddr) > 0 {
			extra["bacnet_sadr"] = hex.EncodeToString(id.SourceAddr)
			extra["source_address_hex"] = extra["bacnet_sadr"]
			extra["component_path"] += fmt.Sprintf("/net/%d/addr/%s", id.SourceNet, extra["bacnet_sadr"])
		}
	}
	return inventory.Device{
		IP:       ip,
		Vendor:   id.VendorName,
		Model:    model,
		Firmware: id.FirmwareRevision,
		Hostname: id.ObjectName,
		Protocol: "bacnet",
		Port:     BACnetPort,
		Extra:    extra,
	}
}

// discoverBACnet performs BACnet/IP device identification across a set of IPs.
// Sends Who-Is (UDP) to each IP directly — collecting both direct and MS/TP-routed devices.
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

			ids, err := BACnetIdentifyAll(ip, timeout)
			if err != nil || len(ids) == 0 {
				return
			}

			mu.Lock()
			for i := range ids {
				devices = append(devices, BACnetIdentityToDevice(ip, &ids[i]))
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	if progress != nil {
		progress(fmt.Sprintf("BACnet/IP identified %d devices", len(devices)))
	}

	return devices
}
