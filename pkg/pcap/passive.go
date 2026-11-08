package pcap

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/inventory"
)

// AnalyzeResult holds the output of passive pcap analysis.
type AnalyzeResult struct {
	Devices   []inventory.Device
	PacketsIn int
	Parsed    int
	Errors    int
}

// Analyze reads a pcap file, extracts ICS protocol responses, and returns
// discovered devices. No network traffic is generated — fully passive.
func Analyze(path string, progress func(string)) (*AnalyzeResult, error) {
	reader, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	switch reader.LinkType() {
	case 0, 1, 101, 108, 228:
	default:
		return nil, fmt.Errorf("unsupported link type %d (Ethernet, IPv4 raw and loopback supported)", reader.LinkType())
	}

	seen := make(map[string]inventory.Device)
	var order []string
	result := &AnalyzeResult{}

	for {
		pkt, err := reader.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Errors++
			continue
		}
		result.PacketsIn++

		frame, err := DemuxLink(reader.LinkType(), pkt.Data)
		if err != nil {
			continue // skip non-IP, non-TCP/UDP
		}

		if dev := tryParseProtocol(frame); dev != nil {
			key := passiveDeviceKey(*dev)
			if prev, exists := seen[key]; !exists {
				seen[key] = *dev
				order = append(order, key)
				result.Parsed++
				if progress != nil {
					progress(fmt.Sprintf("Found %s %s (fw %s) via %s", dev.IP, dev.Model, dev.Firmware, dev.Vendor))
				}
			} else {
				seen[key] = mergePassiveDevice(prev, *dev)
			}
		}
	}

	result.Devices = make([]inventory.Device, 0, len(order))
	for _, k := range order {
		result.Devices = append(result.Devices, seen[k])
	}

	if progress != nil {
		progress(fmt.Sprintf("Processed %d packets, found %d devices (%d errors)", result.PacketsIn, len(result.Devices), result.Errors))
	}

	return result, nil
}

func passiveDeviceKey(d inventory.Device) string {
	if path := d.Extra["component_path"]; d.Protocol == "bacnet" && path != "" {
		return d.IP + "#" + path
	}
	if d.Protocol == "bacnet" && d.Extra != nil && d.Extra["device_instance"] != "" {
		return d.IP + "#bacnet:" + d.Extra["device_instance"]
	}
	return d.IP
}

func isPassivePlaceholderVendor(v string) bool {
	return v == "" || v == "Unknown" || strings.HasPrefix(v, "Vendor(") || strings.HasPrefix(v, "Vendor ")
}

func isPassivePlaceholderModel(m string) bool {
	return m == "" || strings.HasPrefix(m, "BACnet Device #") || m == "TwinCAT System" || m == "TwinCAT ADS Router"
}

func mergePassiveDevice(base, incoming inventory.Device) inventory.Device {
	if isPassivePlaceholderVendor(base.Vendor) && !isPassivePlaceholderVendor(incoming.Vendor) {
		base.Vendor = incoming.Vendor
	}
	if isPassivePlaceholderModel(base.Model) && incoming.Model != "" && !isPassivePlaceholderModel(incoming.Model) {
		base.Model = incoming.Model
	} else if base.Model == "" && incoming.Model != "" {
		base.Model = incoming.Model
	}
	if base.Firmware == "" && incoming.Firmware != "" {
		base.Firmware = incoming.Firmware
	}
	if base.Hostname == "" && incoming.Hostname != "" {
		base.Hostname = incoming.Hostname
	}
	if base.Serial == "" {
		base.Serial = incoming.Serial
	}
	if base.MAC == "" {
		base.MAC = incoming.MAC
	}
	if base.OrderNum == "" {
		base.OrderNum = incoming.OrderNum
	}
	if len(incoming.Extra) > 0 {
		if base.Extra == nil {
			base.Extra = make(map[string]string, len(incoming.Extra))
		}
		for k, v := range incoming.Extra {
			if base.Extra[k] == "" && v != "" {
				base.Extra[k] = v
			}
		}
	}
	return base
}

// tryParseProtocol attempts to parse the frame payload as an ICS protocol response.
// Returns nil if the payload doesn't match any known protocol.
func tryParseProtocol(f *Frame) *inventory.Device {
	if len(f.Payload) == 0 {
		return nil
	}
	srcIP := f.SrcIP.String()

	// Dispatch based on source port (response from device)
	switch int(f.SrcPort) {
	case discover.EIPPort:
		return tryCIP(srcIP, f.Payload)
	case discover.S7Port:
		return tryS7(srcIP, f.Payload)
	case discover.ModbusTCPPort:
		return tryModbus(srcIP, f.Payload)
	case discover.SLMPPort:
		return trySLMP(srcIP, f.Payload)
	case discover.BACnetPort:
		return tryBACnet(srcIP, f.Payload)
	case discover.FINSPort:
		return tryFINS(srcIP, f.Payload)
	case discover.SRTPPort:
		return trySRTP(srcIP, f.Payload)
	case discover.ADSPort:
		return tryADSTCP(srcIP, f.Payload)
	case discover.ADSUDPPort:
		return tryADSUDP(srcIP, f.Payload)
	case discover.SICKPortA, discover.SICKPortB, discover.SICKPortCoLa2:
		return trySICK(srcIP, int(f.SrcPort), f.Payload)
	case discover.OPCUAPort:
		return discover.ParseOPCUAResponseFrame(srcIP, f.Payload)
	case discover.FoxPort:
		return tryFox(srcIP, int(f.SrcPort), f.Payload)
	}

	// Also check destination port for broadcast/multicast/ephemeral-source UDP responses
	switch int(f.DstPort) {
	case discover.EIPPort:
		return tryCIP(srcIP, f.Payload)
	case discover.BACnetPort:
		return tryBACnet(srcIP, f.Payload)
	case discover.ADSUDPPort:
		return tryADSUDP(srcIP, f.Payload)
	}

	return nil
}

func tryCIP(ip string, data []byte) *inventory.Device {
	id, err := discover.ParseListIdentityResponse(data)
	if err != nil || id == nil {
		return nil
	}
	dev := discover.CIPIdentityToDevice(ip, id)
	if dev.Model == "" {
		return nil
	}
	return &dev
}

func tryS7(ip string, data []byte) *inventory.Device {
	// ParseSZLResponse owns TPKT/COTP framing; do not strip it twice.
	id, err := discover.ParseSZLResponse(data)
	if err != nil || id == nil {
		return nil
	}
	dev := discover.S7IdentityToDevice(ip, id)
	if dev.Model == "" {
		return nil
	}
	return &dev
}

func tryModbus(ip string, data []byte) *inventory.Device {
	_, _, pdu, err := discover.ParseMBAPHeader(data)
	if err != nil || len(pdu) < 6 {
		return nil
	}
	objects, _, _, err := discover.ParseReadDeviceIDResponse(pdu)
	if err != nil || len(objects) == 0 {
		return nil
	}
	id := &discover.ModbusIdentity{
		VendorName:  objects[0],
		ProductCode: objects[1],
		Revision:    objects[2],
		ProductName: objects[4],
		ModelName:   objects[5],
	}
	dev := discover.ModbusIdentityToDevice(ip, id)
	if dev.Model == "" {
		return nil
	}
	return &dev
}

func trySLMP(ip string, data []byte) *inventory.Device {
	endCode, payload, err := discover.ParseSLMPResponse(data)
	if err != nil || endCode != 0 || len(payload) == 0 {
		return nil
	}
	id, err := discover.ParseReadTypeNameResponse(payload)
	if err != nil || id == nil {
		return nil
	}
	dev := discover.SLMPIdentityToDevice(ip, id)
	if dev.Model == "" {
		return nil
	}
	return &dev
}

func tryBACnet(ip string, data []byte) *inventory.Device {
	_, bvlcPayload, err := discover.ParseBVLC(data)
	if err != nil || len(bvlcPayload) < 3 {
		return nil
	}
	apdu, srcNet, srcAddr, err := discover.ParseBACnetNPDU(bvlcPayload)
	if err != nil || len(apdu) < 2 {
		return nil
	}

	if deviceInstance, vendorID, err := discover.ParseIAmResponse(apdu); err == nil {
		id := &discover.BACnetIdentity{
			DeviceInstance: deviceInstance,
			VendorID:       vendorID,
			VendorName:     discover.BACnetVendorName(vendorID),
			SourceNet:      srcNet,
			SourceAddr:     srcAddr,
		}
		dev := discover.BACnetIdentityToDevice(ip, id)
		if dev.Model == "" {
			return nil
		}
		return &dev
	}

	if _, deviceInstance, propID, val, err := discover.ParseReadPropertyAck(apdu); err == nil && val != "" {
		id := &discover.BACnetIdentity{
			DeviceInstance: deviceInstance,
			SourceNet:      srcNet,
			SourceAddr:     srcAddr,
		}
		switch propID {
		case 70: // Model_Name
			id.ModelName = val
		case 44: // Firmware_Revision
			id.FirmwareRevision = val
		case 12: // Application_Software_Version remains separate evidence.
			id.ApplicationSoftwareVersion = val
		case 121: // Vendor_Name
			id.VendorName = val
		case 77: // Object_Name
			id.ObjectName = val
		case 58: // Location
			id.Location = val
		default:
			return nil
		}
		dev := discover.BACnetIdentityToDevice(ip, id)
		if id.VendorName == "" {
			dev.Vendor = "Unknown"
		}
		if dev.Extra == nil {
			dev.Extra = make(map[string]string)
		}
		dev.Extra["device_instance"] = strconv.FormatUint(uint64(deviceInstance), 10)
		return &dev
	}

	return nil
}

func tryADSTCP(ip string, data []byte) *inventory.Device {
	id, err := discover.ParseADSReadDeviceInfoFrame(data)
	if err != nil || id == nil {
		return nil
	}
	dev := discover.ADSIdentityToDevice(ip, discover.ADSPort, id)
	return &dev
}

func tryADSUDP(ip string, data []byte) *inventory.Device {
	id, meta, err := discover.ParseADSUDPDiscoveryResponse(data)
	if err != nil || id == nil {
		return nil
	}
	dev := discover.ADSIdentityToDevice(ip, discover.ADSUDPPort, id)
	if h := meta["hostname"]; h != "" {
		dev.Hostname = h
	}
	if osStr := meta["os"]; osStr != "" {
		if dev.Extra == nil {
			dev.Extra = make(map[string]string)
		}
		dev.Extra["os"] = osStr
	}
	return &dev
}

func trySICK(ip string, port int, data []byte) *inventory.Device {
	id, err := discover.ParseSICKCoLaFrame(data, port)
	if err != nil || id == nil || id.Model == "" {
		return nil
	}
	return &inventory.Device{
		IP:       ip,
		Vendor:   "SICK",
		Model:    id.Model,
		Firmware: id.Firmware,
		Protocol: "sick-cola",
		Port:     port,
	}
}

func tryFox(ip string, port int, data []byte) *inventory.Device {
	id, err := discover.ParseFoxHello(string(data))
	if err != nil || id == nil {
		return nil
	}
	// Distinguish Niagara station greeting from minimal client hello request
	if id.AppVersion == "" && id.BrandID == "" && id.StationName == "" {
		return nil
	}
	dev := discover.FoxIdentityToDevice(ip, port, false, id)
	return &dev
}

func tryFINS(ip string, data []byte) *inventory.Device {
	// FINS Controller Data Read response: MRC=05, SRC=01
	_, payload, err := discover.ParseFINSResponse(data, 0x05, 0x01)
	if err != nil || len(payload) == 0 {
		return nil
	}
	id, err := discover.ParseControllerDataRead(payload)
	if err != nil || id == nil {
		return nil
	}
	dev := discover.FINSIdentityToDevice(ip, id)
	if dev.Model == "" {
		return nil
	}
	return &dev
}

func trySRTP(ip string, data []byte) *inventory.Device {
	payload, err := discover.ParseSRTPServiceResponse(data)
	if err != nil || len(payload) == 0 {
		return nil
	}
	id := discover.ParseControllerTypeData(payload)
	if id == nil {
		return nil
	}
	dev := discover.SRTPIdentityToDevice(ip, id)
	if dev.Model == "" {
		return nil
	}
	return &dev
}
