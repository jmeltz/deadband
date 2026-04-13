package pcap

import (
	"fmt"
	"io"

	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/inventory"
)

// AnalyzeResult holds the output of passive pcap analysis.
type AnalyzeResult struct {
	Devices    []inventory.Device
	PacketsIn  int
	Parsed     int
	Errors     int
}

// Analyze reads a pcap file, extracts ICS protocol responses, and returns
// discovered devices. No network traffic is generated — fully passive.
func Analyze(path string, progress func(string)) (*AnalyzeResult, error) {
	reader, err := Open(path)
	if err != nil {
		return nil, err
	}

	if reader.LinkType() != 1 {
		return nil, fmt.Errorf("unsupported link type %d (only Ethernet supported)", reader.LinkType())
	}

	seen := make(map[string]inventory.Device) // keyed by IP
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

		frame, err := DemuxEthernet(pkt.Data)
		if err != nil {
			continue // skip non-IP, non-TCP/UDP
		}

		if dev := tryParseProtocol(frame); dev != nil {
			key := dev.IP
			if _, exists := seen[key]; !exists {
				seen[key] = *dev
				result.Parsed++
				if progress != nil {
					progress(fmt.Sprintf("Found %s %s (fw %s) via %s", dev.IP, dev.Model, dev.Firmware, dev.Vendor))
				}
			}
		}
	}

	result.Devices = make([]inventory.Device, 0, len(seen))
	for _, d := range seen {
		result.Devices = append(result.Devices, d)
	}

	if progress != nil {
		progress(fmt.Sprintf("Processed %d packets, found %d devices (%d errors)", result.PacketsIn, len(result.Devices), result.Errors))
	}

	return result, nil
}

// tryParseProtocol attempts to parse the frame payload as an ICS protocol response.
// Returns nil if the payload doesn't match any known protocol.
func tryParseProtocol(f *Frame) *inventory.Device {
	if len(f.Payload) == 0 {
		return nil
	}
	srcIP := f.SrcIP.String()

	// Dispatch based on source port (response from device)
	switch f.SrcPort {
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
	}

	// Also check destination port for broadcast/multicast responses
	switch f.DstPort {
	case discover.EIPPort:
		return tryCIP(srcIP, f.Payload)
	case discover.BACnetPort:
		return tryBACnet(srcIP, f.Payload)
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
	// S7 over TPKT — strip TPKT header first
	tpktPayload, err := discover.ParseTPKT(data)
	if err != nil || len(tpktPayload) < 3 {
		return nil
	}
	// Skip COTP header (variable length, minimum 2 bytes: length + PDU type)
	cotpLen := int(tpktPayload[0]) + 1
	if cotpLen >= len(tpktPayload) {
		return nil
	}
	s7Data := tpktPayload[cotpLen:]
	id, err := discover.ParseSZLResponse(s7Data)
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
	if err != nil || len(bvlcPayload) < 4 {
		return nil
	}
	deviceInstance, vendorID, err := discover.ParseIAmResponse(bvlcPayload)
	if err != nil {
		return nil
	}
	id := &discover.BACnetIdentity{
		DeviceInstance: deviceInstance,
		VendorID:       vendorID,
		VendorName:     discover.BACnetVendorName(vendorID),
	}
	dev := discover.BACnetIdentityToDevice(ip, id)
	if dev.Model == "" {
		return nil
	}
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
