package pcap

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Frame represents a demuxed network frame with L3/L4 info extracted.
type Frame struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8 // 6=TCP, 17=UDP
	Payload []byte
}

// DemuxLink accepts Ethernet, BSD null/loopback and raw IPv4 captures. It does
// not perform IP fragmentation or TCP stream reassembly; partial protocol
// frames remain unparsed instead of being guessed from incomplete bytes.
func DemuxLink(linkType uint32, data []byte) (*Frame, error) {
	switch linkType {
	case 1:
		return DemuxEthernet(data)
	case 0, 108:
		if len(data) < 4 {
			return nil, fmt.Errorf("loopback header too short")
		}
		var family uint32
		if linkType == 108 {
			family = binary.BigEndian.Uint32(data[:4])
		} else {
			family = binary.LittleEndian.Uint32(data[:4])
			if family != 2 {
				family = binary.BigEndian.Uint32(data[:4])
			}
		}
		if family != 2 {
			return nil, fmt.Errorf("loopback family %d is not IPv4", family)
		}
		return parseIPv4(data[4:])
	case 101, 228:
		return parseIPv4(data)
	default:
		return nil, fmt.Errorf("unsupported link type %d", linkType)
	}
}

// DemuxEthernet parses an Ethernet frame, extracting IP/TCP/UDP headers
// and returning the transport payload. Handles 802.1Q VLAN tags.
func DemuxEthernet(data []byte) (*Frame, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}

	offset := 12
	etherType := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Handle 802.1Q VLAN tag
	if etherType == 0x8100 {
		if len(data) < offset+4 {
			return nil, fmt.Errorf("truncated VLAN tag")
		}
		offset += 2 // skip TCI
		etherType = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	// Only handle IPv4
	if etherType != 0x0800 {
		return nil, fmt.Errorf("not IPv4 (ethertype: 0x%04x)", etherType)
	}

	return parseIPv4(data[offset:])
}

func parseIPv4(data []byte) (*Frame, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("IPv4 header too short")
	}

	version := data[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("not IPv4 (version: %d)", version)
	}

	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return nil, fmt.Errorf("invalid IPv4 IHL: %d", ihl)
	}

	proto := data[9]
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen < ihl || totalLen > len(data) {
		return nil, fmt.Errorf("invalid or truncated IPv4 total length")
	}
	if binary.BigEndian.Uint16(data[6:8])&0x3fff != 0 {
		return nil, fmt.Errorf("fragmented IPv4 unsupported")
	}
	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])

	payload := data[ihl:totalLen]

	switch proto {
	case 6: // TCP
		return parseTCP(srcIP, dstIP, payload)
	case 17: // UDP
		return parseUDP(srcIP, dstIP, payload)
	default:
		return nil, fmt.Errorf("unsupported protocol: %d", proto)
	}
}

func parseTCP(srcIP, dstIP net.IP, data []byte) (*Frame, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("TCP header too short")
	}

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	dataOffset := int(data[12]>>4) * 4
	if dataOffset < 20 || len(data) < dataOffset {
		return nil, fmt.Errorf("invalid TCP data offset: %d", dataOffset)
	}

	return &Frame{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   6,
		Payload: data[dataOffset:],
	}, nil
}

func parseUDP(srcIP, dstIP net.IP, data []byte) (*Frame, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("UDP header too short")
	}

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	length := int(binary.BigEndian.Uint16(data[4:6]))
	if length < 8 || length > len(data) {
		return nil, fmt.Errorf("invalid UDP length")
	}

	return &Frame{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   17,
		Payload: data[8:length],
	}, nil
}
