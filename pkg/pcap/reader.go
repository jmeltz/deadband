package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Global header magic numbers
const (
	magicNative  = 0xa1b2c3d4
	magicSwapped = 0xd4c3b2a1
)

// FileHeader represents a pcap file global header.
type FileHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	LinkType     uint32
}

// Packet represents a single captured packet from a pcap file.
type Packet struct {
	TsSec   uint32
	TsUsec  uint32
	CapLen  uint32
	OrigLen uint32
	Data    []byte
}

// Reader reads packets from a pcap file.
type Reader struct {
	r       io.Reader
	header  FileHeader
	swapped bool
}

// Open opens a pcap file and validates the global header.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening pcap: %w", err)
	}
	return NewReader(f)
}

// NewReader creates a Reader from any io.Reader.
func NewReader(r io.Reader) (*Reader, error) {
	pr := &Reader{r: r}

	// Read magic to determine byte order
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("reading pcap magic: %w", err)
	}

	switch magic {
	case magicNative:
		pr.swapped = false
	case magicSwapped:
		pr.swapped = true
	default:
		return nil, fmt.Errorf("not a pcap file (magic: 0x%08x)", magic)
	}

	pr.header.MagicNumber = magicNative
	order := pr.byteOrder()

	// Read remaining 20 bytes of global header
	if err := binary.Read(r, order, &pr.header.VersionMajor); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}
	if err := binary.Read(r, order, &pr.header.VersionMinor); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}
	if err := binary.Read(r, order, &pr.header.ThisZone); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}
	if err := binary.Read(r, order, &pr.header.SigFigs); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}
	if err := binary.Read(r, order, &pr.header.SnapLen); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}
	if err := binary.Read(r, order, &pr.header.LinkType); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}

	return pr, nil
}

// LinkType returns the data link type (1 = Ethernet).
func (pr *Reader) LinkType() uint32 {
	return pr.header.LinkType
}

// ReadPacket reads the next packet. Returns io.EOF when done.
func (pr *Reader) ReadPacket() (*Packet, error) {
	order := pr.byteOrder()
	var pkt Packet

	if err := binary.Read(pr.r, order, &pkt.TsSec); err != nil {
		return nil, err // io.EOF is expected
	}
	if err := binary.Read(pr.r, order, &pkt.TsUsec); err != nil {
		return nil, fmt.Errorf("reading packet header: %w", err)
	}
	if err := binary.Read(pr.r, order, &pkt.CapLen); err != nil {
		return nil, fmt.Errorf("reading packet header: %w", err)
	}
	if err := binary.Read(pr.r, order, &pkt.OrigLen); err != nil {
		return nil, fmt.Errorf("reading packet header: %w", err)
	}

	if pkt.CapLen > 65535 {
		return nil, fmt.Errorf("packet too large: %d bytes", pkt.CapLen)
	}

	pkt.Data = make([]byte, pkt.CapLen)
	if _, err := io.ReadFull(pr.r, pkt.Data); err != nil {
		return nil, fmt.Errorf("reading packet data: %w", err)
	}

	return &pkt, nil
}

func (pr *Reader) byteOrder() binary.ByteOrder {
	if pr.swapped {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
