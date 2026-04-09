package discover

import (
	"encoding/binary"
	"testing"
)

func TestBuildListIdentityRequest(t *testing.T) {
	req := buildListIdentityRequest()
	if len(req) != eipHeaderSize {
		t.Fatalf("request length = %d, want %d", len(req), eipHeaderSize)
	}

	cmd := binary.LittleEndian.Uint16(req[0:2])
	if cmd != eipCommandListIdentity {
		t.Errorf("command = 0x%04X, want 0x%04X", cmd, eipCommandListIdentity)
	}

	// All other bytes should be zero
	for i := 2; i < eipHeaderSize; i++ {
		if req[i] != 0 {
			t.Errorf("byte[%d] = 0x%02X, want 0x00", i, req[i])
		}
	}
}

// buildTestResponse constructs a valid ListIdentity response for testing.
// Mimics a Rockwell 1756-EN2T/D with revision 11.2, serial 0xD060925B.
func buildTestResponse() []byte {
	productName := "1756-EN2T/D"

	// Item data: encap_version(2) + socket_addr(16) + vendor(2) + device_type(2) +
	//   product_code(2) + rev_major(1) + rev_minor(1) + status(2) + serial(4) +
	//   name_len(1) + name(N) + state(1)
	itemDataLen := 2 + cipSocketAddrSize + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 1 + len(productName) + 1

	// Total: header(24) + item_count(2) + item_type(2) + item_length(2) + item_data
	buf := make([]byte, eipHeaderSize+2+4+itemDataLen)

	// EIP header
	binary.LittleEndian.PutUint16(buf[0:2], eipCommandListIdentity)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(buf)-eipHeaderSize)) // data length

	offset := eipHeaderSize

	// Item count = 1
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1)
	offset += 2

	// Item type + length
	binary.LittleEndian.PutUint16(buf[offset:offset+2], cipItemTypeIdentity)
	binary.LittleEndian.PutUint16(buf[offset+2:offset+4], uint16(itemDataLen))
	offset += 4

	// Encap version
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1)
	offset += 2

	// Socket address (16 bytes) - skip (zeros)
	offset += cipSocketAddrSize

	// Identity fields
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 1) // vendor_id = Rockwell
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 14) // device_type = comm adapter
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 55) // product_code
	offset += 2
	buf[offset] = 11 // rev_major
	offset++
	buf[offset] = 2 // rev_minor
	offset++
	binary.LittleEndian.PutUint16(buf[offset:offset+2], 0x0030) // status
	offset += 2
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0xD060925B) // serial
	offset += 4
	buf[offset] = byte(len(productName))
	offset++
	copy(buf[offset:], productName)
	offset += len(productName)
	buf[offset] = 3 // state = Run

	return buf
}

func TestParseListIdentityResponse(t *testing.T) {
	data := buildTestResponse()
	id, err := ParseListIdentityResponse(data)
	if err != nil {
		t.Fatalf("ParseListIdentityResponse: %v", err)
	}

	if id.VendorID != 1 {
		t.Errorf("VendorID = %d, want 1", id.VendorID)
	}
	if id.DeviceType != 14 {
		t.Errorf("DeviceType = %d, want 14", id.DeviceType)
	}
	if id.ProductCode != 55 {
		t.Errorf("ProductCode = %d, want 55", id.ProductCode)
	}
	if id.RevMajor != 11 {
		t.Errorf("RevMajor = %d, want 11", id.RevMajor)
	}
	if id.RevMinor != 2 {
		t.Errorf("RevMinor = %d, want 2", id.RevMinor)
	}
	if id.Serial != 0xD060925B {
		t.Errorf("Serial = 0x%08X, want 0xD060925B", id.Serial)
	}
	if id.ProductName != "1756-EN2T/D" {
		t.Errorf("ProductName = %q, want %q", id.ProductName, "1756-EN2T/D")
	}
	if id.State != 3 {
		t.Errorf("State = %d, want 3", id.State)
	}
}

func TestParseListIdentityResponse_TooShort(t *testing.T) {
	data := make([]byte, 10)
	_, err := ParseListIdentityResponse(data)
	if err == nil {
		t.Error("expected error for short response, got nil")
	}
}

func TestParseListIdentityResponse_WrongCommand(t *testing.T) {
	data := make([]byte, 30)
	binary.LittleEndian.PutUint16(data[0:2], 0x0065) // RegisterSession, not ListIdentity
	_, err := ParseListIdentityResponse(data)
	if err == nil {
		t.Error("expected error for wrong command, got nil")
	}
}

func TestIdentityToDevice(t *testing.T) {
	id := &CIPIdentity{
		VendorID:    1,
		ProductName: "1756-EN2T/D",
		RevMajor:    11,
		RevMinor:    2,
	}
	dev := CIPIdentityToDevice("10.0.1.1", id)

	if dev.IP != "10.0.1.1" {
		t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.1")
	}
	if dev.Vendor != "Rockwell Automation" {
		t.Errorf("Vendor = %q, want %q", dev.Vendor, "Rockwell Automation")
	}
	if dev.Model != "1756-EN2T/D" {
		t.Errorf("Model = %q, want %q", dev.Model, "1756-EN2T/D")
	}
	if dev.Firmware != "11.002" {
		t.Errorf("Firmware = %q, want %q", dev.Firmware, "11.002")
	}
}

func TestIdentityToDevice_UnknownVendor(t *testing.T) {
	id := &CIPIdentity{
		VendorID:    9999,
		ProductName: "Unknown Device",
		RevMajor:    1,
		RevMinor:    0,
	}
	dev := CIPIdentityToDevice("10.0.1.2", id)

	if dev.Vendor != "Vendor(9999)" {
		t.Errorf("Vendor = %q, want %q", dev.Vendor, "Vendor(9999)")
	}
}

// buildIdentityReply constructs a CIP Get Attributes All reply for the Identity Object.
func buildIdentityReply(vendorID, deviceType, productCode uint16, revMajor, revMinor uint8, serial uint32, productName string) []byte {
	// CIP reply header: service(1) + reserved(1) + status(1) + addl_status_size(1)
	reply := []byte{cipServiceGetAttrAll | 0x80, 0x00, 0x00, 0x00}

	attr := make([]byte, 15+len(productName))
	binary.LittleEndian.PutUint16(attr[0:2], vendorID)
	binary.LittleEndian.PutUint16(attr[2:4], deviceType)
	binary.LittleEndian.PutUint16(attr[4:6], productCode)
	attr[6] = revMajor
	attr[7] = revMinor
	binary.LittleEndian.PutUint16(attr[8:10], 0x0030) // status word
	binary.LittleEndian.PutUint32(attr[10:14], serial)
	attr[14] = byte(len(productName))
	copy(attr[15:], productName)

	return append(reply, attr...)
}

func TestParseCIPIdentityReply_Controller(t *testing.T) {
	data := buildIdentityReply(1, 14, 55, 20, 55, 0x12345678, "1756-L72/B")
	mod, err := parseCIPIdentityReply(data, 0)
	if err != nil {
		t.Fatalf("parseCIPIdentityReply: %v", err)
	}
	if mod.Slot != 0 {
		t.Errorf("Slot = %d, want 0", mod.Slot)
	}
	if mod.VendorID != 1 {
		t.Errorf("VendorID = %d, want 1", mod.VendorID)
	}
	if mod.ProductName != "1756-L72/B" {
		t.Errorf("ProductName = %q, want %q", mod.ProductName, "1756-L72/B")
	}
	if mod.RevMajor != 20 || mod.RevMinor != 55 {
		t.Errorf("Rev = %d.%d, want 20.55", mod.RevMajor, mod.RevMinor)
	}
}

func TestParseCIPIdentityReply_IOModule(t *testing.T) {
	data := buildIdentityReply(1, 7, 100, 3, 4, 0xAABBCCDD, "1756-IB16/A")
	mod, err := parseCIPIdentityReply(data, 3)
	if err != nil {
		t.Fatalf("parseCIPIdentityReply: %v", err)
	}
	if mod.Slot != 3 {
		t.Errorf("Slot = %d, want 3", mod.Slot)
	}
	if mod.ProductName != "1756-IB16/A" {
		t.Errorf("ProductName = %q, want %q", mod.ProductName, "1756-IB16/A")
	}
}

func TestParseCIPIdentityReply_ErrorStatus(t *testing.T) {
	// General status 0x05 = path destination unknown (empty slot)
	data := []byte{0x81, 0x00, 0x05, 0x00}
	_, err := parseCIPIdentityReply(data, 7)
	if err == nil {
		t.Error("expected error for non-zero general status, got nil")
	}
}

func TestParseCIPIdentityReply_CMReply(t *testing.T) {
	// Connection Manager reply (0xD2) wrapping a successful Get Attr All response
	inner := buildIdentityReply(1, 14, 55, 11, 1, 0x11111111, "1756-EN2T/D")
	outer := []byte{cipServiceUnconnectedSend | 0x80, 0x00, 0x00, 0x00}
	outer = append(outer, inner...)

	mod, err := parseCIPIdentityReply(outer, 4)
	if err != nil {
		t.Fatalf("parseCIPIdentityReply (CM wrapped): %v", err)
	}
	if mod.ProductName != "1756-EN2T/D" {
		t.Errorf("ProductName = %q, want %q", mod.ProductName, "1756-EN2T/D")
	}
	if mod.RevMajor != 11 || mod.RevMinor != 1 {
		t.Errorf("Rev = %d.%d, want 11.1", mod.RevMajor, mod.RevMinor)
	}
}

func TestBackplaneModuleToDevice(t *testing.T) {
	mod := &BackplaneModule{
		Slot:        0,
		VendorID:    1,
		ProductName: "1756-L72/B",
		RevMajor:    20,
		RevMinor:    55,
	}
	dev := BackplaneModuleToDevice("10.0.1.1", mod)

	if dev.IP != "10.0.1.1" {
		t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.1")
	}
	if dev.Vendor != "Rockwell Automation" {
		t.Errorf("Vendor = %q, want %q", dev.Vendor, "Rockwell Automation")
	}
	if dev.Model != "1756-L72/B" {
		t.Errorf("Model = %q, want %q", dev.Model, "1756-L72/B")
	}
	if dev.Firmware != "20.055" {
		t.Errorf("Firmware = %q, want %q", dev.Firmware, "20.055")
	}
}

func TestBroadcastAddrForCIDR(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"10.0.1.0/24", "10.0.1.255"},
		{"192.168.1.0/24", "192.168.1.255"},
		{"10.0.0.0/16", "10.0.255.255"},
		{"10.0.1.5/32", ""},
	}
	for _, tt := range tests {
		got := broadcastAddrForCIDR(tt.cidr)
		if got != tt.want {
			t.Errorf("broadcastAddrForCIDR(%q) = %q, want %q", tt.cidr, got, tt.want)
		}
	}
}
