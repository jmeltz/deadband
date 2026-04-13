package discover

import (
	"testing"
)

func TestBuildFINSHeader(t *testing.T) {
	h := buildFINSHeader(0x0A, 0xFE, 0x01)
	if len(h) != 10 {
		t.Fatalf("header length = %d, want 10", len(h))
	}
	if h[0] != 0x80 {
		t.Errorf("ICF = 0x%02X, want 0x80", h[0])
	}
	if h[1] != 0x00 {
		t.Errorf("RSV = 0x%02X, want 0x00", h[1])
	}
	if h[2] != 0x02 {
		t.Errorf("GCT = 0x%02X, want 0x02", h[2])
	}
	if h[3] != 0x00 {
		t.Errorf("DNA = 0x%02X, want 0x00", h[3])
	}
	if h[4] != 0x0A {
		t.Errorf("DA1 = 0x%02X, want 0x0A", h[4])
	}
	if h[5] != 0x00 {
		t.Errorf("DA2 = 0x%02X, want 0x00", h[5])
	}
	if h[7] != 0xFE {
		t.Errorf("SA1 = 0x%02X, want 0xFE", h[7])
	}
	if h[9] != 0x01 {
		t.Errorf("SID = 0x%02X, want 0x01", h[9])
	}
}

func TestBuildControllerDataReadRequest(t *testing.T) {
	req := buildControllerDataReadRequest(0x0A, 0xFE)
	if len(req) != 12 {
		t.Fatalf("request length = %d, want 12", len(req))
	}
	// FINS header
	if req[0] != 0x80 {
		t.Errorf("ICF = 0x%02X, want 0x80", req[0])
	}
	if req[4] != 0x0A {
		t.Errorf("DA1 = 0x%02X, want 0x0A", req[4])
	}
	// Command code
	if req[10] != 0x05 {
		t.Errorf("MRC = 0x%02X, want 0x05", req[10])
	}
	if req[11] != 0x01 {
		t.Errorf("SRC = 0x%02X, want 0x01", req[11])
	}
}

// buildTestFINSResponse constructs a synthetic FINS response for testing.
func buildTestFINSResponse(mrc, src byte, endCode uint16, payload []byte) []byte {
	frame := []byte{
		0xC0, 0x00, 0x02, // ICF (response), RSV, GCT
		0x00, 0xFE, 0x00, // DNA, DA1, DA2
		0x00, 0x0A, 0x00, // SNA, SA1, SA2
		0x01,                               // SID
		mrc, src,                           // Command code
		byte(endCode >> 8), byte(endCode),  // End code (big-endian)
	}
	return append(frame, payload...)
}

func TestParseFINSResponse(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		payload := make([]byte, 40)
		copy(payload[0:20], "CP1L-EL20DT1-D     ")
		copy(payload[20:40], "02.50               ")

		data := buildTestFINSResponse(0x05, 0x01, 0x0000, payload)
		endCode, result, err := ParseFINSResponse(data, 0x05, 0x01)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if endCode != 0x0000 {
			t.Errorf("end code = 0x%04X, want 0x0000", endCode)
		}
		if len(result) != 40 {
			t.Errorf("payload length = %d, want 40", len(result))
		}
	})

	t.Run("non-zero end code", func(t *testing.T) {
		data := buildTestFINSResponse(0x05, 0x01, 0x0401, nil)
		endCode, _, err := ParseFINSResponse(data, 0x05, 0x01)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if endCode != 0x0401 {
			t.Errorf("end code = 0x%04X, want 0x0401", endCode)
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, _, err := ParseFINSResponse([]byte{0xC0, 0x00}, 0x05, 0x01)
		if err == nil {
			t.Fatal("expected error for short response")
		}
	})

	t.Run("not a response", func(t *testing.T) {
		data := buildTestFINSResponse(0x05, 0x01, 0x0000, nil)
		data[0] = 0x80 // Command ICF, not response
		_, _, err := ParseFINSResponse(data, 0x05, 0x01)
		if err == nil {
			t.Fatal("expected error for command ICF")
		}
	})

	t.Run("wrong command code", func(t *testing.T) {
		data := buildTestFINSResponse(0x06, 0x02, 0x0000, nil)
		_, _, err := ParseFINSResponse(data, 0x05, 0x01)
		if err == nil {
			t.Fatal("expected error for wrong command code")
		}
	})
}

func TestParseControllerDataRead(t *testing.T) {
	tests := []struct {
		name        string
		model       string
		version     string
		wantModel   string
		wantVersion string
	}{
		{
			name:        "CP1L null padded",
			model:       "CP1L-EL20DT1-D\x00\x00\x00\x00\x00",
			version:     "02.50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			wantModel:   "CP1L-EL20DT1-D",
			wantVersion: "02.50",
		},
		{
			name:        "NX series space padded",
			model:       "NX102-1200          ",
			version:     "1.48                ",
			wantModel:   "NX102-1200",
			wantVersion: "1.48",
		},
		{
			name:        "CJ2M",
			model:       "CJ2M-CPU31          ",
			version:     "04.10               ",
			wantModel:   "CJ2M-CPU31",
			wantVersion: "04.10",
		},
		{
			name:        "CS1G",
			model:       "CS1G-CPU45H         ",
			version:     "03.20               ",
			wantModel:   "CS1G-CPU45H",
			wantVersion: "03.20",
		},
		{
			name:        "NJ series",
			model:       "NJ501-1300          ",
			version:     "1.60                ",
			wantModel:   "NJ501-1300",
			wantVersion: "1.60",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, 40)
			copy(payload[0:20], tt.model)
			copy(payload[20:40], tt.version)

			id, err := ParseControllerDataRead(payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Model != tt.wantModel {
				t.Errorf("model = %q, want %q", id.Model, tt.wantModel)
			}
			if id.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", id.Version, tt.wantVersion)
			}
		})
	}

	t.Run("short payload", func(t *testing.T) {
		_, err := ParseControllerDataRead(make([]byte, 20))
		if err == nil {
			t.Fatal("expected error for short payload")
		}
	})
}

func TestLastOctet(t *testing.T) {
	tests := []struct {
		ip   string
		want byte
	}{
		{"10.0.1.50", 50},
		{"192.168.1.1", 1},
		{"172.16.0.255", 255},
		{"10.0.0.0", 0},
	}
	for _, tt := range tests {
		if got := lastOctet(tt.ip); got != tt.want {
			t.Errorf("lastOctet(%q) = %d, want %d", tt.ip, got, tt.want)
		}
	}
}

func TestLastOctetInvalid(t *testing.T) {
	if got := lastOctet("not-an-ip"); got != 0 {
		t.Errorf("lastOctet(invalid) = %d, want 0", got)
	}
}

func TestFINSIdentityToDevice(t *testing.T) {
	dev := FINSIdentityToDevice("10.0.1.50", &FINSIdentity{
		Model:   "CP1L-EL20DT1-D",
		Version: "02.50",
	})
	if dev.IP != "10.0.1.50" {
		t.Errorf("IP = %q, want %q", dev.IP, "10.0.1.50")
	}
	if dev.Vendor != "Omron" {
		t.Errorf("Vendor = %q, want %q", dev.Vendor, "Omron")
	}
	if dev.Model != "CP1L-EL20DT1-D" {
		t.Errorf("Model = %q, want %q", dev.Model, "CP1L-EL20DT1-D")
	}
	if dev.Firmware != "02.50" {
		t.Errorf("Firmware = %q, want %q", dev.Firmware, "02.50")
	}
}

func TestFINSFullResponseParsing(t *testing.T) {
	payload := make([]byte, 40)
	copy(payload[0:20], "CP1L-EL20DT1-D\x00\x00\x00\x00\x00")
	copy(payload[20:40], "02.50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	data := buildTestFINSResponse(0x05, 0x01, 0x0000, payload)

	endCode, result, err := ParseFINSResponse(data, 0x05, 0x01)
	if err != nil {
		t.Fatalf("ParseFINSResponse: %v", err)
	}
	if endCode != 0x0000 {
		t.Fatalf("end code = 0x%04X, want 0x0000", endCode)
	}

	id, err := ParseControllerDataRead(result)
	if err != nil {
		t.Fatalf("ParseControllerDataRead: %v", err)
	}
	if id.Model != "CP1L-EL20DT1-D" {
		t.Errorf("model = %q, want %q", id.Model, "CP1L-EL20DT1-D")
	}
	if id.Version != "02.50" {
		t.Errorf("version = %q, want %q", id.Version, "02.50")
	}
}
