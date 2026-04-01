package inventory

import (
	"testing"
)

func TestParseCSV(t *testing.T) {
	devices, err := ParseFile("../../testdata/devices.csv", "csv")
	if err != nil {
		t.Fatalf("ParseFile CSV: %v", err)
	}
	if len(devices) != 5 {
		t.Fatalf("expected 5 devices, got %d", len(devices))
	}
	d := devices[0]
	if d.IP != "172.16.12.21" {
		t.Errorf("device[0].IP = %q, want 172.16.12.21", d.IP)
	}
	if d.Model != "1756-EN2T/D" {
		t.Errorf("device[0].Model = %q, want 1756-EN2T/D", d.Model)
	}
	if d.Firmware != "11.002" {
		t.Errorf("device[0].Firmware = %q, want 11.002", d.Firmware)
	}
	if d.Vendor != "Rockwell Automation" {
		t.Errorf("device[0].Vendor = %q, want Rockwell Automation", d.Vendor)
	}
}

func TestParseJSON(t *testing.T) {
	devices, err := ParseFile("../../testdata/devices.json", "json")
	if err != nil {
		t.Fatalf("ParseFile JSON: %v", err)
	}
	if len(devices) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(devices))
	}
	if devices[0].Model != "1756-EN2T/D" {
		t.Errorf("device[0].Model = %q, want 1756-EN2T/D", devices[0].Model)
	}
}

func TestParseFlat(t *testing.T) {
	devices, err := ParseFile("../../testdata/devices.flat", "flat")
	if err != nil {
		t.Fatalf("ParseFile flat: %v", err)
	}
	if len(devices) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(devices))
	}
	d := devices[1]
	if d.Vendor != "ABB" {
		t.Errorf("device[1].Vendor = %q, want ABB", d.Vendor)
	}
	if d.Model != "AC500" {
		t.Errorf("device[1].Model = %q, want AC500", d.Model)
	}
}

func TestAutoDetect(t *testing.T) {
	// .csv extension should auto-detect as CSV
	devices, err := ParseFile("../../testdata/devices.csv", "auto")
	if err != nil {
		t.Fatalf("auto-detect CSV: %v", err)
	}
	if len(devices) != 5 {
		t.Errorf("expected 5 devices, got %d", len(devices))
	}

	// .json extension
	devices, err = ParseFile("../../testdata/devices.json", "auto")
	if err != nil {
		t.Fatalf("auto-detect JSON: %v", err)
	}
	if len(devices) != 3 {
		t.Errorf("expected 3 devices, got %d", len(devices))
	}
}
