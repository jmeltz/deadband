package diff

import (
	"testing"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

var testDB = &advisory.Database{
	Advisories: []advisory.Advisory{
		{
			ID:               "ICSA-24-179-01",
			Vendor:           "Rockwell Automation",
			Products:         []string{"1756-EN2T"},
			AffectedVersions: []string{"<=12.0"},
			CVSSv3Max:        9.8,
			CVEs:             []string{"CVE-2024-6242"},
		},
	},
}

var defaultOpts = matcher.FilterOpts{MinConfidence: matcher.ConfidenceLow}

func TestCompute_NewDevices(t *testing.T) {
	base := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "11.002"},
	}
	compare := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "11.002"},
		{IP: "10.0.1.2", Vendor: "Rockwell Automation", Model: "1756-L85E", Firmware: "33.011"},
	}

	report := Compute(base, compare, testDB, defaultOpts)
	if len(report.NewDevices) != 1 {
		t.Fatalf("NewDevices = %d, want 1", len(report.NewDevices))
	}
	if report.NewDevices[0].IP != "10.0.1.2" {
		t.Errorf("new device IP = %q, want %q", report.NewDevices[0].IP, "10.0.1.2")
	}
}

func TestCompute_RemovedDevices(t *testing.T) {
	base := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "11.002"},
		{IP: "10.0.1.3", Vendor: "Rockwell Automation", Model: "1756-L85E", Firmware: "33.011"},
	}
	compare := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "11.002"},
	}

	report := Compute(base, compare, testDB, defaultOpts)
	if len(report.RemovedDevices) != 1 {
		t.Fatalf("RemovedDevices = %d, want 1", len(report.RemovedDevices))
	}
	if report.RemovedDevices[0].IP != "10.0.1.3" {
		t.Errorf("removed device IP = %q, want %q", report.RemovedDevices[0].IP, "10.0.1.3")
	}
}

func TestCompute_FirmwareChange(t *testing.T) {
	base := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "10.005"},
	}
	compare := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "11.002"},
	}

	report := Compute(base, compare, testDB, defaultOpts)
	if len(report.FirmwareChanges) != 1 {
		t.Fatalf("FirmwareChanges = %d, want 1", len(report.FirmwareChanges))
	}
	fc := report.FirmwareChanges[0]
	if fc.OldFirmware != "10.005" || fc.NewFirmware != "11.002" {
		t.Errorf("firmware change = %q → %q, want %q → %q", fc.OldFirmware, fc.NewFirmware, "10.005", "11.002")
	}
}

func TestCompute_NewVulnerability(t *testing.T) {
	// Base: device at firmware 13.0 (not affected by <=12.0)
	base := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "13.000"},
	}
	// Compare: device downgraded to firmware 11.0 (affected by <=12.0)
	compare := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "11.000"},
	}

	report := Compute(base, compare, testDB, defaultOpts)
	if len(report.NewVulnerabilities) != 1 {
		t.Fatalf("NewVulnerabilities = %d, want 1", len(report.NewVulnerabilities))
	}
	if report.NewVulnerabilities[0].NewMatches[0].Advisory.ID != "ICSA-24-179-01" {
		t.Errorf("unexpected advisory ID: %s", report.NewVulnerabilities[0].NewMatches[0].Advisory.ID)
	}
}

func TestCompute_NoChanges(t *testing.T) {
	devices := []inventory.Device{
		{IP: "10.0.1.1", Vendor: "Rockwell Automation", Model: "1756-EN2T", Firmware: "11.002"},
	}

	report := Compute(devices, devices, testDB, defaultOpts)
	if len(report.NewDevices) != 0 {
		t.Errorf("NewDevices = %d, want 0", len(report.NewDevices))
	}
	if len(report.RemovedDevices) != 0 {
		t.Errorf("RemovedDevices = %d, want 0", len(report.RemovedDevices))
	}
	if len(report.FirmwareChanges) != 0 {
		t.Errorf("FirmwareChanges = %d, want 0", len(report.FirmwareChanges))
	}
	if len(report.NewVulnerabilities) != 0 {
		t.Errorf("NewVulnerabilities = %d, want 0", len(report.NewVulnerabilities))
	}
}

func TestCompute_EmptyInputs(t *testing.T) {
	report := Compute(nil, nil, testDB, defaultOpts)
	if report == nil {
		t.Fatal("expected non-nil report for empty inputs")
	}
	if len(report.NewDevices) != 0 || len(report.RemovedDevices) != 0 {
		t.Error("expected empty report for empty inputs")
	}
}
