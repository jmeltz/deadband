package discover

import (
	"testing"

	"github.com/jmeltz/deadband/pkg/inventory"
)

func TestUnknownModeFailsBeforeCIDRExpansion(t *testing.T) {
	_, err := Run(Opts{Mode: "typo", CIDR: "invalid"})
	if err == nil || err.Error() != `unsupported discovery mode "typo"` {
		t.Fatalf("%v", err)
	}
}

func TestPhysicalSlotsIncludingZeroRemainDistinct(t *testing.T) {
	var devices []inventory.Device
	for slot := 0; slot < 3; slot++ {
		devices = append(devices, BackplaneModuleToDevice("10.0.0.1", &BackplaneModule{Slot: slot, VendorID: 1, ProductName: "1756-IB16/A", RevMajor: 3, RevMinor: 4}))
	}
	devices = append(devices, inventory.Device{IP: "10.0.0.1", Model: "EN2T adapter", Protocol: "cip"})
	got := mergeDevices([][]inventory.Device{devices})
	if len(got) != 4 {
		t.Fatalf("physical components collapsed: %+v", got)
	}
	if got[0].Extra["slot"] != "0" || got[0].Extra["component"] != "chassis_slot" {
		t.Fatalf("slot zero unmarked: %+v", got[0])
	}
}
