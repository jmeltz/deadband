package asset

import (
	"testing"

	"github.com/jmeltz/deadband/pkg/inventory"
)

func TestStoreImport_PersistsExtraAndPreservesRoutedBACnetSubDevices(t *testing.T) {
	store := &Store{Version: 1}

	initial := []inventory.Device{
		{
			IP:       "10.30.1.10",
			Vendor:   "Danfoss",
			Model:    "AK-CC55",
			Firmware: "2.01",
			Protocol: "bacnet",
			Port:     47808,
			Extra: map[string]string{
				"device_instance": "8502",
				"location":        "Freezer Aisle 1",
				"routed_snet":     "20",
			},
		},
		{
			IP:       "10.30.1.10",
			Vendor:   "Danfoss",
			Model:    "AK-CC55",
			Firmware: "2.01",
			Protocol: "bacnet",
			Port:     47808,
			Extra: map[string]string{
				"device_instance": "8503",
				"location":        "Freezer Aisle 2",
				"routed_snet":     "20",
			},
		},
		{
			IP:       "10.30.1.20",
			Vendor:   "Beckhoff",
			Model:    "CX5130-OSR",
			Firmware: "3.1.4024",
			Protocol: "ads",
			Port:     48898,
			Extra: map[string]string{
				"ams_net_id": "10.30.1.20.1.1",
			},
		},
	}

	res := store.Import(initial, "discovery")
	if res.Added != 3 || len(store.Assets) != 3 {
		t.Fatalf("Import added=%d len=%d, want 3 (2 distinct routed MS/TP instances + 1 ADS IPC)", res.Added, len(store.Assets))
	}

	// Re-import updated Beckhoff asset with enriched OS metadata
	res2 := store.Import([]inventory.Device{
		{
			IP:       "10.30.1.20",
			Vendor:   "Beckhoff",
			Model:    "CX5130-OSR",
			Firmware: "3.1.4026",
			Protocol: "ads",
			Port:     48898,
			Extra: map[string]string{
				"os": "Windows 10.0",
			},
		},
	}, "discovery")
	if res2.Updated != 1 {
		t.Fatalf("expected 1 updated asset, got %+v", res2)
	}

	matches := store.Filter(FilterOpts{Search: "Freezer Aisle 2"})
	if len(matches) != 1 || matches[0].Extra["device_instance"] != "8503" {
		t.Errorf("Filter(Freezer Aisle 2) = %+v, want instance 8503", matches)
	}

	adsMatches := store.Filter(FilterOpts{Vendor: "Beckhoff"})
	if len(adsMatches) != 1 {
		t.Fatalf("expected 1 Beckhoff asset, got %d", len(adsMatches))
	}
	if adsMatches[0].Extra["ams_net_id"] != "10.30.1.20.1.1" || adsMatches[0].Extra["os"] != "Windows 10.0" {
		t.Errorf("merged Beckhoff Extra = %+v, want both ams_net_id and os", adsMatches[0].Extra)
	}
}
