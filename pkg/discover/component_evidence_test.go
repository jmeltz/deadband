package discover

import "testing"

func TestCIPRootAndSlotsHaveSeparateComponentEvidence(t *testing.T) {
	d := cipDiscoveryDevices("192.0.2.1", &CIPIdentity{VendorID: 1, ProductName: "EN2T", RevMajor: 11, RevMinor: 2}, []BackplaneModule{{Slot: 0, VendorID: 1, ProductName: "L72", RevMajor: 32, RevMinor: 11}})
	if len(d) != 2 || d[0].Extra["component_path"] != "identity" || d[1].Extra["component_path"] != "backplane/slot/0" || d[0].Firmware != "11.002" || d[1].Firmware != "32.011" {
		t.Fatalf("component evidence %+v", d)
	}
}

func TestBACnetVersionKindsAndAddressesRemainDistinct(t *testing.T) {
	d := BACnetIdentityToDevice("192.0.2.1", &BACnetIdentity{DeviceInstance: 100, ApplicationSoftwareVersion: "app-2.0", SourceNet: 2000, SourceAddr: []byte{0, 0x1e}})
	if d.Firmware != "" || d.Extra["application_software_version"] != "app-2.0" || d.Extra["source_address_hex"] != "001e" || d.Extra["source_network"] != "2000" || d.Extra["component_path"] != "bacnet/device/100/net/2000/addr/001e" {
		t.Fatalf("misclassified BACnet evidence %+v", d)
	}
	d = BACnetIdentityToDevice("192.0.2.1", &BACnetIdentity{DeviceInstance: 100, FirmwareRevision: "1.2.3"})
	if d.Extra["version_kind"] != "bacnet_firmware_revision" || d.Extra["source_network"] != "" {
		t.Fatalf("invented route or version kind %+v", d)
	}
}
