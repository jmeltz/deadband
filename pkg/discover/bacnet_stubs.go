//go:build !bacnet

// BACnet/IP discovery was scoped out of the default deadband build for v0.5
// — it serves the building automation market rather than manufacturing OT
// and is moving to a separate `trics/bacnet-enum` tool. The real probe and
// parser live in bacnet.go behind the `bacnet` build tag. This file provides
// no-op stubs so passive PCAP analysis (which still recognizes BACnet
// frames) and the `--mode bacnet` switch arm continue to compile.
//
// To re-enable BACnet:  go build -tags bacnet ./...

package discover

import (
	"errors"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// errBACnetNotBuilt explains why BACnet probes return nothing. Callers that
// handle this error gracefully will simply log the cause.
var errBACnetNotBuilt = errors.New("BACnet support was not compiled into this binary; rebuild with `go build -tags bacnet`")

// BACnetIdentity is preserved as an empty struct so callers in pcap/passive.go
// can still reference the type without conditional imports. Fields mirror
// the real implementation so no field-access call site needs to change.
type BACnetIdentity struct {
	VendorID         uint16
	VendorName       string
	ModelName        string
	FirmwareRevision string
	DeviceInstance   uint32
}

// ParseBVLC stub. Always returns the not-built error; passive PCAP code
// treats any error as "this packet wasn't BACnet" and skips silently.
func ParseBVLC(_ []byte) (uint8, []byte, error) {
	return 0, nil, errBACnetNotBuilt
}

// ParseIAmResponse stub.
func ParseIAmResponse(_ []byte) (uint32, uint16, error) {
	return 0, 0, errBACnetNotBuilt
}

// BACnetVendorName stub. Returns empty string for any vendor ID.
func BACnetVendorName(_ uint16) string {
	return ""
}

// BACnetIdentityToDevice stub. Always returns a zero-valued device.
func BACnetIdentityToDevice(_ string, _ *BACnetIdentity) inventory.Device {
	return inventory.Device{}
}

// discoverBACnet stub. Returns nil so `--mode bacnet` produces an empty
// result set on default builds rather than crashing.
func discoverBACnet(_ []string, _ time.Duration, _ int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress("BACnet support not built into this binary; rebuild with `go build -tags bacnet` to enable")
	}
	return nil
}
