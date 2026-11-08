// Package capability describes shipped query contracts and planned work. It is
// metadata, not permission to execute a protocol or a device safety certificate.
package capability

import (
	"encoding/json"
	"io"

	"github.com/jmeltz/deadband/pkg/query"
)

type Registry struct {
	RegistryVersion    int       `json:"registry_version"`
	SourcePackage      string    `json:"source_package"`
	SourceVersion      string    `json:"source_version"`
	EnginePackage      string    `json:"engine_package"`
	EngineVersion      string    `json:"engine_version"`
	WireSchemaVersions []int     `json:"wire_schema_versions"`
	Profiles           []Profile `json:"profiles"`
}

type Profile struct {
	Key                      string     `json:"key"`
	Name                     string     `json:"name"`
	Protocol                 string     `json:"protocol"`
	Status                   string     `json:"status"`
	Executable               bool       `json:"executable"`
	WireProfileID            string     `json:"wire_profile_id,omitempty"`
	SchemaVersions           []int      `json:"schema_versions"`
	Transports               []Endpoint `json:"transports"`
	RequestedFields          []string   `json:"requested_fields"`
	Validation               string     `json:"validation"`
	DeviceValidationRequired bool       `json:"device_validation_required"`
}

type Endpoint struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
}

// Current returns fresh data so a consumer cannot mutate the registry used by
// another request. Stable means a shipped executable contract; Lab is a product
// validation workflow, not an alternative wire profile or maturity guarantee.
func Current() Registry {
	profiles := []Profile{{Key: "enip_identity_tcp", Name: "EtherNet/IP endpoint identity", Protocol: "enip", Status: "stable", Executable: true, WireProfileID: query.ProfileENIPIdentityTCP, SchemaVersions: []int{query.SchemaVersion}, Transports: []Endpoint{{Transport: "tcp", Port: 44818}}, RequestedFields: []string{"vendor", "model", "firmware", "serial"}, Validation: "protocol_contract_and_loopback", DeviceValidationRequired: true}}
	for _, p := range []struct{ key, name, protocol string }{
		{"modbus_known_unit", "Modbus identification at a known unit", "modbus"},
		{"s7_known_tsap", "S7 identification at a known TSAP", "s7"},
		{"bacnet_known_instance", "BACnet identification at a known device instance", "bacnet"},
		{"ads_device_info", "Route-less ADS device information", "ads"},
		{"sopas_identity", "SOPAS identification", "sopas"},
	} {
		profiles = append(profiles, Profile{Key: p.key, Name: p.name, Protocol: p.protocol, Status: "planned", Executable: false, SchemaVersions: []int{}, Transports: []Endpoint{}, RequestedFields: []string{}, Validation: "not_implemented", DeviceValidationRequired: true})
	}
	return Registry{RegistryVersion: 1, SourcePackage: "github.com/jmeltz/deadband/pkg/capability", SourceVersion: "v0.8.1", EnginePackage: "github.com/jmeltz/deadband/pkg/query", EngineVersion: "v0.8.0", WireSchemaVersions: []int{query.SchemaVersion}, Profiles: profiles}
}

// Write emits deterministic JSON with sorted object keys and a final newline.
// The artifact is consumed directly by TypeScript; consumers must preserve the
// distinction between metadata keys and actual executable wire profile IDs.
func Write(w io.Writer) error {
	b, err := json.Marshal(Current())
	if err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	return e.Encode(value)
}
