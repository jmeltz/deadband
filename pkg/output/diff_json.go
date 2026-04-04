package output

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/diff"
)

type diffJSONOutput struct {
	ComparedAt         string                `json:"compared_at"`
	BaseFile           string                `json:"base_file"`
	CompareFile        string                `json:"compare_file"`
	Summary            diffJSONSummary       `json:"summary"`
	NewDevices         []diffJSONDevice      `json:"new_devices"`
	RemovedDevices     []diffJSONDevice      `json:"removed_devices"`
	FirmwareChanges    []diffJSONFWChange    `json:"firmware_changes"`
	NewVulnerabilities []diffJSONNewVuln     `json:"new_vulnerabilities"`
}

type diffJSONSummary struct {
	NewDevices         int `json:"new_devices"`
	RemovedDevices     int `json:"removed_devices"`
	FirmwareChanges    int `json:"firmware_changes"`
	NewVulnerabilities int `json:"new_vulnerabilities"`
}

type diffJSONDevice struct {
	IP       string `json:"ip"`
	Vendor   string `json:"vendor"`
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
}

type diffJSONFWChange struct {
	IP          string `json:"ip"`
	Model       string `json:"model"`
	OldFirmware string `json:"old_firmware"`
	NewFirmware string `json:"new_firmware"`
}

type diffJSONNewVuln struct {
	IP         string               `json:"ip"`
	Model      string               `json:"model"`
	Firmware   string               `json:"firmware"`
	Advisories []diffJSONAdvisory   `json:"advisories"`
}

type diffJSONAdvisory struct {
	ID     string   `json:"id"`
	CVEs   []string `json:"cves"`
	CVSSv3 float64  `json:"cvss_v3"`
	Title  string   `json:"title"`
}

type diffJSONWriter struct {
	w      io.Writer
	output *diffJSONOutput
}

func (jw *diffJSONWriter) WriteDiff(report *diff.DiffReport) error {
	out := &diffJSONOutput{
		ComparedAt:         time.Now().UTC().Format(time.RFC3339),
		BaseFile:           report.BaseFile,
		CompareFile:        report.CompareFile,
		NewDevices:         make([]diffJSONDevice, 0, len(report.NewDevices)),
		RemovedDevices:     make([]diffJSONDevice, 0, len(report.RemovedDevices)),
		FirmwareChanges:    make([]diffJSONFWChange, 0, len(report.FirmwareChanges)),
		NewVulnerabilities: make([]diffJSONNewVuln, 0, len(report.NewVulnerabilities)),
	}

	for _, d := range report.NewDevices {
		out.NewDevices = append(out.NewDevices, diffJSONDevice{IP: d.IP, Vendor: d.Vendor, Model: d.Model, Firmware: d.Firmware})
	}
	for _, d := range report.RemovedDevices {
		out.RemovedDevices = append(out.RemovedDevices, diffJSONDevice{IP: d.IP, Vendor: d.Vendor, Model: d.Model, Firmware: d.Firmware})
	}
	for _, fc := range report.FirmwareChanges {
		out.FirmwareChanges = append(out.FirmwareChanges, diffJSONFWChange{
			IP: fc.Device.IP, Model: fc.Device.Model,
			OldFirmware: fc.OldFirmware, NewFirmware: fc.NewFirmware,
		})
	}
	for _, nv := range report.NewVulnerabilities {
		jnv := diffJSONNewVuln{IP: nv.Device.IP, Model: nv.Device.Model, Firmware: nv.Device.Firmware}
		for _, m := range nv.NewMatches {
			jnv.Advisories = append(jnv.Advisories, diffJSONAdvisory{
				ID: m.Advisory.ID, CVEs: m.Advisory.CVEs,
				CVSSv3: m.Advisory.CVSSv3Max, Title: strings.TrimSpace(m.Advisory.Title),
			})
		}
		out.NewVulnerabilities = append(out.NewVulnerabilities, jnv)
	}

	out.Summary = diffJSONSummary{
		NewDevices:         len(report.NewDevices),
		RemovedDevices:     len(report.RemovedDevices),
		FirmwareChanges:    len(report.FirmwareChanges),
		NewVulnerabilities: len(report.NewVulnerabilities),
	}

	jw.output = out
	return nil
}

func (jw *diffJSONWriter) Flush() error {
	if jw.output == nil {
		return nil
	}
	enc := json.NewEncoder(jw.w)
	enc.SetIndent("", "  ")
	return enc.Encode(jw.output)
}
