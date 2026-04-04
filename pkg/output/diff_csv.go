package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/jmeltz/deadband/pkg/diff"
)

type diffCSVWriter struct {
	w *csv.Writer
}

func newDiffCSVWriter(w io.Writer) *diffCSVWriter {
	return &diffCSVWriter{w: csv.NewWriter(w)}
}

func (cw *diffCSVWriter) WriteDiff(report *diff.DiffReport) error {
	if err := cw.w.Write([]string{
		"Change Type", "IP", "Vendor", "Model", "Firmware",
		"Old Firmware", "Advisory ID", "CVEs", "CVSS",
	}); err != nil {
		return err
	}

	for _, d := range report.NewDevices {
		if err := cw.w.Write([]string{
			"NEW_DEVICE", d.IP, d.Vendor, d.Model, d.Firmware, "", "", "", "",
		}); err != nil {
			return err
		}
	}

	for _, d := range report.RemovedDevices {
		if err := cw.w.Write([]string{
			"REMOVED_DEVICE", d.IP, d.Vendor, d.Model, d.Firmware, "", "", "", "",
		}); err != nil {
			return err
		}
	}

	for _, fc := range report.FirmwareChanges {
		if err := cw.w.Write([]string{
			"FIRMWARE_CHANGE", fc.Device.IP, fc.Device.Vendor, fc.Device.Model,
			fc.NewFirmware, fc.OldFirmware, "", "", "",
		}); err != nil {
			return err
		}
	}

	for _, nv := range report.NewVulnerabilities {
		for _, m := range nv.NewMatches {
			if err := cw.w.Write([]string{
				"NEW_VULN", nv.Device.IP, nv.Device.Vendor, nv.Device.Model,
				nv.Device.Firmware, "",
				m.Advisory.ID, strings.Join(m.Advisory.CVEs, "; "),
				fmt.Sprintf("%.1f", m.Advisory.CVSSv3Max),
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (cw *diffCSVWriter) Flush() error {
	cw.w.Flush()
	return cw.w.Error()
}
