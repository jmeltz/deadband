package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/jmeltz/deadband/pkg/diff"
)

type diffTextWriter struct {
	w io.Writer
}

func (tw *diffTextWriter) WriteDiff(report *diff.DiffReport) error {
	if len(report.NewDevices) > 0 {
		fmt.Fprintf(tw.w, "NEW DEVICES (%d):\n", len(report.NewDevices))
		for _, d := range report.NewDevices {
			fmt.Fprintf(tw.w, "  + %-16s %-14s fw %-10s %s\n", d.IP, d.Model, d.Firmware, d.Vendor)
		}
		fmt.Fprintln(tw.w)
	}

	if len(report.RemovedDevices) > 0 {
		fmt.Fprintf(tw.w, "REMOVED DEVICES (%d):\n", len(report.RemovedDevices))
		for _, d := range report.RemovedDevices {
			fmt.Fprintf(tw.w, "  - %-16s %-14s fw %-10s %s\n", d.IP, d.Model, d.Firmware, d.Vendor)
		}
		fmt.Fprintln(tw.w)
	}

	if len(report.FirmwareChanges) > 0 {
		fmt.Fprintf(tw.w, "FIRMWARE CHANGES (%d):\n", len(report.FirmwareChanges))
		for _, fc := range report.FirmwareChanges {
			fmt.Fprintf(tw.w, "  ~ %-16s %-14s %s → %s\n", fc.Device.IP, fc.Device.Model, fc.OldFirmware, fc.NewFirmware)
		}
		fmt.Fprintln(tw.w)
	}

	if len(report.NewVulnerabilities) > 0 {
		fmt.Fprintf(tw.w, "NEW VULNERABILITIES (%d devices):\n", len(report.NewVulnerabilities))
		for _, nv := range report.NewVulnerabilities {
			fmt.Fprintf(tw.w, "  ! %-16s %-14s fw %s\n", nv.Device.IP, nv.Device.Model, nv.Device.Firmware)
			for _, m := range nv.NewMatches {
				cves := strings.Join(m.Advisory.CVEs, ", ")
				fmt.Fprintf(tw.w, "      %s  %s  CVSS %.1f\n", m.Advisory.ID, cves, m.Advisory.CVSSv3Max)
			}
		}
		fmt.Fprintln(tw.w)
	}

	total := len(report.NewDevices) + len(report.RemovedDevices) + len(report.FirmwareChanges) + len(report.NewVulnerabilities)
	if total == 0 {
		fmt.Fprintln(tw.w, "No changes detected.")
	} else {
		fmt.Fprintf(tw.w, "[deadband] Diff summary: %d new, %d removed, %d firmware changed, %d newly vulnerable\n",
			len(report.NewDevices), len(report.RemovedDevices), len(report.FirmwareChanges), len(report.NewVulnerabilities))
	}

	return nil
}

func (tw *diffTextWriter) Flush() error {
	return nil
}
