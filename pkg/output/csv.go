package output

import (
	"encoding/csv"
	"io"
	"fmt"
	"strings"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

type csvWriter struct {
	w *csv.Writer
}

func newCSVWriter(w io.Writer) *csvWriter {
	return &csvWriter{w: csv.NewWriter(w)}
}

func (cw *csvWriter) WriteHeader(_ advisory.Database, _ int) error {
	return cw.w.Write([]string{
		"IP", "Device Name", "Firmware", "Status", "Confidence",
		"Advisory ID", "CVEs", "CVSS", "URL",
	})
}

func (cw *csvWriter) WriteResult(r matcher.Result) error {
	if len(r.Matches) == 0 {
		return cw.w.Write([]string{
			r.Device.IP, r.Device.Model, r.Device.Firmware,
			r.Status, "", "", "", "", "",
		})
	}
	for _, m := range r.Matches {
		cves := strings.Join(m.Advisory.CVEs, "; ")
		if err := cw.w.Write([]string{
			r.Device.IP, r.Device.Model, r.Device.Firmware,
			r.Status, string(m.Confidence),
			m.Advisory.ID, cves,
			fmt.Sprintf("%.1f", m.Advisory.CVSSv3Max),
			m.Advisory.URL,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (cw *csvWriter) WriteSummary(_ Summary, _ int) error {
	return nil
}

func (cw *csvWriter) Flush() error {
	cw.w.Flush()
	return cw.w.Error()
}
