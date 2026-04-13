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
		"KEV", "EPSS Score", "EPSS Percentile", "Risk Score",
	})
}

func (cw *csvWriter) WriteResult(r matcher.Result) error {
	if len(r.Matches) == 0 {
		return cw.w.Write([]string{
			r.Device.IP, r.Device.Model, r.Device.Firmware,
			r.Status, "", "", "", "", "",
			"", "", "", "",
		})
	}
	for _, m := range r.Matches {
		cves := strings.Join(m.Advisory.CVEs, "; ")
		kev := ""
		if m.KEV {
			kev = "true"
		}
		epss := ""
		if m.EPSSScore > 0 {
			epss = fmt.Sprintf("%.4f", m.EPSSScore)
		}
		epssPctl := ""
		if m.EPSSPercentile > 0 {
			epssPctl = fmt.Sprintf("%.4f", m.EPSSPercentile)
		}
		risk := ""
		if m.RiskScore > 0 {
			risk = fmt.Sprintf("%.1f", m.RiskScore)
		}
		if err := cw.w.Write([]string{
			r.Device.IP, r.Device.Model, r.Device.Firmware,
			r.Status, string(m.Confidence),
			m.Advisory.ID, cves,
			fmt.Sprintf("%.1f", m.Advisory.CVSSv3Max),
			m.Advisory.URL,
			kev, epss, epssPctl, risk,
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
