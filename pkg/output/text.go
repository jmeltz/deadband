package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

type textWriter struct {
	w io.Writer
}

func (tw *textWriter) WriteHeader(db advisory.Database, deviceCount int) error {
	return nil
}

func (tw *textWriter) WriteResult(r matcher.Result) error {
	status := r.Status
	conf := ""
	if len(r.Matches) > 0 {
		conf = fmt.Sprintf("  [%s]", r.Matches[0].Confidence)
	}

	fmt.Fprintf(tw.w, "  %-16s %-14s fw %-10s %s%s\n",
		r.Device.IP, r.Device.Model, r.Device.Firmware, status, conf)

	for _, m := range r.Matches {
		cves := strings.Join(m.Advisory.CVEs, ", ")
		note := m.Advisory.Title
		if m.Note != "" {
			note = m.Note
		}
		fmt.Fprintf(tw.w, "    %-16s %-16s CVSS %.1f  %s\n",
			m.Advisory.ID, cves, m.Advisory.CVSSv3Max, note)
		// Enrichment line (KEV, EPSS, Risk Score)
		if m.KEV || m.EPSSScore > 0 || m.RiskScore > 0 {
			fmt.Fprintf(tw.w, "    ")
			if m.KEV {
				if m.KEVRansomware {
					fmt.Fprintf(tw.w, "[KEV+Ransomware] ")
				} else {
					fmt.Fprintf(tw.w, "[KEV] ")
				}
			}
			if m.EPSSScore > 0 {
				fmt.Fprintf(tw.w, "EPSS %.0f%% (%dth pctl)  ", m.EPSSScore*100, int(m.EPSSPercentile*100))
			}
			if m.RiskScore > 0 {
				fmt.Fprintf(tw.w, "Risk: %.0f", m.RiskScore)
			}
			fmt.Fprintln(tw.w)
		}
		if m.Advisory.URL != "" {
			fmt.Fprintf(tw.w, "    %s\n", m.Advisory.URL)
		}
	}
	fmt.Fprintln(tw.w)
	return nil
}

func (tw *textWriter) WriteSummary(s Summary, totalDevices int) error {
	fmt.Fprintf(tw.w, "[deadband] Summary: %d VULNERABLE, %d POTENTIAL, %d OK (of %d checked; %d no advisory match)\n",
		s.Vulnerable, s.Potential, s.OK, totalDevices, s.NoMatch)
	return nil
}

func (tw *textWriter) Flush() error {
	return nil
}
