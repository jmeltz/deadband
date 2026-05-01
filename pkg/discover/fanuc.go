// Package discover — Fanuc CNC controller discovery.
//
// Fanuc controllers expose two interesting surfaces:
//
//  1. FTP on TCP/21 (this milestone). The 220 banner reliably identifies
//     Fanuc controllers and often reveals the controller series (30i-B, 31i,
//     0i-MD, etc.) and a software version string.
//
//  2. FOCAS2 on TCP/8193 (deferred). FOCAS2 is the proprietary CNC interface;
//     no public wire-protocol spec, requires Fanuc's libfwlib32 in practice.
//     Stubbed out here so the surface exists for future work once we secure
//     access to a live Fanuc device for development.
//
// The FTP banner-grab is purely passive: connect, read the 220 line, close.
// We do NOT issue USER, PASS, or any other FTP command — no auth attempts,
// no state changes.
package discover

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// FanucIdentity is the parsed result of an FTP banner grab.
type FanucIdentity struct {
	Series  string // e.g. "30i-B", "0i-MD"
	Version string // raw banner-derived version string when present
	Banner  string // full trimmed banner line (kept for diagnostics)
}

// errFanucFOCAS2NotImplemented is returned by the FOCAS2 stub.
var errFanucFOCAS2NotImplemented = errors.New("FANUC FOCAS2 probing is not implemented in this release")

// fanucBannerSeries matches Fanuc-style FTP banners. Real-world samples:
//
//	"220 FANUC SERIES 30i-B FTP server ready."
//	"220 FANUC 0i-MD ready."
//	"220-FANUC LTD. R-30iB ROBOT FTP SERVICE"
var (
	fanucSeriesRE  = regexp.MustCompile(`(?i)\b(?:series\s+)?(?:r-)?([0-9]{1,2}i(?:[a-z](?:[+-][a-z0-9]+)?)?(?:-[a-z0-9]+)?)\b`)
	fanucBannerRE  = regexp.MustCompile(`(?i)\bfanuc\b`)
	fanucVersionRE = regexp.MustCompile(`(?i)\bversion\s+(\S+)`)
)

// FanucFTPBanner connects to TCP/21 and reads the 220 banner. Returns nil, nil
// if the host doesn't respond or the banner doesn't look Fanuc.
func FanucFTPBanner(ip string, timeout time.Duration) (*FanucIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", FanucFTPPort))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return nil, nil
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "220") {
		return nil, nil
	}
	if !fanucBannerRE.MatchString(line) {
		return nil, nil
	}

	id := &FanucIdentity{Banner: line}
	if m := fanucSeriesRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Series = strings.ToUpper(m[1])
	}
	if m := fanucVersionRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Version = m[1]
	}
	return id, nil
}

// FanucFOCAS2Probe is a placeholder for future FOCAS2 (TCP/8193) work.
// Always returns errFanucFOCAS2NotImplemented; kept so callers can introspect
// the planned surface without conditional compilation.
func FanucFOCAS2Probe(_ string, _ time.Duration) (*FanucIdentity, error) {
	return nil, errFanucFOCAS2NotImplemented
}

// FanucIdentityToDevice converts a FanucIdentity to an inventory.Device.
func FanucIdentityToDevice(ip string, id *FanucIdentity) inventory.Device {
	model := id.Series
	if model == "" {
		model = "Unknown Series"
	}
	dev := inventory.Device{
		IP:       ip,
		Vendor:   "Fanuc",
		Model:    model,
		Firmware: id.Version,
		Protocol: "fanuc-ftp",
		Port:     FanucFTPPort,
	}
	if id.Banner != "" {
		dev.Extra = map[string]string{"banner": id.Banner}
	}
	return dev
}

// discoverFanucFTP runs FanucFTPBanner over a slice of IPs concurrently.
func discoverFanucFTP(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("Fanuc: probing %d hosts on TCP/%d (FTP banner)", len(ips), FanucFTPPort))
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		devices []inventory.Device
		sem     = make(chan struct{}, concurrency)
	)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			id, err := FanucFTPBanner(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := FanucIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()

			if progress != nil {
				progress(fmt.Sprintf("Fanuc: %s → %s", ip, dev.Model))
			}
		}(ip)
	}

	wg.Wait()
	return devices
}
