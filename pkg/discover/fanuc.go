// Package discover — Fanuc CNC and robot controller discovery.
//
// Fanuc fingerprinting fans out three independent unauthenticated, read-only
// probes against each candidate IP and takes the first positive hit, with
// CIP > FTP > HTTP precedence:
//
//  1. EtherNet/IP CIP ListIdentity on UDP/44818. Highest-confidence — Fanuc's
//     ODVA Vendor ID (252) is unique to them. Most R-30iB+ robot controllers
//     and modern CNCs ship with the EtherNet/IP option enabled by default.
//
//  2. FTP banner grab on TCP/21. Catches both CNC ("FANUC SERIES 30i-B") and
//     robot ("R-30iB", "HandlingTool", "ArcTool", bare "ROBOT FTP server")
//     banner formats. The earlier release was over-strict on the literal
//     "FANUC" substring and missed every robot controller on the market.
//
//  3. HTTP fingerprint on TCP/80. Last-resort signal that uses iPendant /
//     Fanuc Robotics page strings and Fanuc-only paths (`.stm`, `/MD/`,
//     `/FR/`, `/KAREL/`).
//
// FOCAS2 (TCP/8193) remains stubbed — it only applies to CNC, not robots,
// and has no public wire-protocol spec.
//
// All three probes are read-only by construction: CIP ListIdentity is the
// 24-byte ODVA-spec'd discovery message, FTP just reads the 220 banner with
// no commands issued, and HTTP only sends a single `GET /` request.
package discover

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// FanucIdentity carries whatever a successful probe could extract from a
// Fanuc controller. Fields are best-effort; only Source is guaranteed.
type FanucIdentity struct {
	Series  string // e.g. "30i-B", "0i-MD", "R-30iB"
	Version string // firmware/software version when present
	Banner  string // raw evidence (FTP banner line, CIP product name, HTML title)
	Source  string // "cip", "ftp", or "http" — which probe succeeded
}

// errFanucFOCAS2NotImplemented is returned by the FOCAS2 stub.
var errFanucFOCAS2NotImplemented = errors.New("FANUC FOCAS2 probing is not implemented in this release")

// fanucBannerRE matches Fanuc-style FTP banners, both CNC and robot. Real
// banner samples covered:
//
//	"220 FANUC SERIES 30i-B FTP server ready."        (CNC)
//	"220 FANUC 0i-MD ready."                          (CNC)
//	"220-FANUC LTD. R-30iB ROBOT FTP SERVICE"         (robot, multi-line)
//	"220 R-30iB FTP server ready. [HandlingTool V8.20P/06]"  (robot, no FANUC literal)
//	"220 ROBOT FTP server ready."                     (robot, default hostname)
var (
	fanucBannerRE = regexp.MustCompile(
		`(?i)(\bfanuc\b|R-30i[ABM]|HandlingTool|ArcTool|SpotTool|PaintTool|DispenseTool|PalletTool|^220[\s-]+ROBOT\s+FTP)`,
	)
	fanucSeriesRE  = regexp.MustCompile(`(?i)\b(?:series\s+)?(R-30i[ABM]|[0-9]{1,2}i(?:[a-z](?:[+-][a-z0-9]+)?)?(?:-[a-z0-9]+)?)\b`)
	fanucVersionRE = regexp.MustCompile(`(?i)\bversion\s+(\S+)`)
	// fanucAppTagRE captures the bracketed application tag emitted by some
	// VxWorks robot FTP servers, e.g. "[HandlingTool V8.20P/06]".
	fanucAppTagRE = regexp.MustCompile(`\[((?:HandlingTool|ArcTool|SpotTool|PaintTool|DispenseTool|PalletTool)[^\]]*)\]`)
	fanucHTTPRE   = regexp.MustCompile(
		`(?i)(iPendant|FANUC\s+Robotics|FANUC\s+CORPORATION|R-30i[ABM]|/KAREL/|webpanel\.htm|\.stm\b)`,
	)
	fanucHTTPModelRE = regexp.MustCompile(`(?i)\b(R-30i[ABM]|[0-9]{1,2}i(?:[a-z](?:[+-][a-z0-9]+)?)?(?:-[a-z0-9]+)?)\b`)
)

// FanucCIP probes UDP/44818 with an EtherNet/IP ListIdentity request and
// reports a Fanuc identity if VendorID matches the ODVA registry value (252).
// Returns nil, nil on any failure mode (no response, parse error, wrong
// vendor) — the caller treats nil as "this probe didn't fingerprint Fanuc".
func FanucCIP(ip string, timeout time.Duration) (*FanucIdentity, error) {
	cip, err := ListIdentityUnicast(ip, timeout)
	if err != nil || cip == nil {
		return nil, nil
	}
	if cip.VendorID != FanucCIPVendorID {
		return nil, nil
	}
	id := &FanucIdentity{
		Series:  strings.TrimSpace(cip.ProductName),
		Version: fmt.Sprintf("%d.%d", cip.RevMajor, cip.RevMinor),
		Banner:  fmt.Sprintf("CIP vendor=%d product=%q rev=%d.%d", cip.VendorID, cip.ProductName, cip.RevMajor, cip.RevMinor),
		Source:  "cip",
	}
	return id, nil
}

// FanucFTPBanner connects to TCP/21 and reads the 220 banner. Returns nil, nil
// if the host doesn't respond or the banner doesn't match a known Fanuc
// (CNC or robot) pattern.
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

	id := &FanucIdentity{Banner: line, Source: "ftp"}
	if m := fanucSeriesRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Series = strings.ToUpper(m[1])
	}
	if m := fanucVersionRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Version = m[1]
	}
	// Robot banner application tag ("[HandlingTool V8.20P/06]") is the most
	// reliable firmware signal we get over FTP. Captures whole tag including
	// the version.
	if m := fanucAppTagRE.FindStringSubmatch(line); len(m) >= 2 && id.Version == "" {
		id.Version = m[1]
	}
	return id, nil
}

// FanucHTTP fetches GET / over plain HTTP and returns a Fanuc identity if
// any of the well-known iPendant / FANUC Robotics signals appear in the
// response body or path set. Read-only — only a single GET is issued.
func FanucHTTP(ip string, timeout time.Duration) (*FanucIdentity, error) {
	client := &http.Client{
		Timeout: timeout,
		// Don't follow redirects — Fanuc iPendant often redirects to a
		// language-specific path; we only want the entry-page fingerprint.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", net.JoinHostPort(ip, "80")), nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "deadband/0.5")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Cap the read so a hostile or huge response can't blow memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil && len(body) == 0 {
		return nil, nil
	}
	bodyStr := string(body)
	if !fanucHTTPRE.MatchString(bodyStr) {
		return nil, nil
	}

	id := &FanucIdentity{
		Banner: fmt.Sprintf("HTTP %s — %s", resp.Status, firstLine(bodyStr)),
		Source: "http",
	}
	if m := fanucHTTPModelRE.FindStringSubmatch(bodyStr); len(m) >= 2 {
		id.Series = strings.ToUpper(m[1])
	}
	return id, nil
}

// FanucFOCAS2Probe is a placeholder. Robots don't run FOCAS, and CNC FOCAS2
// requires Fanuc's proprietary libfwlib32 to negotiate. Kept so callers can
// surface the planned probe without conditional compilation.
func FanucFOCAS2Probe(_ string, _ time.Duration) (*FanucIdentity, error) {
	return nil, errFanucFOCAS2NotImplemented
}

// FanucProbe runs all three Fanuc fingerprints concurrently against ip and
// returns the first positive hit, with CIP > FTP > HTTP precedence. Each
// probe receives the full timeout; total wall-clock is bounded by max of
// the three. The verbose progress callback (when non-nil) reports per-probe
// outcomes so an operator running `--mode fanuc` against unresponsive
// hardware can see which surface failed.
func FanucProbe(ip string, timeout time.Duration, verbose func(string)) *FanucIdentity {
	var (
		mu       sync.Mutex
		cipID    *FanucIdentity
		ftpID    *FanucIdentity
		httpID   *FanucIdentity
		wg       sync.WaitGroup
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		id, _ := FanucCIP(ip, timeout)
		mu.Lock()
		cipID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Fanuc CIP probe (%s:%d): no Fanuc identity", ip, EIPPort))
			} else {
				verbose(fmt.Sprintf("Fanuc CIP probe (%s:%d): %s", ip, EIPPort, id.Banner))
			}
		}
	}()
	go func() {
		defer wg.Done()
		id, _ := FanucFTPBanner(ip, timeout)
		mu.Lock()
		ftpID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Fanuc FTP probe (%s:%d): no Fanuc banner", ip, FanucFTPPort))
			} else {
				verbose(fmt.Sprintf("Fanuc FTP probe (%s:%d): %s", ip, FanucFTPPort, id.Banner))
			}
		}
	}()
	go func() {
		defer wg.Done()
		id, _ := FanucHTTP(ip, timeout)
		mu.Lock()
		httpID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Fanuc HTTP probe (%s:80): no Fanuc fingerprint", ip))
			} else {
				verbose(fmt.Sprintf("Fanuc HTTP probe (%s:80): %s", ip, id.Banner))
			}
		}
	}()
	wg.Wait()

	switch {
	case cipID != nil:
		return cipID
	case ftpID != nil:
		return ftpID
	case httpID != nil:
		return httpID
	default:
		return nil
	}
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
		Protocol: "fanuc-" + id.Source,
		Port:     fanucPortFor(id.Source),
	}
	if id.Banner != "" {
		dev.Extra = map[string]string{"banner": id.Banner, "probe": id.Source}
	}
	return dev
}

func fanucPortFor(source string) int {
	switch source {
	case "cip":
		return EIPPort
	case "http":
		return 80
	default:
		return FanucFTPPort
	}
}

// discoverFanuc runs FanucProbe over a slice of IPs concurrently. Verbose
// per-probe progress is emitted only when a single host is being scanned —
// auto-mode and large CIDR sweeps stay quiet to avoid log spam.
func discoverFanuc(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("Fanuc: probing %d host(s) — CIP/UDP %d, FTP/TCP %d, HTTP/TCP 80",
			len(ips), EIPPort, FanucFTPPort))
	}

	verbose := func(s string) {}
	if progress != nil && len(ips) == 1 {
		verbose = progress
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

			id := FanucProbe(ip, timeout, verbose)
			if id == nil {
				return
			}

			dev := FanucIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()

			if progress != nil {
				progress(fmt.Sprintf("Fanuc: %s → %s (via %s)", ip, dev.Model, id.Source))
			}
		}(ip)
	}

	wg.Wait()
	return devices
}

// firstLine returns the first non-empty line of s, trimmed and capped at 120
// chars — used for compact diagnostic strings that get logged.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 120 {
			line = line[:120] + "..."
		}
		return line
	}
	return ""
}
