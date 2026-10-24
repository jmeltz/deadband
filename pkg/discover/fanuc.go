// Package discover — Fanuc CNC and robot controller discovery.
//
// Fanuc fingerprinting fans out four independent unauthenticated, read-only
// probes against each candidate IP and selects the highest-confidence hit,
// with CIP > FOCAS2 > FTP > HTTP precedence:
//
//  1. EtherNet/IP CIP ListIdentity on UDP/44818. Matches BOTH ODVA Vendor IDs
//     registered to Fanuc: 591 ("FANUC Ltd." — Series 30i/31i/32i/0i CNCs) and
//     356 ("Fanuc Robotics America" — R-30iA / R-30iB / R-30iB Plus robots).
//
//  2. FOCAS2 read-only session + cnc_sysinfo on TCP/8193. Negotiates an
//     embedded-Ethernet FOCAS2 handle (0xA0A0A0A0 OPN_REQU), issues the
//     read-only cnc_sysinfo [1,1,0x18] query to unpack the 18-byte ODBSYS
//     identity struct (CNC series, M/T machining type, firmware series &
//     version, controlled axes), and sends CLS_REQU (0x0201) before closing
//     so finite embedded CNC socket slots are freed immediately.
//
//  3. Multi-line RFC 959 FTP banner grab on TCP/21 (zero bytes transmitted).
//     Reads continuation `220-...` lines through `220 ` to catch VxWorks
//     R-30iB robot multi-line banners as well as single-line CNC banners.
//
//  4. HTTP fingerprint on TCP/80 for iPendant / KAREL / .stm robot web servers.
package discover

import (
	"bufio"
	"encoding/binary"
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
	Series  string // e.g. "Series 31i-M", "30I-B", "0I-MF", "R-30IB PLUS"
	Version string // firmware/software version when present
	Serial  string // hex serial when reported via CIP
	Banner  string // raw evidence (FOCAS ODBSYS, FTP banner, CIP product, HTML)
	Source  string // "cip", "focas", "ftp", or "http"
}

var (
	fanucBannerRE = regexp.MustCompile(
		`(?i)(\bfanuc\b|R-30i[ABM]|HandlingTool|ArcTool|SpotTool|PaintTool|DispenseTool|PalletTool|(?:^|\n)220[\s-]+ROBOT\s+FTP)`,
	)
	fanucSeriesRE = regexp.MustCompile(
		`(?i)\b(?:series\s+)?(R-30i[ABM](?:\s+(?:Mate|Mini|Compact))?(?:\s+Plus)?|[0-9]{1,2}i(?:[a-z](?:[+-][a-z0-9]+)?)?(?:-[a-z0-9]+)?(?:\s+Plus)?)\b`,
	)
	fanucVersionRE = regexp.MustCompile(`(?i)\bversion\s+(\S+)`)
	fanucAppTagRE  = regexp.MustCompile(`\[((?:HandlingTool|ArcTool|SpotTool|PaintTool|DispenseTool|PalletTool)[^\]]*)\]`)
	fanucHTTPRE    = regexp.MustCompile(
		`(?i)(iPendant|FANUC\s+Robotics|FANUC\s+CORPORATION|R-30i[ABM]|/KAREL/|webpanel\.htm|\.stm\b)`,
	)
	fanucHTTPModelRE = regexp.MustCompile(
		`(?i)\b(R-30i[ABM](?:\s+(?:Mate|Mini|Compact))?(?:\s+Plus)?|[0-9]{1,2}i(?:[a-z](?:[+-][a-z0-9]+)?)?(?:-[a-z0-9]+)?(?:\s+Plus)?)\b`,
	)
)

const (
	focasFrameMagic uint32 = 0xA0A0A0A0
	focasOpenReq    uint16 = 0x0101
	focasOpenResp   uint16 = 0x0102
	focasCloseReq   uint16 = 0x0201
	focasVarReq     uint16 = 0x2101
	focasVarResp    uint16 = 0x2102
)

// FanucCIP probes UDP/44818 with an EtherNet/IP ListIdentity request and
// reports a Fanuc identity if VendorID matches FANUC Ltd. (591) or Fanuc
// Robotics America (356).
func FanucCIP(ip string, timeout time.Duration) (*FanucIdentity, error) {
	cip, err := ListIdentityUnicast(ip, timeout)
	if err != nil || cip == nil {
		return nil, nil
	}
	if !IsFanucCIPVendorID(cip.VendorID) {
		return nil, nil
	}
	var serial string
	if cip.Serial != 0 {
		serial = fmt.Sprintf("%08X", cip.Serial)
	}
	return &FanucIdentity{
		Series:  strings.TrimSpace(cip.ProductName),
		Version: fmt.Sprintf("%d.%d", cip.RevMajor, cip.RevMinor),
		Serial:  serial,
		Banner:  fmt.Sprintf("CIP vendor=%d product=%q rev=%d.%d", cip.VendorID, cip.ProductName, cip.RevMajor, cip.RevMinor),
		Source:  "cip",
	}, nil
}

// buildFOCASOpenReq builds the 12-byte FOCAS2 session open request.
func buildFOCASOpenReq() []byte {
	return []byte{0xA0, 0xA0, 0xA0, 0xA0, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x02}
}

// buildFOCASSysInfoReq builds the 40-byte read-only cnc_sysinfo (1, 1, 0x18) FOCAS2 request.
func buildFOCASSysInfoReq() []byte {
	pkt := make([]byte, 40)
	binary.BigEndian.PutUint32(pkt[0:4], focasFrameMagic)
	binary.BigEndian.PutUint16(pkt[4:6], 0x0001)
	binary.BigEndian.PutUint16(pkt[6:8], focasVarReq)
	binary.BigEndian.PutUint16(pkt[8:10], 30)     // outer payload len
	binary.BigEndian.PutUint16(pkt[10:12], 1)     // 1 subcommand
	binary.BigEndian.PutUint16(pkt[12:14], 28)    // subcommand len (2 + 26)
	binary.BigEndian.PutUint16(pkt[14:16], 1)     // c1 = 1
	binary.BigEndian.PutUint16(pkt[16:18], 1)     // c2 = 1
	binary.BigEndian.PutUint16(pkt[18:20], 0x0018) // c3 = 0x18 (cnc_sysinfo)
	// bytes [20:40] = 5 int32 zero args
	return pkt
}

// buildFOCASCloseReq builds the 10-byte FOCAS2 handle release request so we
// never leak finite embedded Ethernet socket slots on the CNC.
func buildFOCASCloseReq() []byte {
	return []byte{0xA0, 0xA0, 0xA0, 0xA0, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00}
}

func readFOCASFrame(r io.Reader) (ftype uint16, payload []byte, err error) {
	var hdr [10]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != focasFrameMagic {
		return 0, nil, fmt.Errorf("invalid FOCAS frame magic")
	}
	ftype = binary.BigEndian.Uint16(hdr[6:8])
	plen := int(binary.BigEndian.Uint16(hdr[8:10]))
	if plen > 4096 {
		return 0, nil, fmt.Errorf("oversized FOCAS payload: %d", plen)
	}
	if plen == 0 {
		return ftype, nil, nil
	}
	payload = make([]byte, plen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return ftype, payload, nil
}

func formatFOCASModel(cncType, mtType string) string {
	ct := strings.TrimSpace(cncType)
	mt := strings.TrimSpace(mtType)
	var base string
	switch ct {
	case "0":
		base = "Series 0i"
	case "15":
		base = "Series 15i"
	case "16":
		base = "Series 16i"
	case "18":
		base = "Series 18i"
	case "21":
		base = "Series 21i"
	case "30":
		base = "Series 30i"
	case "31":
		base = "Series 31i"
	case "32":
		base = "Series 32i"
	case "35":
		base = "Series 35i"
	case "PD":
		base = "Power Motion i"
	default:
		if ct != "" {
			base = "Series " + ct
		} else {
			base = "CNC (FOCAS2)"
		}
	}
	if mt != "" {
		return base + "-" + mt
	}
	return base
}

func cleanFOCASASCII(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x21 && c <= 0x7E {
			sb.WriteByte(c)
		} else if c == ' ' {
			sb.WriteByte(' ')
		}
	}
	return strings.TrimSpace(sb.String())
}

// ParseFOCASSysInfoPayload extracts Series + Version from a FOCAS2 VAR_RESP
// payload carrying the 18-byte ODBSYS struct.
func ParseFOCASSysInfoPayload(payload []byte) (model, version, banner string, ok bool) {
	// Expected layout: qu(2) + le(2) + cmd(6) + status(6) + dataLen(2) + ODBSYS(18) = 36 bytes
	if len(payload) < 36 {
		return "", "", "", false
	}
	qu := binary.BigEndian.Uint16(payload[0:2])
	subLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if qu < 1 || subLen < 32 || 4+subLen-2 > len(payload) {
		return "", "", "", false
	}
	sub := payload[4:]
	// Verify echoed command (1, 1, 0x18) and 6 zero status bytes
	if binary.BigEndian.Uint16(sub[0:2]) != 1 ||
		binary.BigEndian.Uint16(sub[2:4]) != 1 ||
		binary.BigEndian.Uint16(sub[4:6]) != 0x0018 {
		return "", "", "", false
	}
	for i := 6; i < 12; i++ {
		if sub[i] != 0 {
			return "", "", "", false
		}
	}
	dataLen := int(binary.BigEndian.Uint16(sub[12:14]))
	if dataLen < 18 || len(sub) < 14+18 {
		return "", "", "", false
	}
	odbsys := sub[14 : 14+18]
	maxAxis := binary.BigEndian.Uint16(odbsys[2:4])
	cncType := cleanFOCASASCII(odbsys[4:6])
	mtType := cleanFOCASASCII(odbsys[6:8])
	seriesCode := cleanFOCASASCII(odbsys[8:12])
	swVer := cleanFOCASASCII(odbsys[12:16])
	axes := cleanFOCASASCII(odbsys[16:18])

	model = formatFOCASModel(cncType, mtType)
	if seriesCode != "" && swVer != "" {
		version = seriesCode + "/" + swVer
	} else if swVer != "" {
		version = swVer
	} else {
		version = seriesCode
	}
	banner = fmt.Sprintf("FOCAS2 ODBSYS model=%q series=%q ver=%q axes=%s/%d",
		model, seriesCode, swVer, axes, maxAxis)
	return model, version, banner, true
}

// FanucFOCAS2Probe connects to TCP/8193, negotiates a FOCAS2 handle, executes
// a read-only cnc_sysinfo query, and sends CLS_REQU before closing.
func FanucFOCAS2Probe(ip string, timeout time.Duration) (*FanucIdentity, error) {
	return fanucFOCAS2At(net.JoinHostPort(ip, fmt.Sprintf("%d", FanucFOCASPort)), timeout)
}

func fanucFOCAS2At(addr string, timeout time.Duration) (*FanucIdentity, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildFOCASOpenReq()); err != nil {
		return nil, nil
	}
	ftype, _, err := readFOCASFrame(conn)
	if err != nil || ftype != focasOpenResp {
		return nil, nil
	}

	// Ensure we always release the CNC socket slot cleanly before closing TCP.
	defer func() {
		_ = conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
		_, _ = conn.Write(buildFOCASCloseReq())
		var drain [32]byte
		_, _ = conn.Read(drain[:])
	}()

	id := &FanucIdentity{
		Series: "CNC (FOCAS2)",
		Banner: "FOCAS2 session established on TCP/8193",
		Source: "focas",
	}

	if _, err := conn.Write(buildFOCASSysInfoReq()); err == nil {
		if vtype, payload, rerr := readFOCASFrame(conn); rerr == nil && vtype == focasVarResp {
			if model, ver, banner, ok := ParseFOCASSysInfoPayload(payload); ok {
				id.Series = model
				id.Version = ver
				id.Banner = banner
			}
		}
	}
	return id, nil
}

// FanucFTPBanner connects to TCP/21 and reads single- or multi-line RFC 959
// 220 welcome banners without transmitting a single byte.
func FanucFTPBanner(ip string, timeout time.Duration) (*FanucIdentity, error) {
	return fanucFTPAt(net.JoinHostPort(ip, fmt.Sprintf("%d", FanucFTPPort)), timeout)
}

func fanucFTPAt(addr string, timeout time.Duration) (*FanucIdentity, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(io.LimitReader(conn, 2048))
	var lines []string
	for i := 0; i < 8; i++ {
		line, err := r.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
		// RFC 959: "220-" continues onto subsequent lines until "220 "
		if strings.HasPrefix(trimmed, "220 ") || !strings.HasPrefix(trimmed, "220-") {
			break
		}
		if err != nil {
			break
		}
	}
	return parseFanucFTPBannerText(strings.Join(lines, "\n")), nil
}

func parseFanucFTPBannerText(banner string) *FanucIdentity {
	banner = strings.TrimSpace(banner)
	if !strings.HasPrefix(banner, "220") {
		return nil
	}
	if !fanucBannerRE.MatchString(banner) {
		return nil
	}

	flat := strings.ReplaceAll(banner, "\n", " | ")
	id := &FanucIdentity{Banner: flat, Source: "ftp"}
	if m := fanucSeriesRE.FindStringSubmatch(banner); len(m) >= 2 {
		id.Series = strings.ToUpper(strings.Join(strings.Fields(m[1]), " "))
	}
	if m := fanucVersionRE.FindStringSubmatch(banner); len(m) >= 2 {
		id.Version = m[1]
	}
	if m := fanucAppTagRE.FindStringSubmatch(banner); len(m) >= 2 && id.Version == "" {
		id.Version = m[1]
	}
	return id
}

// FanucHTTP fetches GET / over plain HTTP and returns a Fanuc identity if
// any well-known iPendant / FANUC Robotics signals appear.
func FanucHTTP(ip string, timeout time.Duration) (*FanucIdentity, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", net.JoinHostPort(ip, "80")), nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "deadband/0.6")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil && len(body) == 0 {
		return nil, nil
	}
	// Check Location redirect header too (e.g. Location: /MD/index_tp.htm or /fr/webpanel.stm)
	combined := resp.Header.Get("Location") + "\n" + string(body)
	if !fanucHTTPRE.MatchString(combined) {
		return nil, nil
	}

	id := &FanucIdentity{
		Banner: fmt.Sprintf("HTTP %s — %s", resp.Status, firstLine(combined)),
		Source: "http",
	}
	if m := fanucHTTPModelRE.FindStringSubmatch(combined); len(m) >= 2 {
		id.Series = strings.ToUpper(strings.Join(strings.Fields(m[1]), " "))
	}
	return id, nil
}

// FanucProbe runs all four Fanuc fingerprints concurrently against ip and
// returns the highest-confidence hit with CIP > FOCAS2 > FTP > HTTP precedence.
func FanucProbe(ip string, timeout time.Duration, verbose func(string)) *FanucIdentity {
	var (
		mu      sync.Mutex
		cipID   *FanucIdentity
		focasID *FanucIdentity
		ftpID   *FanucIdentity
		httpID  *FanucIdentity
		wg      sync.WaitGroup
	)

	wg.Add(4)
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
		id, _ := FanucFOCAS2Probe(ip, timeout)
		mu.Lock()
		focasID = id
		mu.Unlock()
		if verbose != nil {
			if id == nil {
				verbose(fmt.Sprintf("Fanuc FOCAS2 probe (%s:%d): no FOCAS2 response", ip, FanucFOCASPort))
			} else {
				verbose(fmt.Sprintf("Fanuc FOCAS2 probe (%s:%d): %s", ip, FanucFOCASPort, id.Banner))
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
	case focasID != nil:
		return focasID
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
		Serial:   id.Serial,
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
	case "focas":
		return FanucFOCASPort
	case "http":
		return 80
	default:
		return FanucFTPPort
	}
}

func discoverFanuc(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("Fanuc: probing %d host(s) — CIP/UDP %d, FOCAS2/TCP %d, FTP/TCP %d, HTTP/TCP 80",
			len(ips), EIPPort, FanucFOCASPort, FanucFTPPort))
	}

	verbose := func(s string) {}
	if progress != nil && len(ips) == 1 {
		verbose = progress
	}

	hostConc := concurrency / 4
	if hostConc < 1 {
		hostConc = 1
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		devices []inventory.Device
		sem     = make(chan struct{}, hostConc)
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
