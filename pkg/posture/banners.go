package posture

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// BannerResult holds data extracted from a protocol banner grab.
type BannerResult struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Banner  string `json:"banner"`
	Product string `json:"product,omitempty"` // parsed product name if identifiable
	Version string `json:"version,omitempty"` // parsed version if identifiable
}

// --- SSH banner ---

// ProbeSSH connects to an SSH server and reads the identification string.
// SSH servers send their version immediately on connect (RFC 4253 §4.2),
// e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4".
func ProbeSSH(ip string, timeout time.Duration) (*BannerResult, error) {
	addr := net.JoinHostPort(ip, "22")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	banner := strings.TrimSpace(line)
	if banner == "" {
		return nil, fmt.Errorf("empty SSH banner")
	}

	res := &BannerResult{
		Port:   22,
		Proto:  "SSH",
		Banner: banner,
	}

	// Parse "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
	if parts := strings.SplitN(banner, "-", 4); len(parts) >= 3 {
		soft := parts[2]
		if len(parts) == 4 {
			soft = parts[2] + "-" + parts[3]
		}
		// Split on first space for comment
		if sp := strings.IndexByte(soft, ' '); sp > 0 {
			res.Product = soft[:sp]
			res.Version = strings.TrimSpace(soft[sp+1:])
		} else {
			res.Product = soft
		}
	}

	return res, nil
}

// --- HTTP server header ---

// ProbeHTTP sends a HEAD request and extracts the Server header and
// HTML <title> from the response. Works for both HTTP and HTTPS.
func ProbeHTTP(ip string, port int, timeout time.Duration) (*BannerResult, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	res := &BannerResult{
		Port:  port,
		Proto: strings.ToUpper(scheme),
	}

	server := resp.Header.Get("Server")
	if server != "" {
		res.Banner = server
		res.Product = server
	}

	// Try to grab <title> from small initial body read
	body := make([]byte, 4096)
	n, _ := io.ReadFull(resp.Body, body)
	if n > 0 {
		title := extractTitle(string(body[:n]))
		if title != "" {
			if res.Banner != "" {
				res.Banner += " — " + title
			} else {
				res.Banner = title
			}
		}
	}

	if res.Banner == "" {
		res.Banner = fmt.Sprintf("%s %s", resp.Proto, resp.Status)
	}

	return res, nil
}

func extractTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title>")
	if start < 0 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(html[start : start+end])
	if len(title) > 120 {
		title = title[:120] + "…"
	}
	return title
}

// --- Telnet banner ---

// ProbeTelnet connects to a Telnet port and reads the initial banner
// the device sends. Many managed switches and routers identify themselves
// in the login prompt.
func ProbeTelnet(ip string, timeout time.Duration) (*BannerResult, error) {
	addr := net.JoinHostPort(ip, "23")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}

	// Strip telnet IAC sequences (0xFF xx xx)
	clean := stripTelnetIAC(buf[:n])
	banner := strings.TrimSpace(string(clean))
	if banner == "" {
		return nil, fmt.Errorf("empty telnet banner")
	}

	// Truncate to first meaningful line(s)
	lines := strings.SplitN(banner, "\n", 5)
	var meaningful []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			meaningful = append(meaningful, l)
		}
	}
	if len(meaningful) == 0 {
		return nil, fmt.Errorf("empty telnet banner after cleanup")
	}
	banner = strings.Join(meaningful, " | ")
	if len(banner) > 200 {
		banner = banner[:200] + "…"
	}

	return &BannerResult{
		Port:   23,
		Proto:  "Telnet",
		Banner: banner,
	}, nil
}

func stripTelnetIAC(data []byte) []byte {
	var out []byte
	for i := 0; i < len(data); {
		if data[i] == 0xFF && i+2 < len(data) {
			// IAC command — skip 3 bytes (or 2 for some)
			cmd := data[i+1]
			if cmd == 0xFA {
				// Sub-negotiation: skip until IAC SE (0xFF 0xF0)
				j := i + 2
				for j < len(data)-1 {
					if data[j] == 0xFF && data[j+1] == 0xF0 {
						j += 2
						break
					}
					j++
				}
				i = j
			} else {
				i += 3
			}
		} else {
			out = append(out, data[i])
			i++
		}
	}
	return out
}

// --- SNMP sysDescr ---

// ProbeSNMP sends an SNMP v2c GET request for sysDescr.0
// (OID 1.3.6.1.2.1.1.1.0) using community string "public".
// Most managed network devices respond with a description like
// "Cisco IOS Software, C2960 Software ...".
func ProbeSNMP(ip string, timeout time.Duration) (*BannerResult, error) {
	addr := net.JoinHostPort(ip, "161")
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Pre-built SNMP v2c GET for sysDescr.0
	if _, err := conn.Write(snmpGetSysDescr); err != nil {
		return nil, err
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	desc := parseSNMPString(buf[:n])
	if desc == "" {
		return nil, fmt.Errorf("no sysDescr in response")
	}
	if len(desc) > 300 {
		desc = desc[:300] + "…"
	}

	return &BannerResult{
		Port:   161,
		Proto:  "SNMP",
		Banner: desc,
	}, nil
}

// snmpGetSysDescr is a pre-encoded SNMPv2c GET-REQUEST for
// OID 1.3.6.1.2.1.1.1.0 (sysDescr.0) with community "public".
var snmpGetSysDescr = []byte{
	0x30, 0x29, // SEQUENCE, length 41
	0x02, 0x01, 0x01, // INTEGER: version = 1 (SNMPv2c)
	0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING: "public"
	0xa0, 0x1c, // GET-REQUEST PDU, length 28
	0x02, 0x04, 0x01, 0x02, 0x03, 0x04, // INTEGER: request-id
	0x02, 0x01, 0x00, // INTEGER: error-status = 0
	0x02, 0x01, 0x00, // INTEGER: error-index = 0
	0x30, 0x0e, // SEQUENCE (varbind list)
	0x30, 0x0c, // SEQUENCE (varbind)
	0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
	0x05, 0x00, // NULL
}

// parseSNMPString does a minimal walk of the SNMP response to extract
// the first OCTET STRING value (the sysDescr).
func parseSNMPString(data []byte) string {
	// Walk through looking for an OCTET STRING (0x04) that follows
	// the OID for sysDescr.
	sysDescrOID := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	idx := 0
	for idx < len(data)-len(sysDescrOID) {
		// Find the OID
		if data[idx] == 0x06 { // OID tag
			oidLen := int(data[idx+1])
			if idx+2+oidLen <= len(data) {
				oid := data[idx+2 : idx+2+oidLen]
				if bytesEqual(oid, sysDescrOID) {
					// Next TLV should be the value
					valIdx := idx + 2 + oidLen
					if valIdx < len(data) && data[valIdx] == 0x04 { // OCTET STRING
						vLen, hdrLen := decodeASN1Len(data[valIdx+1:])
						start := valIdx + 1 + hdrLen
						if start+vLen <= len(data) {
							return string(data[start : start+vLen])
						}
					}
				}
			}
		}
		idx++
	}
	return ""
}

func decodeASN1Len(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 2 || len(data) < 1+numBytes {
		return 0, 1
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
