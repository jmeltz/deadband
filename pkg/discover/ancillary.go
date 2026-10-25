package discover

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// Ancillary Infrastructure, Cold-Chain Refrigeration, EMS & Intralogistics WCS
// Read-Only HTTP / HTTPS + TLS Certificate Fingerprinter (ports 80, 443, 8080, 8443).
//
// SAFETY INVARIANTS:
//   1. Strictly issues a single read-only HTTP GET "/" with a 64 KiB body cap.
//   2. NEVER connects to raw printer port TCP/9100 (which would cause Zebra/industrial
//      thermal printers to physically print HTTP headers onto shipping labels).
//   3. Only emits an inventory.Device when a high-confidence OT, intralogistics,
//      cold-chain refrigeration, regulated EMS, or server-room HVAC/UPS signature
//      matches — generic IT web servers (nginx/Apache/IIS without OT signatures) are ignored.

var ancillaryPorts = []int{443, 80, 8443, 8080}

type ancillarySignature struct {
	vendor        string
	defaultModel  string
	matchRe       *regexp.Regexp
	modelExtract  *regexp.Regexp
	fwExtract     *regexp.Regexp
}

var ancillarySignatures = []ancillarySignature{
	// --- KNAPP & Warehouse Execution / Shuttle Automation ---
	{
		vendor:       "KNAPP",
		defaultModel: "KiSoft WCS / OSR Gateway",
		matchRe:      regexp.MustCompile(`(?i)\b(kisoft|knapp\s+ag|osr\s+shuttle|apostore|redpilot)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(KiSoft\s*[A-Za-z0-9_-]*|Apostore\s*[A-Za-z0-9_-]*|OSR\s+Shuttle\s*[A-Za-z0-9_-]*)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|release|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Swisslog",
		defaultModel: "SynQ / Translogic Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(swisslog|translogic\s*pts|synq\s+wms)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Translogic\s*PTS|SynQ\s*[A-Za-z0-9_-]*)\b`),
	},
	{
		vendor:       "Dematic",
		defaultModel: "Dematic WCS / Multishuttle",
		matchRe:      regexp.MustCompile(`(?i)\b(dematic\s+wcs|dematic\s+iq|multishuttle)\b`),
	},
	{
		vendor:       "B&R",
		defaultModel: "Automation Runtime SDM",
		matchRe:      regexp.MustCompile(`(?i)(system\s+diagnostics\s+manager|br-automation|b&r\s+industrial\s+automation)`),
		modelExtract: regexp.MustCompile(`(?i)\b(X20CP[0-9A-Z]+|APC[0-9A-Z]+|System\s+Diagnostics\s+Manager)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:AR|Automation\s+Runtime)[\s/:v]*([A-Z]?[0-9]+\.[0-9]+)`),
	},

	// --- Cold-Chain Refrigeration Controllers & Supervisors ---
	{
		vendor:       "Danfoss",
		defaultModel: "AK-SM 800A Series",
		matchRe:      regexp.MustCompile(`(?i)\b(ak-sm\s*8[0-9x]{2}a?|ak-sc\s*[0-9]+|danfoss\s+system\s+manager|adap-kool)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(AK-SM\s*8[0-9]{2}A?|AK-SC\s*[0-9]+)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:sw|software|firmware|ver|v)[\s:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Copeland",
		defaultModel: "XWEB Pro",
		matchRe:      regexp.MustCompile(`(?i)\b(xweb\s*(?:300d?|500d?|5000|pro|evo)|dixell|emerson\s+e2|emerson\s+e3|site\s+supervisor)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(XWEB\s*(?:300D?|500D?\s*EVO|500D?|5000|Pro|EVO)|Site\s+Supervisor|E2E?|E3)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:rel|release|ver|version|v)[\s.:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "CAREL",
		defaultModel: "Boss / pCOWeb Supervisory Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(carel\s+boss|boss-mini|pcoweb|plantvisor|c\.pco)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Boss-Mini|Boss|pCOWeb|PlantVisor|c\.pCO)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|fw|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},

	// --- Regulated Healthcare & Cold-Chain Environmental Monitoring (EMS) ---
	{
		vendor:       "Vaisala",
		defaultModel: "viewLinc Enterprise Server",
		matchRe:      regexp.MustCompile(`(?i)\b(viewlinc|vaisala\s+oyj|vaisala\s+veriteq)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(viewLinc(?:\s+Enterprise\s+Server)?|DL[0-9]{4}|RFL100)\b`),
		fwExtract:    regexp.MustCompile(`(?i)viewLinc[\s/v]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Testo",
		defaultModel: "Saveris Base",
		matchRe:      regexp.MustCompile(`(?i)\b(testo\s+saveris|saveris\s+base|saveris\s+2)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Saveris\s*[A-Za-z0-9]*)\b`),
	},
	{
		vendor:       "ELPRO",
		defaultModel: "elproMONITOR / LIBERO",
		matchRe:      regexp.MustCompile(`(?i)\b(elpromonitor|elpro-buchs|libero\s+g[xh])\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(elproMONITOR|LIBERO\s*[A-Z0-9]*)\b`),
	},
	{
		vendor:       "Sensaphone",
		defaultModel: "Web600 / Sentinel",
		matchRe:      regexp.MustCompile(`(?i)\b(sensaphone|web600|ims-4000)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Web600|Sentinel\s*[A-Za-z0-9]*|IMS-4000)\b`),
	},
	{
		vendor:       "Rees Scientific",
		defaultModel: "Centron EMS",
		matchRe:      regexp.MustCompile(`(?i)\b(rees\s+scientific|centron\s+presidio)\b`),
	},

	// --- Server-Room / MDF Precision Cooling, Rack Environmental & UPS ---
	{
		vendor:       "Schneider Electric",
		defaultModel: "APC Network Management Card",
		matchRe:      regexp.MustCompile(`(?i)\b(inrow\s*(?:rc|rd|rp|sc)?|acrc[0-9a-z]+|acrd[0-9a-z]+|netbotz|smart-ups|ap96[34][015]|schneider\s+electric.*network\s+management\s+card|allegro[- ]software[- ]rompager.*apc|apc\s+web/snmp\s+management\s+card)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(InRow(?:\s+(?:RC|RD|RP|SC|ACRC[0-9A-Z]+|ACRD[0-9A-Z]+)){1,2}|ACRC[0-9A-Z]+|ACRD[0-9A-Z]+|NetBotz\s*[0-9A-Z]*|Smart-UPS\s*[A-Z0-9]*|AP96[34][015])\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:aos|firmware|app\s+v|v)[\s:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Vertiv",
		defaultModel: "Liebert IntelliSlot UNITY",
		matchRe:      regexp.MustCompile(`(?i)\b(liebert|intellislot|rdu101|vertiv\s+corporation|liebert\s+crv|liebert\s+pdx|liebert\s+gxt)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(RDU101|IntelliSlot\s*UNITY|Liebert\s*[A-Z0-9-]+)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9A-Za-z._-]*))`),
	},
	{
		vendor:       "Rittal",
		defaultModel: "CMC III / Blue e+ Chiller",
		matchRe:      regexp.MustCompile(`(?i)\b(rittal\s+cmc\s*iii|sk\s*3232|rittal\s+blue\s+e\+)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(CMC\s*III|SK\s*3232[A-Z0-9-]*|Blue\s+e\+)\b`),
	},

	// --- Auto-ID Vision & Pack-Out Labelers (HTTP 80/443 ONLY — NEVER 9100) ---
	{
		vendor:       "Cognex",
		defaultModel: "In-Sight / DataMan Vision",
		matchRe:      regexp.MustCompile(`(?i)\b(cognex\s+in-sight|cognex\s+dataman|3d-a1000)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(In-Sight\s*[0-9A-Z-]*|DataMan\s*[0-9A-Z-]*|3D-A1000)\b`),
	},
	{
		vendor:       "Zebra",
		defaultModel: "Link-OS Industrial Printer",
		matchRe:      regexp.MustCompile(`(?i)\b(zebranet\s+printserver|zebra\s+technologies.*link-os|zt[46][12]0|zt230)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(ZT[0-9]{3}|ZD[0-9]{3}|ZebraNet\s+PrintServer)\b`),
		fwExtract:    regexp.MustCompile(`(?i)\b(V[0-9]{2}\.[0-9]{2}\.[0-9A-Z]+)\b`),
	},
}

var htmlTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func newAncillaryHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // OT/cold-chain controllers routinely use self-signed OEM certs
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// MatchAncillaryCorpus evaluates combined HTTP headers, TLS certificate fields, and HTML snippet.
func MatchAncillaryCorpus(ip string, port int, isTLS bool, corpus string, certCN string) *inventory.Device {
	for _, sig := range ancillarySignatures {
		if !sig.matchRe.MatchString(corpus) {
			continue
		}
		model := sig.defaultModel
		if sig.modelExtract != nil {
			if m := sig.modelExtract.FindStringSubmatch(corpus); len(m) > 1 {
				model = strings.TrimSpace(m[1])
			}
		}
		fw := ""
		if sig.fwExtract != nil {
			if m := sig.fwExtract.FindStringSubmatch(corpus); len(m) > 1 {
				fw = strings.TrimSpace(m[1])
			}
		}
		proto := "http"
		if isTLS {
			proto = "https"
		}
		hostname := ""
		if certCN != "" && !strings.Contains(certCN, " ") && certCN != ip {
			hostname = certCN
		}
		return &inventory.Device{
			IP:       ip,
			Vendor:   sig.vendor,
			Model:    model,
			Firmware: fw,
			Hostname: hostname,
			Protocol: proto,
			Port:     port,
		}
	}
	return nil
}

// AncillaryProbeURL queries a single URL (used directly by unit tests and per-host scanner).
func AncillaryProbeURL(client *http.Client, targetURL, ip string, port int, isTLS bool) *inventory.Device {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Deadband-OT-Discovery/1.0 (Read-Only)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(bodyBytes)

	var parts []string
	if srv := resp.Header.Get("Server"); srv != "" {
		parts = append(parts, "Server: "+srv)
	}
	if auth := resp.Header.Get("WWW-Authenticate"); auth != "" {
		parts = append(parts, "WWW-Authenticate: "+auth)
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		parts = append(parts, powered)
	}

	certCN := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		certCN = strings.TrimSpace(leaf.Subject.CommonName)
		parts = append(parts, leaf.Subject.CommonName)
		parts = append(parts, leaf.Subject.Organization...)
		parts = append(parts, leaf.Issuer.CommonName)
		parts = append(parts, leaf.Issuer.Organization...)
	}

	if tm := htmlTitleRe.FindStringSubmatch(bodyStr); len(tm) > 1 {
		parts = append(parts, strings.TrimSpace(tm[1]))
	}
	parts = append(parts, bodyStr)

	corpus := strings.Join(parts, "\n")
	return MatchAncillaryCorpus(ip, port, isTLS, corpus, certCN)
}

func discoverAncillary(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	type hostPorts struct {
		ports []int
	}
	openMap := make(map[string]*hostPorts)
	var mapMu sync.Mutex

	for _, p := range ancillaryPorts {
		open := ScanPorts(ips, p, timeout, concurrency)
		mapMu.Lock()
		for _, ip := range open {
			hp := openMap[ip]
			if hp == nil {
				hp = &hostPorts{}
				openMap[ip] = hp
			}
			hp.ports = append(hp.ports, p)
		}
		mapMu.Unlock()
	}

	if progress != nil {
		progress(fmt.Sprintf("Ancillary Cold-Chain / WCS / HVAC HTTP+TLS: %d/%d hosts with web ports open", len(openMap), len(ips)))
	}
	if len(openMap) == 0 {
		return nil
	}

	httpTimeout := timeout * 2
	if httpTimeout < 2*time.Second {
		httpTimeout = 2 * time.Second
	}
	client := newAncillaryHTTPClient(httpTimeout)

	var (
		mu      sync.Mutex
		devices []inventory.Device
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)

	for ip, hp := range openMap {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string, ports []int) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, p := range ports {
				isTLS := p == 443 || p == 8443
				scheme := "http"
				if isTLS {
					scheme = "https"
				}
				url := fmt.Sprintf("%s://%s:%d/", scheme, ip, p)
				if dev := AncillaryProbeURL(client, url, ip, p, isTLS); dev != nil {
					mu.Lock()
					devices = append(devices, *dev)
					mu.Unlock()
					return
				}
			}
		}(ip, hp.ports)
	}
	wg.Wait()
	return devices
}
