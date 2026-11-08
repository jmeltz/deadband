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

// Ancillary Infrastructure, Cold-Chain Refrigeration, BMS, EMS & Intralogistics WCS
// Read-Only HTTP / HTTPS + TLS Certificate + SNMP sysDescr Fingerprinter (ports 80, 443, 8080, 8443).
//
// SAFETY INVARIANTS:
//   1. Strictly issues a single read-only HTTP GET "/" with a 64 KiB body cap
//      (plus optional read-only SNMPv2c GET sysDescr.0 when firmware is hidden pre-auth).
//   2. NEVER connects to raw printer port TCP/9100 (which would cause Zebra/industrial
//      thermal printers to physically print HTTP headers onto shipping labels).
//   3. Only emits an inventory.Device when a high-confidence OT, intralogistics,
//      cold-chain refrigeration, BMS, regulated EMS, or server-room HVAC/UPS signature
//      matches — generic IT web servers (nginx/Apache/IIS without OT signatures) are ignored.

var ancillaryPorts = []int{443, 80, 8443, 8080}

type ancillarySignature struct {
	vendor       string
	defaultModel string
	matchRe      *regexp.Regexp
	modelExtract *regexp.Regexp
	fwExtract    *regexp.Regexp
}

var ancillarySignatures = []ancillarySignature{
	// --- KNAPP & Warehouse Execution / Shuttle / Goods-to-Person Automation ---
	{
		vendor:       "KNAPP",
		defaultModel: "KiSoft WCS / OSR Gateway",
		matchRe:      regexp.MustCompile(`(?i)(\bkisoft\b|\bknapp\s+ag\b|\bosr\s+shuttle\b|\bapostore\b|\bredpilot\b|/realms/kisoft|/kisoft/)`),
		modelExtract: regexp.MustCompile(`(?i)\b(KiSoft(?:\s+(?:WCS|WMS|One|Analytics|Vision))?|Apostore\s*[A-Za-z0-9_-]*|OSR\s+Shuttle\s*[A-Za-z0-9_-]*|redPILOT)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|release|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Swisslog",
		defaultModel: "SynQ / Translogic Controller",
		matchRe:      regexp.MustCompile(`(?i)(\bswisslog\b|\btranslogic\s*pts\b|\bsynq\s+wms\b|/synq/|/realms/synq)`),
		modelExtract: regexp.MustCompile(`(?i)\b(Translogic\s*PTS|SynQ(?:\s+WMS)?|CarryPick|AutoStore\s+SynQ)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|release|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Dematic",
		defaultModel: "Dematic WCS / Multishuttle",
		matchRe:      regexp.MustCompile(`(?i)\b(dematic\s+wcs|dematic\s+iq|dematic\s+sprout|multishuttle)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Dematic\s+(?:WCS|iQ|Sprout)|Multishuttle)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|release|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Vanderlande",
		defaultModel: "Vanderlande VISION / ADAPTO",
		matchRe:      regexp.MustCompile(`(?i)\b(vanderlande|vanderlande\s+vision|adapto\s+shuttle|fastpick)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(VISION|ADAPTO|FASTPICK)\b`),
	},
	{
		vendor:       "TGW",
		defaultModel: "TGW Commander / FlashPick",
		matchRe:      regexp.MustCompile(`(?i)\b(tgw\s+logistics|tgw\s+commander|flashpick|stingray\s+shuttle)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(TGW\s+Commander|FlashPick|Stingray\s+Shuttle)\b`),
	},
	{
		vendor:       "SSI Schaefer",
		defaultModel: "WAMAS WCS",
		matchRe:      regexp.MustCompile(`(?i)\b(wamas|ssi\s+schaefer|ssi\s+schäfer)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(WAMAS(?:\s+Lighthouse)?)\b`),
	},
	{
		vendor:       "AutoStore",
		defaultModel: "AutoStore Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(autostore\s+(?:router|controller|grid|port)|autostore\s+system)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(AutoStore\s+(?:Router|Controller|Grid))\b`),
	},
	{
		vendor:       "Interroll",
		defaultModel: "MultiControl Conveyor Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(interroll|multicontrol\s*(?:ai|bi|pro)?|rollerdrive\s*ec[35]00)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(MultiControl(?:\s*(?:AI|BI|PRO))?|RollerDrive\s*EC[35]00)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:fw|firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Pulseroller",
		defaultModel: "ConveyLinx Zone Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(conveylinx|pulseroller|senergy\s+ai)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(ConveyLinx(?:-(?:Ai2|Ai3|ECO|ERSC))?)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:fw|firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "SEW-EURODRIVE",
		defaultModel: "MOVI-C / MOVITRAC Drive Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(sew-eurodrive|movi-c|movitrac|movidrive|dfe3[23]b)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(MOVI-C|MOVITRAC|MOVIDRIVE|DFE3[23]B)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:fw|firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "B&R",
		defaultModel: "Automation Runtime SDM",
		matchRe:      regexp.MustCompile(`(?i)(system\s+diagnostics\s+manager|br-automation|b&r\s+industrial\s+automation)`),
		modelExtract: regexp.MustCompile(`(?i)\b(X20CP[0-9A-Z]+|APC[0-9A-Z]+)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:AR|Automation\s+Runtime)[\s/:v]*([A-Z]?[0-9]+\.[0-9]+)`),
	},

	// --- Cold-Chain & Industrial Ammonia/CO2 Refrigeration Controllers ---
	{
		vendor:       "Danfoss",
		defaultModel: "AK-SM 800A Series",
		matchRe:      regexp.MustCompile(`(?i)\b(ak-sm\s*8[0-9x]{2}a?|ak-sc\s*[0-9]+|ak-cc55|danfoss\s+system\s+manager|adap-kool)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(AK-SM\s*8[0-9]{2}A?|AK-SC\s*[0-9]+|AK-CC55)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:sw|software|firmware|ver|v)[\s:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Copeland",
		defaultModel: "XWEB Pro",
		matchRe:      regexp.MustCompile(`(?i)\b(xweb\s*(?:300d?|500d?|5000|pro|evo)|dixell|emerson\s+e2|emerson\s+e3|site\s+supervisor)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(XWEB\s*(?:300D?\s*(?:PRO|EVO)?|500D?\s*(?:PRO|EVO)?|500B\s*PRO|5000|Pro|EVO)|Site\s+Supervisor|E2E?|E3)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:rel|release|ver|version|v)[\s.:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "CAREL",
		defaultModel: "Boss / pCOWeb Supervisory Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(carel\s+boss|boss-mini|pcoweb|plantvisor|c\.pco|mpxpro)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Boss-Mini|Boss|pCOWeb|PlantVisor|c\.pCO|MPXPRO)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|fw|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "GEA",
		defaultModel: "GEA Omni Refrigeration Panel",
		matchRe:      regexp.MustCompile(`(?i)\b(gea\s+omni|gea\s+refrigeration)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(GEA\s+Omni)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|fw|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Mayekawa",
		defaultModel: "MYPRO Touch Compressor Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(mayekawa|mycom\s+mypro|mypro\s+touch)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(MYPRO\s*Touch|Mycom)\b`),
	},

	// --- Building Management Systems (BMS / BAS / Chiller Supervisors) ---
	{
		vendor:       "Johnson Controls",
		defaultModel: "Metasys Server / Engine",
		matchRe:      regexp.MustCompile(`(?i)(\bmetasys\b|/metasysiii/|\bfacility\s+explorer\b|\bfrick\s+quantum\b|\bsne[0-9]{4}|\bsnc[0-9]{4}|\bnae[0-9]{2})`),
		modelExtract: regexp.MustCompile(`(?i)\b(Frick\s+Quantum\s*(?:HD|LX)?|Metasys(?:\s+(?:Server|UI|ADX|ADS))?|Facility\s+Explorer|SNE[0-9]{4}[A-Z0-9-]*|SNC[0-9]{4}[A-Z0-9-]*|NAE[0-9]{2}[A-Z0-9-]*)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:metasys|release|version|v)[\s/:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Trane",
		defaultModel: "Tracer SC+",
		matchRe:      regexp.MustCompile(`(?i)(\btracer\s+sc\+|\b(?:tracer\s+sc|tracer\s+concierge|tracer\s+ensemble|trane\s+symbio\s*800)\b)`),
		modelExtract: regexp.MustCompile(`(?i)\b(Tracer\s+SC\+|(?:Tracer\s+SC|Tracer\s+Concierge|Tracer\s+Ensemble|Symbio\s*800)\b)`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|release|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Carrier",
		defaultModel: "WebCTRL / i-Vu Server",
		matchRe:      regexp.MustCompile(`(?i)\b(webctrl|automated\s+logic|carrier\s+i-vu|i-vu\s+pro)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(WebCTRL|i-Vu(?:\s+Pro)?)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:webctrl|i-vu|version|v)[\s/:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Siemens",
		defaultModel: "Desigo CC / PXC Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(desigo\s*(?:cc|pxc|optic)?|pxc[457]\.[a-z0-9-]+|pxa40-w[0-9]?|climatix|synco\s+ozw)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Desigo\s+(?:CC|PXC|Optic)|PXC[457]\.[A-Z0-9-]+|PXA40-W[0-9]?|Climatix[A-Z0-9 -]*|OZW[0-9]+)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|fw|version|v)[\s:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Schneider Electric",
		defaultModel: "EcoStruxure Building Operation / SpaceLogic",
		matchRe:      regexp.MustCompile(`(?i)\b(ecostruxure\s+building|spacelogic\s+as-[pb]|smartx\s+server|struxureware\s+building)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(EcoStruxure\s+Building\s+Operation|SpaceLogic\s+AS-[PB]|SmartX\s+Server)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|release|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Tridium",
		defaultModel: "Niagara Framework",
		matchRe:      regexp.MustCompile(`(?i)(\btridium\b|\bniagara\s*4\b|\bniagara\s+web\s+supervisor\b|\bjace-[89]000\b|niagara_session|niagara_userid|/prelogin)`),
		modelExtract: regexp.MustCompile(`(?i)\b(JACE-[89]000|Niagara\s*4|Niagara\s+Web\s+Supervisor)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:niagara|version|v)[\s/:=]*(4\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "LOYTEC",
		defaultModel: "LINX / LIOB Automation Server",
		matchRe:      regexp.MustCompile(`(?i)\b(loytec|linx-[0-9]{3}|liob-[0-9]{3}|lvis-[0-9a-z-]+|lgate-[0-9]{3})\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(LINX-[0-9]{3}[A-Z0-9-]*|LIOB-[0-9]{3}[A-Z0-9-]*|LVIS-[0-9A-Z-]+|LGATE-[0-9]{3}[A-Z0-9-]*)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Delta Controls",
		defaultModel: "enteliWEB / enteliBUS",
		matchRe:      regexp.MustCompile(`(?is)\b(enteliweb|entelibus|ebmgr|delta\s+controls.*o3)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(enteliWEB|enteliBUS|eBMGR|O3-DIN)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:enteliweb|version|v)[\s/:=]*([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "SAUTER",
		defaultModel: "moduWeb Vision / ecos504",
		matchRe:      regexp.MustCompile(`(?i)\b(moduweb\s*(?:vision|unity)?|sauter\s+ecos[0-9]+|ey-modulo)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(moduWeb(?:\s+(?:Vision|Unity))?|ecos[0-9]+|EY-modulo\s*[0-9]*)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|fw|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Reliable Controls",
		defaultModel: "MACH-ProWeb Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(mach-proweb|mach-procom|rc-webview|reliable\s+controls)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(MACH-ProWeb(?:Com|Sys)?|MACH-ProCom|RC-WebView)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Distech Controls",
		defaultModel: "ECLYPSE / EC-BOS Controller",
		matchRe:      regexp.MustCompile(`(?i)\b(distech\s+controls|eclypse\s*(?:connected|sky)?|ec-bos-[0-9]+)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(ECLYPSE|EC-BOS-[0-9]+)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
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
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "ELPRO",
		defaultModel: "elproMONITOR / LIBERO",
		matchRe:      regexp.MustCompile(`(?i)\b(elpromonitor|elpro-buchs|libero\s+g[xh])\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(elproMONITOR|LIBERO\s*[A-Z0-9]*)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Sensaphone",
		defaultModel: "Web600 / Sentinel",
		matchRe:      regexp.MustCompile(`(?i)\b(sensaphone|web600|ims-4000)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(Web600|Sentinel\s*[A-Za-z0-9]*|IMS-4000)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
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
		matchRe:      regexp.MustCompile(`(?is)\b(inrow\s*(?:rc|rd|rp|sc)?|acrc[0-9a-z]+|acrd[0-9a-z]+|netbotz|smart-ups|ap96[34][015]|schneider\s+electric.*network\s+management\s+card|allegro[- ]software[- ]rompager.*apc|apc\s+(?:web/snmp\s+)?management\s+card)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(InRow(?:\s+(?:RC|RD|RP|SC|ACRC[0-9A-Z]+|ACRD[0-9A-Z]+)){1,2}|ACRC[0-9A-Z]+|ACRD[0-9A-Z]+|NetBotz\s*[0-9A-Z]*|Smart-UPS\s*[A-Z0-9]*|AP96[34][015])\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:aos|pf:|firmware|app\s+v|v)[\s:=]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
	},
	{
		vendor:       "Vertiv",
		defaultModel: "Liebert IntelliSlot UNITY",
		matchRe:      regexp.MustCompile(`(?i)\b(liebert|intellislot|rdu101|is-unity|vertiv\s+corporation|liebert\s+crv|liebert\s+pdx|liebert\s+gxt)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(RDU101|IS-UNITY(?:-DP)?|IntelliSlot\s*UNITY|Liebert\s*[A-Z0-9-]+)\b`),
		fwExtract:    regexp.MustCompile(`(?i)(?:firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9A-Za-z._-]*))`),
	},
	{
		vendor:       "Rittal",
		defaultModel: "CMC III / Blue e+ Chiller",
		matchRe:      regexp.MustCompile(`(?i)(\brittal\s+blue\s+e\+|\b(?:rittal\s+cmc\s*iii|cmc-tc|sk\s*3232)\b)`),
		modelExtract: regexp.MustCompile(`(?i)\b(Blue\s+e\+|(?:CMC\s*III|SK\s*3232[A-Z0-9-]*)\b)`),
		fwExtract:    regexp.MustCompile(`(?i)(?:sw|firmware|version|v)[\s:=]+([0-9]+\.[0-9]+(?:\.[0-9]+)*)`),
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
		matchRe:      regexp.MustCompile(`(?is)\b(zebranet\s+printserver|zebra\s+technologies.*link-os|zt[46][12]0|zt230)\b`),
		modelExtract: regexp.MustCompile(`(?i)\b(ZT[0-9]{3}|ZD[0-9]{3})\b`),
		fwExtract:    regexp.MustCompile(`(?i)\b(V[0-9]{2}\.[0-9]{2}\.[0-9A-Z]+)\b`),
	},
}

var (
	htmlTitleRe  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	apcMNRe      = regexp.MustCompile(`(?i)\bMN:([A-Z0-9-]+)\b`)
	apcPFRe      = regexp.MustCompile(`(?i)\bPF:v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)\b`)
	genericVerRe = regexp.MustCompile(`(?i)(?:firmware|fw|sw|version|ver|v)[\s:=]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)*)`)
)

func newAncillaryHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // OT/cold-chain controllers routinely use self-signed OEM certs
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Never follow redirects off-host (avoids split-DNS failures on air-gapped OT networks
			// and keeps probes strictly scoped to the target IP).
			if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// MatchAncillaryCorpus evaluates combined HTTP headers, redirect paths, cookies, TLS SAN/CN, and HTML snippet.
func MatchAncillaryCorpus(ip string, port int, isTLS bool, corpus string, certCN string) *inventory.Device {
	for _, sig := range ancillarySignatures {
		if !sig.matchRe.MatchString(corpus) {
			continue
		}
		model := sig.defaultModel
		if sig.modelExtract != nil {
			if matches := sig.modelExtract.FindAllStringSubmatch(corpus, -1); len(matches) > 0 {
				best := ""
				for _, m := range matches {
					if len(m) > 1 {
						cand := strings.TrimSpace(m[1])
						if len(cand) > len(best) {
							best = cand
						}
					}
				}
				if best != "" {
					model = best
				}
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

// enrichDeviceFromSysDescr enriches Firmware/Model on an ancillary device using SNMP sysDescr.0
// (e.g. "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin ... MN:AP9631 ...)").
func enrichDeviceFromSysDescr(dev *inventory.Device, sysDescr string) {
	if dev == nil || sysDescr == "" {
		return
	}
	if m := apcMNRe.FindStringSubmatch(sysDescr); len(m) > 1 && strings.Contains(dev.Model, "Network Management Card") {
		dev.Model = strings.TrimSpace(m[1])
	}
	if dev.Firmware == "" {
		if m := apcPFRe.FindStringSubmatch(sysDescr); len(m) > 1 {
			dev.Firmware = m[1]
			return
		}
		if m := genericVerRe.FindStringSubmatch(sysDescr); len(m) > 1 {
			dev.Firmware = m[1]
		}
	}
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
	// Walk the redirect response chain (final response back through prior 30x hops)
	// so intermediate Set-Cookie / Location / URL paths are preserved.
	for cur := resp; cur != nil; {
		if cur.Request != nil && cur.Request.URL != nil {
			parts = append(parts, cur.Request.URL.Path+" "+cur.Request.URL.RawQuery)
		}
		if loc := cur.Header.Get("Location"); loc != "" {
			parts = append(parts, "Location: "+loc)
		}
		for _, ck := range cur.Header.Values("Set-Cookie") {
			parts = append(parts, "Set-Cookie: "+ck)
		}
		if srv := cur.Header.Get("Server"); srv != "" {
			parts = append(parts, "Server: "+srv)
		}
		if auth := cur.Header.Get("WWW-Authenticate"); auth != "" {
			parts = append(parts, "WWW-Authenticate: "+auth)
		}
		if powered := cur.Header.Get("X-Powered-By"); powered != "" {
			parts = append(parts, powered)
		}
		if cur.Request != nil {
			cur = cur.Request.Response
		} else {
			break
		}
	}

	certCN := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		certCN = strings.TrimSpace(leaf.Subject.CommonName)
		parts = append(parts, leaf.Subject.CommonName)
		parts = append(parts, leaf.Subject.Organization...)
		parts = append(parts, leaf.Issuer.CommonName)
		parts = append(parts, leaf.Issuer.Organization...)
		parts = append(parts, leaf.DNSNames...)
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
	snmpTimeout := timeout
	if snmpTimeout > 600*time.Millisecond {
		snmpTimeout = 600 * time.Millisecond
	}

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
					if dev.Firmware == "" {
						if sysDescr := SNMPGetSysDescr(ip, SNMPPort, snmpTimeout); sysDescr != "" {
							enrichDeviceFromSysDescr(dev, sysDescr)
						}
					}
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
