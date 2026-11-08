package discover

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// DiscoveryMode selects the discovery protocol.
type DiscoveryMode string

const (
	ModeCIP        DiscoveryMode = "cip"
	ModeS7         DiscoveryMode = "s7"
	ModeModbusTCP  DiscoveryMode = "modbus"
	ModeMELSEC     DiscoveryMode = "melsec"
	ModeBACnet     DiscoveryMode = "bacnet"
	ModeFINS       DiscoveryMode = "fins"
	ModeSRTP       DiscoveryMode = "srtp"
	ModeOPCUA      DiscoveryMode = "opcua"
	ModeADS        DiscoveryMode = "ads"
	ModeSICK       DiscoveryMode = "sick"
	ModeFox        DiscoveryMode = "fox"
	ModeAncillary  DiscoveryMode = "ancillary"
	ModeHaas       DiscoveryMode = "haas"
	ModeFanuc      DiscoveryMode = "fanuc"
	ModeMazak      DiscoveryMode = "mazak"
	ModeAuto       DiscoveryMode = "auto"
	ModeLegacyHTTP DiscoveryMode = "http"
)

type Opts struct {
	CIDR        string
	Timeout     time.Duration
	HTTPTimeout time.Duration
	Concurrency int
	Mode        DiscoveryMode
	Progress    func(msg string)
}

// ValidateMode rejects a misspelled or unsupported mode before any network I/O.
func ValidateMode(mode DiscoveryMode) error {
	switch mode {
	case "", ModeAuto, ModeCIP, ModeS7, ModeModbusTCP, ModeMELSEC, ModeBACnet,
		ModeFINS, ModeSRTP, ModeOPCUA, ModeADS, ModeSICK, ModeFox,
		ModeAncillary, ModeHaas, ModeFanuc, ModeMazak, ModeLegacyHTTP:
		return nil
	default:
		return fmt.Errorf("unsupported discovery mode %q", mode)
	}
}

// Run performs device discovery on a CIDR range and returns inventory devices.
// In Auto mode (default), probes both CIP and S7 protocols concurrently.
func Run(opts Opts) ([]inventory.Device, error) {
	if err := ValidateMode(opts.Mode); err != nil {
		return nil, err
	}
	if opts.Mode == "" {
		opts.Mode = ModeAuto
	}

	ips, err := ExpandCIDR(opts.CIDR)
	if err != nil {
		return nil, err
	}

	switch opts.Mode {
	case ModeCIP:
		return runCIP(opts, ips)
	case ModeS7:
		return runS7(opts, ips)
	case ModeModbusTCP:
		return runModbusTCP(opts, ips)
	case ModeMELSEC:
		return runMELSEC(opts, ips)
	case ModeBACnet:
		return runBACnet(opts, ips)
	case ModeFINS:
		return runFINS(opts, ips)
	case ModeSRTP:
		return runSRTP(opts, ips)
	case ModeOPCUA:
		return runOPCUA(opts, ips)
	case ModeADS:
		return runADS(opts, ips)
	case ModeSICK:
		return runSICK(opts, ips)
	case ModeFox:
		return runFox(opts, ips)
	case ModeAncillary:
		return runAncillary(opts, ips)
	case ModeHaas:
		return runHaas(opts, ips)
	case ModeFanuc:
		return runFanuc(opts, ips)
	case ModeMazak:
		return runMazak(opts, ips)
	case ModeLegacyHTTP:
		return runHTTP(opts, ips)
	case ModeAuto:
		return runAuto(opts, ips)
	}
	return nil, fmt.Errorf("unsupported discovery mode %q", opts.Mode)
}

func runCIP(opts Opts, ips []string) ([]inventory.Device, error) {
	cidr := opts.CIDR
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	broadcastAddr := broadcastAddrForCIDR(cidr)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("CIP ListIdentity discovery on %d hosts...", len(ips)))
	}

	devices := discoverCIP(ips, broadcastAddr, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("CIP discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runS7(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("S7comm discovery on %d hosts...", len(ips)))
	}

	devices := discoverS7(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("S7comm discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runModbusTCP(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Modbus TCP discovery on %d hosts...", len(ips)))
	}

	devices := discoverModbusTCP(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Modbus TCP discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runMELSEC(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("MELSEC/SLMP discovery on %d hosts...", len(ips)))
	}

	devices := discoverSLMP(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("MELSEC/SLMP discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runBACnet(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("BACnet/IP discovery on %d hosts...", len(ips)))
	}

	devices := discoverBACnet(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("BACnet/IP discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runFINS(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("FINS discovery on %d hosts...", len(ips)))
	}

	devices := discoverFINS(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("FINS discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runSRTP(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("GE-SRTP discovery on %d hosts...", len(ips)))
	}

	devices := discoverSRTP(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("GE-SRTP discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runOPCUA(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("OPC UA discovery on %d hosts...", len(ips)))
	}

	devices := discoverOPCUA(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("OPC UA discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runHaas(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Haas Q-command discovery on %d hosts...", len(ips)))
	}

	devices := discoverHaas(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Haas discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runFanuc(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Fanuc multi-probe discovery (CIP / FTP / HTTP) on %d hosts...", len(ips)))
	}

	devices := discoverFanuc(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Fanuc discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runMazak(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Mazak multi-probe discovery (CIP / MTConnect) on %d hosts...", len(ips)))
	}

	devices := discoverMazak(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Mazak discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runADS(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Beckhoff TwinCAT ADS discovery on %d hosts...", len(ips)))
	}

	devices := discoverADS(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("TwinCAT ADS discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runSICK(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("SICK SOPAS CoLa discovery on %d hosts...", len(ips)))
	}

	devices := discoverSICK(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("SICK SOPAS discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runFox(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Tridium Niagara Fox/FoxS discovery on %d hosts...", len(ips)))
	}

	devices := discoverFox(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Tridium Niagara Fox/FoxS discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runAncillary(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Ancillary Cold-Chain / WCS / HVAC HTTP+TLS discovery on %d hosts...", len(ips)))
	}

	devices := discoverAncillary(ips, opts.Timeout, opts.Concurrency, opts.Progress)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Ancillary HTTP+TLS discovery found %d devices", len(devices)))
	}

	return devices, nil
}

func runAuto(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Auto discovery (CIP + S7 + Modbus + BACnet + Fox + OPC UA + ADS + SICK + MELSEC + FINS + SRTP + Haas + Fanuc + Mazak + Ancillary) on %d hosts...", len(ips)))
	}

	type result struct {
		devices []inventory.Device
		err     error
	}

	cipCh := make(chan result, 1)
	s7Ch := make(chan result, 1)
	modbusCh := make(chan result, 1)
	bacnetCh := make(chan result, 1)
	foxCh := make(chan result, 1)
	melsecCh := make(chan result, 1)
	finsCh := make(chan result, 1)
	srtpCh := make(chan result, 1)
	opcuaCh := make(chan result, 1)
	adsCh := make(chan result, 1)
	sickCh := make(chan result, 1)
	ancillaryCh := make(chan result, 1)
	haasCh := make(chan result, 1)
	fanucCh := make(chan result, 1)
	mazakCh := make(chan result, 1)

	go func() {
		d, e := runCIP(opts, ips)
		cipCh <- result{d, e}
	}()
	go func() {
		d, e := runS7(opts, ips)
		s7Ch <- result{d, e}
	}()
	go func() {
		d, e := runModbusTCP(opts, ips)
		modbusCh <- result{d, e}
	}()
	go func() {
		d, e := runBACnet(opts, ips)
		bacnetCh <- result{d, e}
	}()
	go func() {
		d, e := runFox(opts, ips)
		foxCh <- result{d, e}
	}()
	go func() {
		d, e := runMELSEC(opts, ips)
		melsecCh <- result{d, e}
	}()
	go func() {
		d, e := runFINS(opts, ips)
		finsCh <- result{d, e}
	}()
	go func() {
		d, e := runSRTP(opts, ips)
		srtpCh <- result{d, e}
	}()
	go func() {
		d, e := runOPCUA(opts, ips)
		opcuaCh <- result{d, e}
	}()
	go func() {
		d, e := runADS(opts, ips)
		adsCh <- result{d, e}
	}()
	go func() {
		d, e := runSICK(opts, ips)
		sickCh <- result{d, e}
	}()
	go func() {
		d, e := runAncillary(opts, ips)
		ancillaryCh <- result{d, e}
	}()
	go func() {
		d, e := runHaas(opts, ips)
		haasCh <- result{d, e}
	}()
	go func() {
		d, e := runFanuc(opts, ips)
		fanucCh <- result{d, e}
	}()
	go func() {
		d, e := runMazak(opts, ips)
		mazakCh <- result{d, e}
	}()

	cipResult := <-cipCh
	s7Result := <-s7Ch
	modbusResult := <-modbusCh
	bacnetResult := <-bacnetCh
	foxResult := <-foxCh
	melsecResult := <-melsecCh
	finsResult := <-finsCh
	srtpResult := <-srtpCh
	opcuaResult := <-opcuaCh
	adsResult := <-adsCh
	sickResult := <-sickCh
	ancillaryResult := <-ancillaryCh
	haasResult := <-haasCh
	fanucResult := <-fanucCh
	mazakResult := <-mazakCh

	// Merge results: preserve multi-slot chassis modules and routed BACnet sub-devices,
	// while upgrading placeholder vendors/models on primary host entries.
	devices := mergeDevices([][]inventory.Device{
		cipResult.devices,
		s7Result.devices,
		modbusResult.devices,
		bacnetResult.devices,
		foxResult.devices,
		opcuaResult.devices,
		adsResult.devices,
		sickResult.devices,
		melsecResult.devices,
		finsResult.devices,
		srtpResult.devices,
		haasResult.devices,
		fanucResult.devices,
		mazakResult.devices,
		ancillaryResult.devices,
	})

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Auto discovery found %d total devices", len(devices)))
	}

	// Return first non-nil error only if every protocol probe failed
	allResults := []result{
		cipResult, s7Result, modbusResult, bacnetResult, foxResult,
		melsecResult, finsResult, srtpResult, opcuaResult,
		adsResult, sickResult, ancillaryResult, haasResult,
		fanucResult, mazakResult,
	}
	allFailed := true
	for _, r := range allResults {
		if r.err == nil {
			allFailed = false
			break
		}
	}
	if allFailed {
		return devices, cipResult.err
	}

	return devices, nil
}

func isPlaceholderVendor(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" ||
		strings.EqualFold(v, "Unknown") ||
		strings.HasPrefix(v, "Vendor(") ||
		strings.HasPrefix(v, "BACnet Vendor ")
}

func isPlaceholderModel(m string) bool {
	m = strings.TrimSpace(m)
	return m == "" ||
		strings.HasPrefix(m, "BACnet Device #") ||
		m == "OPC UA Server" ||
		m == "TwinCAT ADS Router" ||
		m == "SIMATIC S7"
}

func deviceMergeKey(d inventory.Device, seen map[string]inventory.Device) string {
	if path := d.Extra["component_path"]; d.Protocol == "bacnet" && path != "" {
		return d.IP + "|" + path
	}
	if d.Slot > 0 || (d.Extra != nil && d.Extra["component"] == "chassis_slot") {
		return fmt.Sprintf("%s|slot:%d", d.IP, d.Slot)
	}
	if d.Protocol == "bacnet" && d.Extra != nil {
		if snet := d.Extra["bacnet_snet"]; snet != "" {
			return fmt.Sprintf("%s|bacnet:%s:%s:%s", d.IP, snet, d.Extra["bacnet_sadr"], d.Extra["device_instance"])
		}
		if inst := d.Extra["device_instance"]; inst != "" {
			if existing, ok := seen[d.IP]; ok && existing.Protocol == "bacnet" && existing.Extra != nil {
				if prevInst := existing.Extra["device_instance"]; prevInst != "" && prevInst != inst {
					return fmt.Sprintf("%s|bacnet:%s", d.IP, inst)
				}
			}
		}
	}
	return d.IP
}

func mergeDevices(lists [][]inventory.Device) []inventory.Device {
	seen := make(map[string]inventory.Device)
	var order []string

	for _, list := range lists {
		for _, d := range list {
			key := deviceMergeKey(d, seen)
			existing, ok := seen[key]
			if !ok {
				if d.Extra != nil {
					copied := make(map[string]string, len(d.Extra))
					for k, v := range d.Extra {
						copied[k] = v
					}
					d.Extra = copied
				}
				seen[key] = d
				order = append(order, key)
				continue
			}

			if isPlaceholderVendor(existing.Vendor) && !isPlaceholderVendor(d.Vendor) {
				existing.Vendor = d.Vendor
				if d.Model != "" && (isPlaceholderModel(existing.Model) || existing.Protocol != d.Protocol) {
					// Keep concrete hardware model if existing already has one, unless existing is a generic placeholder
					if isPlaceholderModel(existing.Model) {
						existing.Model = d.Model
					}
				}
			}
			if isPlaceholderModel(existing.Model) && d.Model != "" && !isPlaceholderModel(d.Model) {
				existing.Model = d.Model
			}
			if existing.Firmware == "" && d.Firmware != "" {
				existing.Firmware = d.Firmware
			}
			if existing.Hostname == "" && d.Hostname != "" {
				existing.Hostname = d.Hostname
			}
			if existing.Serial == "" && d.Serial != "" {
				existing.Serial = d.Serial
			}
			if existing.MAC == "" && d.MAC != "" {
				existing.MAC = d.MAC
			}
			if len(d.Extra) > 0 {
				if existing.Extra == nil {
					existing.Extra = make(map[string]string, len(d.Extra))
				}
				for k, v := range d.Extra {
					if v != "" && existing.Extra[k] == "" {
						existing.Extra[k] = v
					}
				}
			}
			seen[key] = existing
		}
	}

	devices := make([]inventory.Device, 0, len(order))
	for _, key := range order {
		devices = append(devices, seen[key])
	}
	return devices
}

func runHTTP(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Scanning %d hosts for port %d...", len(ips), EIPPort))
	}

	openHosts := ScanPorts(ips, EIPPort, opts.Timeout, opts.Concurrency)

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Found %d hosts with EtherNet/IP port open", len(openHosts)))
	}

	if len(openHosts) == 0 {
		return nil, nil
	}

	httpClient := &http.Client{Timeout: opts.HTTPTimeout}
	var devices []inventory.Device

	for _, ip := range openHosts {
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("Querying %s...", ip))
		}

		info, err := ScrapeDevice(httpClient, ip)
		if err != nil {
			if opts.Progress != nil {
				opts.Progress(fmt.Sprintf("Warning: failed to scrape %s: %v", ip, err))
			}
			continue
		}

		dev := inventory.Device{
			IP:       ip,
			Vendor:   "Rockwell Automation",
			Model:    info["Device Name"],
			Firmware: info["Product Revision"],
			Serial:   info["Serial Number"],
			MAC:      info["Ethernet Address (MAC)"],
			Protocol: "cip",
			Port:     EIPPort,
		}
		if info["Status"] != "" || info["Uptime"] != "" {
			dev.Extra = map[string]string{}
			if v := info["Status"]; v != "" {
				dev.Extra["status"] = v
			}
			if v := info["Uptime"]; v != "" {
				dev.Extra["uptime"] = v
			}
		}
		if dev.Model != "" {
			devices = append(devices, dev)
		}
	}

	return devices, nil
}
