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

// Run performs device discovery on a CIDR range and returns inventory devices.
// In Auto mode (default), probes both CIP and S7 protocols concurrently.
func Run(opts Opts) ([]inventory.Device, error) {
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
	default:
		return runAuto(opts, ips)
	}
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
		opts.Progress(fmt.Sprintf("Auto discovery (CIP + S7 + Modbus + BACnet + OPC UA + ADS + SICK + MELSEC + FINS + SRTP + Haas + Fanuc + Mazak + Ancillary) on %d hosts...", len(ips)))
	}

	type result struct {
		devices []inventory.Device
		err     error
	}

	cipCh := make(chan result, 1)
	s7Ch := make(chan result, 1)
	modbusCh := make(chan result, 1)
	bacnetCh := make(chan result, 1)
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

	// Merge results, deduplicate by IP (prefer structured OT identities first, then Ancillary HTTP+TLS)
	seen := make(map[string]inventory.Device)
	mergeList := [][]inventory.Device{
		cipResult.devices,
		s7Result.devices,
		modbusResult.devices,
		bacnetResult.devices,
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
	}
	for _, list := range mergeList {
		for _, d := range list {
			if existing, ok := seen[d.IP]; !ok || existing.Model == "" {
				seen[d.IP] = d
			} else {
				if existing.Firmware == "" && d.Firmware != "" {
					existing.Firmware = d.Firmware
				}
				if existing.Hostname == "" && d.Hostname != "" {
					existing.Hostname = d.Hostname
				}
				seen[d.IP] = existing
			}
		}
	}

	devices := make([]inventory.Device, 0, len(seen))
	for _, d := range seen {
		devices = append(devices, d)
	}

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Auto discovery found %d total devices", len(devices)))
	}

	// Return first non-nil error if all failed
	if cipResult.err != nil && s7Result.err != nil && modbusResult.err != nil && melsecResult.err != nil && finsResult.err != nil && srtpResult.err != nil && opcuaResult.err != nil && haasResult.err != nil && fanucResult.err != nil && mazakResult.err != nil {
		return devices, cipResult.err
	}

	return devices, nil
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
