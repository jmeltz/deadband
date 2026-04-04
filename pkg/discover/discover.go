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

func runAuto(opts Opts, ips []string) ([]inventory.Device, error) {
	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Auto discovery (CIP + S7 + Modbus + MELSEC + BACnet + FINS) on %d hosts...", len(ips)))
	}

	type result struct {
		devices []inventory.Device
		err     error
	}

	cipCh := make(chan result, 1)
	s7Ch := make(chan result, 1)
	modbusCh := make(chan result, 1)
	melsecCh := make(chan result, 1)
	bacnetCh := make(chan result, 1)
	finsCh := make(chan result, 1)

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
		d, e := runMELSEC(opts, ips)
		melsecCh <- result{d, e}
	}()
	go func() {
		d, e := runBACnet(opts, ips)
		bacnetCh <- result{d, e}
	}()
	go func() {
		d, e := runFINS(opts, ips)
		finsCh <- result{d, e}
	}()

	cipResult := <-cipCh
	s7Result := <-s7Ch
	modbusResult := <-modbusCh
	melsecResult := <-melsecCh
	bacnetResult := <-bacnetCh
	finsResult := <-finsCh

	// Merge results, deduplicate by IP (prefer result with non-empty Model)
	seen := make(map[string]inventory.Device)
	for _, d := range cipResult.devices {
		seen[d.IP] = d
	}
	for _, d := range s7Result.devices {
		if existing, ok := seen[d.IP]; !ok || existing.Model == "" {
			seen[d.IP] = d
		}
	}
	for _, d := range modbusResult.devices {
		if existing, ok := seen[d.IP]; !ok || existing.Model == "" {
			seen[d.IP] = d
		}
	}
	for _, d := range melsecResult.devices {
		if existing, ok := seen[d.IP]; !ok || existing.Model == "" {
			seen[d.IP] = d
		}
	}
	for _, d := range bacnetResult.devices {
		if existing, ok := seen[d.IP]; !ok || existing.Model == "" {
			seen[d.IP] = d
		}
	}
	for _, d := range finsResult.devices {
		if existing, ok := seen[d.IP]; !ok || existing.Model == "" {
			seen[d.IP] = d
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
	if cipResult.err != nil && s7Result.err != nil && modbusResult.err != nil && melsecResult.err != nil && bacnetResult.err != nil && finsResult.err != nil {
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
		}
		if dev.Model != "" {
			devices = append(devices, dev)
		}
	}

	return devices, nil
}
