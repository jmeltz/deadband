package discover

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

type Opts struct {
	CIDR        string
	Timeout     time.Duration
	HTTPTimeout time.Duration
	Concurrency int
	Progress    func(msg string)
}

// Run performs Rockwell EtherNet/IP device discovery on a CIDR range
// and returns the results as inventory devices ready for matching.
func Run(opts Opts) ([]inventory.Device, error) {
	ips, err := ExpandCIDR(opts.CIDR)
	if err != nil {
		return nil, err
	}

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
