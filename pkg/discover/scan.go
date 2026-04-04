package discover

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	EIPPort       = 44818
	S7Port        = 102
	ModbusTCPPort = 502
	SLMPPort      = 5007
)

// ExpandCIDR returns all usable host IPs in a CIDR range.
// Single IPs without a mask are treated as /32.
func ExpandCIDR(cidr string) ([]string, error) {
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	var ips []string
	for addr := ip.Mask(ipNet.Mask); ipNet.Contains(addr); incIP(addr) {
		ips = append(ips, addr.String())
	}

	// Remove network and broadcast addresses for ranges larger than /32
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ScanPorts checks which IPs have the given TCP port open.
func ScanPorts(ips []string, port int, timeout time.Duration, concurrency int) []string {
	var mu sync.Mutex
	var open []string

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			open = append(open, ip)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return open
}
