// Package discover — Haas NGC Q-command discovery.
//
// Haas Automation's Next Generation Control (NGC) exposes an ASCII Q-command
// interface on TCP/5051 designed for shop-management software integration.
// It is an unauthenticated, read-only protocol from the perspective of the
// queries we issue: each Q-command returns a single line and changes no
// machine state.
//
// Wire format:
//
//	Client → ?Q100\r\n            (machine name / serial)
//	Server → >Q100 1234567 OK<    (or >Q100 ALARM<, or no response)
//	Client → ?Q104\r\n            (software / firmware version)
//	Server → >Q104 100.21.000.1037 OK<
//
// Some shops disable the Q-command listener — we treat any read timeout as
// "host doesn't speak Haas" and skip silently.
package discover

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/inventory"
)

// HaasIdentity is the parsed result of a Q100/Q104 probe.
type HaasIdentity struct {
	MachineName string // from Q100
	Software    string // from Q104
}

// haasReply matches `>Qnnn <payload> [STATUS]<` envelopes. Captures the
// payload between the command echo and the trailing status word.
var haasReply = regexp.MustCompile(`^>Q\d+\s+(.+?)(?:\s+(?:OK|ALARM|\?))?\s*<\s*$`)

// HaasProbe runs ?Q100 and ?Q104 against the target and returns identity.
// Returns nil, nil when the host doesn't respond or the reply doesn't parse —
// this is the common "shop has Haas Q-commands disabled" case.
func HaasProbe(ip string, timeout time.Duration) (*HaasIdentity, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", HaasPort))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	identity := &HaasIdentity{}

	if name, err := haasQuery(conn, "?Q100\r\n", timeout); err == nil {
		identity.MachineName = name
	}
	if sw, err := haasQuery(conn, "?Q104\r\n", timeout); err == nil {
		identity.Software = sw
	}

	if identity.MachineName == "" && identity.Software == "" {
		return nil, nil
	}
	return identity, nil
}

// haasQuery writes a single Q-command and parses the response line.
func haasQuery(conn net.Conn, query string, timeout time.Duration) (string, error) {
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('<')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, ">") {
		return "", fmt.Errorf("unexpected reply: %q", line)
	}
	m := haasReply.FindStringSubmatch(line)
	if len(m) < 2 {
		return "", fmt.Errorf("unparseable reply: %q", line)
	}
	payload := strings.TrimSpace(m[1])
	// Bare-status replies like ">Q500 ALARM<" capture the status word as
	// the payload because the optional status group is greedy. Reject those
	// — they carry no useful identification.
	switch payload {
	case "OK", "ALARM", "?":
		return "", fmt.Errorf("status-only reply: %q", line)
	}
	return payload, nil
}

// HaasIdentityToDevice converts a HaasIdentity to an inventory.Device.
func HaasIdentityToDevice(ip string, id *HaasIdentity) inventory.Device {
	return inventory.Device{
		IP:       ip,
		Vendor:   "Haas Automation",
		Model:    id.MachineName,
		Firmware: id.Software,
		Protocol: "haas",
		Port:     HaasPort,
	}
}

// discoverHaas runs HaasProbe over a slice of IPs concurrently.
func discoverHaas(ips []string, timeout time.Duration, concurrency int, progress func(string)) []inventory.Device {
	if progress != nil {
		progress(fmt.Sprintf("Haas: probing %d hosts on TCP/%d", len(ips), HaasPort))
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

			id, err := HaasProbe(ip, timeout)
			if err != nil || id == nil {
				return
			}

			dev := HaasIdentityToDevice(ip, id)
			mu.Lock()
			devices = append(devices, dev)
			mu.Unlock()

			if progress != nil {
				progress(fmt.Sprintf("Haas: %s → %s (sw %s)", ip, dev.Model, dev.Firmware))
			}
		}(ip)
	}

	wg.Wait()
	return devices
}
