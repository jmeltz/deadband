package discover

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtureHaasServer returns a TCP listener that emits canned Q-command
// replies. The handler also captures every byte the client wrote so tests can
// assert read-only behavior (only the documented Q-command queries are sent,
// nothing else).
func fixtureHaasServer(t *testing.T, replies map[string]string) (string, *[]byte, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var (
		mu       sync.Mutex
		captured []byte
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					line, err := r.ReadString('\n')
					if line != "" {
						mu.Lock()
						captured = append(captured, []byte(line)...)
						mu.Unlock()
					}
					if err != nil {
						return
					}
					query := strings.TrimSpace(line)
					if reply, ok := replies[query]; ok {
						_, _ = io.WriteString(c, reply)
					}
				}
			}(conn)
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = port
	return host + ":" + port, &captured, func() { _ = ln.Close() }
}

// probeHaasViaAddr is a test-helper that lets us point HaasProbe at an
// arbitrary host:port, since real HaasPort is fixed at 5051.
func probeHaasViaAddr(addr string, timeout time.Duration) (*HaasIdentity, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	id := &HaasIdentity{}
	if name, err := haasQuery(conn, "?Q100\r\n", timeout); err == nil {
		id.MachineName = name
	}
	if sw, err := haasQuery(conn, "?Q104\r\n", timeout); err == nil {
		id.Software = sw
	}
	if id.MachineName == "" && id.Software == "" {
		return nil, nil
	}
	return id, nil
}

func TestHaasProbeParsesQReplies(t *testing.T) {
	addr, captured, stop := fixtureHaasServer(t, map[string]string{
		"?Q100": ">Q100 1234567 OK<",
		"?Q104": ">Q104 100.21.000.1037 OK<",
	})
	defer stop()

	id, err := probeHaasViaAddr(addr, 1*time.Second)
	if err != nil {
		t.Fatalf("probeHaas: %v", err)
	}
	if id == nil {
		t.Fatal("expected identity, got nil")
	}
	if id.MachineName != "1234567" {
		t.Errorf("MachineName: got %q, want %q", id.MachineName, "1234567")
	}
	if id.Software != "100.21.000.1037" {
		t.Errorf("Software: got %q, want %q", id.Software, "100.21.000.1037")
	}

	// Read-only assertion: probe must only have written documented Q-command queries.
	got := strings.TrimSpace(string(*captured))
	wantLines := []string{"?Q100", "?Q104"}
	for _, want := range wantLines {
		if !strings.Contains(got, want) {
			t.Errorf("captured writes missing %q; got %q", want, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "?Q") {
			t.Errorf("probe wrote unexpected non-Q-command bytes: %q", line)
		}
	}
}

func TestHaasProbeNoResponse(t *testing.T) {
	// Listener that accepts then immediately closes — simulates a shop with
	// Q-commands disabled (port open but no protocol).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	id, err := probeHaasViaAddr(ln.Addr().String(), 200*time.Millisecond)
	if err != nil {
		t.Fatalf("probeHaas error: %v", err)
	}
	if id != nil {
		t.Errorf("expected nil identity for closed connection, got %+v", id)
	}
}

func TestHaasReplyParsing(t *testing.T) {
	// Validates the haasReply regex captures the payload from well-formed
	// replies. Status-only replies (e.g. ">Q500 ALARM<") match the regex
	// because the status group is optional — those are filtered downstream
	// in haasQuery, not at the regex layer. See TestHaasQueryStatusOnly.
	tests := []struct {
		name, line, want string
		shouldMatch      bool
	}{
		{"basic", ">Q104 100.21.000.1037 OK<", "100.21.000.1037", true},
		{"no_status", ">Q100 1234567<", "1234567", true},
		{"alarm_status_capture", ">Q500 ALARM<", "ALARM", true},
		{"malformed", "garbage", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := haasReply.FindStringSubmatch(tt.line)
			if !tt.shouldMatch {
				if len(m) >= 2 {
					t.Errorf("expected parse failure, got payload %q", m[1])
				}
				return
			}
			if len(m) < 2 {
				t.Fatalf("no match for %q", tt.line)
			}
			if m[1] != tt.want {
				t.Errorf("got %q, want %q", m[1], tt.want)
			}
		})
	}
}

// TestHaasQueryStatusOnlyReply asserts haasQuery rejects bare-status replies
// (no real payload) so they don't pollute discovery output with the literal
// string "ALARM" as a machine name.
func TestHaasQueryStatusOnlyReply(t *testing.T) {
	addr, _, stop := fixtureHaasServer(t, map[string]string{
		"?Q100": ">Q500 ALARM<",
	})
	defer stop()

	id, err := probeHaasViaAddr(addr, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("probeHaas: %v", err)
	}
	// Q100 returns status-only → MachineName must NOT be "ALARM".
	if id != nil && id.MachineName == "ALARM" {
		t.Errorf("status-only reply leaked into MachineName: %q", id.MachineName)
	}
}
