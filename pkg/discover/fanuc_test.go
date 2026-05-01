package discover

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fixtureFTPServer accepts connections, sends a single banner line, then
// captures any client writes (which there should be none of for a banner
// grab) and closes.
func fixtureFTPServer(t *testing.T, banner string) (string, *[]byte, func()) {
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
				_, _ = io.WriteString(c, banner)
				c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						mu.Lock()
						captured = append(captured, buf[:n]...)
						mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), &captured, func() { _ = ln.Close() }
}

func bannerProbe(addr string, timeout time.Duration) (*FanucIdentity, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, nil
	}
	line := string(buf[:n])
	// Strip trailing CRLF if present.
	for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == '\n') {
		line = line[:len(line)-1]
	}

	if len(line) < 4 || line[:3] != "220" {
		return nil, nil
	}
	if !fanucBannerRE.MatchString(line) {
		return nil, nil
	}
	id := &FanucIdentity{Banner: line}
	if m := fanucSeriesRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Series = uppercaseASCII(m[1])
	}
	if m := fanucVersionRE.FindStringSubmatch(line); len(m) >= 2 {
		id.Version = m[1]
	}
	return id, nil
}

// uppercaseASCII upper-cases ASCII letters without locale dependencies.
func uppercaseASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func TestFanucBannerParse(t *testing.T) {
	tests := []struct {
		name, banner, wantSeries string
		match                    bool
	}{
		{
			name:       "series_30i_b",
			banner:     "220 FANUC SERIES 30i-B FTP server ready.\r\n",
			wantSeries: "30I-B",
			match:      true,
		},
		{
			name:       "series_0i_md",
			banner:     "220 FANUC 0i-MD ready.\r\n",
			wantSeries: "0I-MD",
			match:      true,
		},
		{
			name:       "robot_r30ib",
			banner:     "220-FANUC LTD. R-30iB ROBOT FTP SERVICE\r\n",
			wantSeries: "30IB",
			match:      true,
		},
		{
			name:   "non_fanuc_banner",
			banner: "220 ProFTPD 1.3.5 Server ready.\r\n",
			match:  false,
		},
		{
			name:   "wrong_status",
			banner: "421 Service not available\r\n",
			match:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, captured, stop := fixtureFTPServer(t, tt.banner)
			defer stop()

			id, err := bannerProbe(addr, 500*time.Millisecond)
			if err != nil {
				t.Fatalf("bannerProbe: %v", err)
			}
			if !tt.match {
				if id != nil {
					t.Errorf("expected nil identity, got %+v", id)
				}
				return
			}
			if id == nil {
				t.Fatal("expected identity, got nil")
			}
			if id.Series != tt.wantSeries {
				t.Errorf("Series: got %q, want %q", id.Series, tt.wantSeries)
			}

			// Read-only assertion: the banner-grab MUST NOT have written anything to the server.
			if len(*captured) > 0 {
				t.Errorf("Fanuc banner probe wrote %d bytes to server; expected zero. Got: %q",
					len(*captured), string(*captured))
			}
		})
	}
}

func TestFanucFOCAS2Stub(t *testing.T) {
	id, err := FanucFOCAS2Probe("10.0.0.1", 100*time.Millisecond)
	if id != nil {
		t.Errorf("FOCAS2 stub returned non-nil identity: %+v", id)
	}
	if err == nil {
		t.Error("FOCAS2 stub returned nil error; expected not-implemented")
	}
}
