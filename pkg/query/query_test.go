package query

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testPlan(t *testing.T, n int) Plan {
	t.Helper()
	targets := make([]Target, n)
	for i := range targets {
		targets[i] = Target{AssetID: fmt.Sprintf("asset-%d", i), IP: fmt.Sprintf("127.0.0.%d", i+1), Port: 44818, RequestedFields: []string{"model", "firmware", "serial"}}
	}
	p, err := NewPlan(targets, "enrich")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func rehash(t *testing.T, p *Plan) {
	t.Helper()
	var err error
	p.PlanHash, err = Hash(*p)
	if err != nil {
		t.Fatal(err)
	}
}

func fixtureIdentity() []byte {
	name := []byte("1756-EN2T/D")
	data := make([]byte, 34+len(name))
	binary.LittleEndian.PutUint16(data, 1)
	binary.BigEndian.PutUint16(data[2:], 2)
	binary.LittleEndian.PutUint16(data[18:], 1)
	binary.LittleEndian.PutUint16(data[20:], 12)
	binary.LittleEndian.PutUint16(data[22:], 43)
	data[24], data[25] = 11, 2
	binary.LittleEndian.PutUint32(data[28:], 0x12345678)
	data[32] = byte(len(name))
	copy(data[33:], name)
	body := make([]byte, 6)
	binary.LittleEndian.PutUint16(body, 1)
	binary.LittleEndian.PutUint16(body[2:], 0x0c)
	binary.LittleEndian.PutUint16(body[4:], uint16(len(data)))
	body = append(body, data...)
	header := make([]byte, 24)
	binary.LittleEndian.PutUint16(header, 0x63)
	binary.LittleEndian.PutUint16(header[2:], uint16(len(body)))
	return append(header, body...)
}

func loopbackDial(t *testing.T, handler func(net.Conn)) dialFunc {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handler(c) }()
		}
	}()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasSuffix(addr, ":44818") {
			return nil, fmt.Errorf("undeclared endpoint: %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}
}

func TestIdentityOnlyWireContract(t *testing.T) {
	var requests atomic.Int32
	wireErr := make(chan error, 1)
	dial := loopbackDial(t, func(c net.Conn) {
		req := make([]byte, 24)
		if _, err := io.ReadFull(c, req); err != nil {
			wireErr <- err
			return
		}
		requests.Add(1)
		want := make([]byte, 24)
		want[0] = 0x63
		if !bytes.Equal(req, want) {
			wireErr <- fmt.Errorf("unexpected request: %x", req)
			return
		}
		// Segmented TCP data must be read by the frame length, not a single Read.
		response := fixtureIdentity()
		for _, part := range [][]byte{response[:9], response[9:25], response[25:]} {
			if _, err := c.Write(part); err != nil {
				wireErr <- err
				return
			}
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		extra := make([]byte, 1)
		n, err := c.Read(extra)
		if n != 0 || err != io.EOF {
			wireErr <- fmt.Errorf("unexpected follow-up: %x %v", extra[:n], err)
			return
		}
		wireErr <- nil
	})
	p := testPlan(t, 1)
	p.Targets[0].Expected = ExpectedIdentity{Vendor: "Allen-Bradley", Model: "1756-EN2T/D", Serial: "12345678"}
	rehash(t, &p)
	r, err := execute(context.Background(), p, dial)
	if err != nil {
		t.Fatal(err)
	}
	o := r.Outcomes[0]
	if o.Status != "success" || o.Metrics.Connections != 1 || o.Metrics.Requests != 1 || o.Metrics.BytesSent != 24 || o.Metrics.BytesReceived != len(fixtureIdentity()) {
		t.Fatalf("outcome: %+v", o)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests=%d", requests.Load())
	}
	if err := <-wireErr; err != nil {
		t.Fatal(err)
	}
	fields := map[string]Observation{}
	for _, o := range o.Observations {
		fields[o.Field] = o
		if o.Protocol != "enip" || o.Operation != "ListIdentity" || o.Component != "identity" {
			t.Fatalf("bad provenance %+v", o)
		}
	}
	if fields["firmware"].Value != "11.002" || fields["firmware"].RawValue != "11.2" || fields["firmware"].VersionKind != "identity_revision" || fields["vendor_id"].Value != "1" {
		t.Fatalf("observations %+v", fields)
	}
}

func TestValidateAllTargetsBeforeIO(t *testing.T) {
	for name, change := range map[string]func(*Plan){
		"unknown profile": func(p *Plan) { p.Profile = "auto" }, "unknown schema": func(p *Plan) { p.SchemaVersion = 2 },
		"DNS": func(p *Plan) { p.Targets[1].IP = "localhost" }, "multicast": func(p *Plan) { p.Targets[1].IP = "224.0.0.1" },
		"port": func(p *Plan) { p.Targets[1].Port = 80 }, "field": func(p *Plan) { p.Targets[1].RequestedFields = []string{"write"} },
		"expiry":      func(p *Plan) { p.ExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano) },
		"concurrency": func(p *Plan) { p.Budget.Concurrency = 9 }, "tampering": func(p *Plan) { p.Targets[1].Expected.Model = "changed" },
	} {
		t.Run(name, func(t *testing.T) {
			p := testPlan(t, 2)
			change(&p)
			if name != "tampering" {
				rehash(t, &p)
			}
			var calls atomic.Int32
			_, err := execute(context.Background(), p, func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, fmt.Errorf("unexpected dial")
			})
			if err == nil || calls.Load() != 0 {
				t.Fatalf("err=%v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestCancellationAndDeadlineOutcomes(t *testing.T) {
	dial := loopbackDial(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	for _, cancelParent := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelParent), func(t *testing.T) {
			p := testPlan(t, 2)
			p.Budget.MaxDurationMS = 60
			p.Budget.TimeoutMS = 1000
			rehash(t, &p)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelParent {
				time.AfterFunc(20*time.Millisecond, cancel)
			}
			start := time.Now()
			r, err := execute(ctx, p, dial)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("cancel did not interrupt read")
			}
			want := "budget_exhausted"
			if cancelParent {
				want = "canceled"
			}
			for _, o := range r.Outcomes {
				if o.Status != want {
					t.Fatalf("outcome %+v, want %s", o, want)
				}
			}
			if r.Outcomes[1].Metrics.Connections != 0 {
				t.Fatal("canceled target dialed")
			}
		})
	}
}

func TestBudgetsAndMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		budget   func(*Plan)
		response func() []byte
		want     string
	}{
		{"connection limit", func(p *Plan) { p.Budget.MaxConnections = 1 }, fixtureIdentity, "budget_exhausted"},
		{"received limit", func(p *Plan) { p.Budget.MaxBytesReceived = 24 }, fixtureIdentity, "budget_exhausted"},
		{"oversized header", func(*Plan) {}, func() []byte { b := fixtureIdentity()[:24]; binary.LittleEndian.PutUint16(b[2:], 65535); return b }, "error"},
		{"truncated frame", func(*Plan) {}, func() []byte { return fixtureIdentity()[:30] }, "error"},
		{"control character name", func(*Plan) {}, func() []byte { b := fixtureIdentity(); b[63] = '\n'; return b }, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPlan(t, 2)
			p.Budget.RequestsPerSecond = 10
			tc.budget(&p)
			rehash(t, &p)
			dial := loopbackDial(t, func(c net.Conn) {
				req := make([]byte, 24)
				if _, err := io.ReadFull(c, req); err == nil {
					_, _ = c.Write(tc.response())
				}
			})
			r, err := execute(context.Background(), p, dial)
			if err != nil {
				t.Fatal(err)
			}
			last := r.Outcomes[1]
			if last.Status != tc.want {
				t.Fatalf("%+v", r)
			}
			var total Metrics
			for _, o := range r.Outcomes {
				total.Connections += o.Metrics.Connections
				total.Requests += o.Metrics.Requests
				total.BytesSent += o.Metrics.BytesSent
				total.BytesReceived += o.Metrics.BytesReceived
			}
			if total.Connections > p.Budget.MaxConnections || total.Requests > p.Budget.MaxRequests || total.BytesSent > p.Budget.MaxBytesSent || total.BytesReceived > p.Budget.MaxBytesReceived {
				t.Fatalf("budget exceeded: %+v", total)
			}
		})
	}
}

func TestIdentityConflictRetainsEvidence(t *testing.T) {
	p := testPlan(t, 1)
	p.Targets[0].Expected.Serial = "different-device"
	rehash(t, &p)
	dial := loopbackDial(t, func(c net.Conn) {
		req := make([]byte, 24)
		_, _ = io.ReadFull(c, req)
		_, _ = c.Write(fixtureIdentity())
	})
	r, err := execute(context.Background(), p, dial)
	if err != nil {
		t.Fatal(err)
	}
	o := r.Outcomes[0]
	if o.Status != "identity_conflict" || len(o.Observations) < 4 {
		t.Fatalf("%+v", o)
	}
}

func TestStrictDecodeAndCanonicalHash(t *testing.T) {
	p := testPlan(t, 1)
	p.ID = "unicode <>& \u2028\u2029 literal \\u2028"
	rehash(t, &p)
	data, _ := json.Marshal(p)
	got, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.PlanHash != p.PlanHash {
		t.Fatal("hash changed")
	}
	var out bytes.Buffer
	if err := canonical(&out, map[string]any{"b": "<&\u2028", "a": []any{json.Number("1"), "x\n"}}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "{\"a\":[1,\"x\\n\"],\"b\":\"<&\u2028\"}" {
		t.Fatalf("canonical %q", out.String())
	}
	for _, bad := range []string{strings.TrimSuffix(string(data), "}") + `,"surprise":1}`, strings.TrimSuffix(string(data), "}") + `,"id":"duplicate"}`, string(data) + ` {}`} {
		if _, err := Decode(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// Generated with Node crypto SHA256(JSON.stringify(recursivelySortedPlan)),
// including literal U+2028/U+2029 and the distinct backslash-u2028 spelling.
func TestJavaScriptUnicodeHashGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/hash-unicode.json")
	if err != nil {
		t.Fatal(err)
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	h, err := Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	if h != p.PlanHash {
		t.Fatalf("Go/JS hash mismatch: got %s want %s", h, p.PlanHash)
	}
}

func TestRecordedSAQIdentityReply(t *testing.T) {
	b, err := os.ReadFile("testdata/saq-enip-identity.hex")
	if err != nil {
		t.Fatal(err)
	}
	frame, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseIdentity(frame[24:])
	if err != nil {
		t.Fatal(err)
	}
	if id.model != "SAQ CIP Adapter" || id.firmware != "1.002" || id.serial != "00001234" || id.vendorID != 0 || id.vendor != "" {
		t.Fatalf("recorded identity %+v", id)
	}
}
