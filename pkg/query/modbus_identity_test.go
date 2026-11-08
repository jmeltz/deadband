package query

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"testing/iotest"
	"time"
)

func TestModbusCanonicalPlanFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/modbus-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	var plan Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	hash, err := Hash(plan)
	if err != nil || hash != "4201fb7660a33d8086e18dab4a5e394c28b2e5cdc1cded8987edf5006cb0c728" || hash != plan.PlanHash {
		t.Fatalf("hash %s: %v", hash, err)
	}
	at, _ := time.Parse(time.RFC3339, plan.CreatedAt)
	if err := validateAt(plan, at); err != nil {
		t.Fatal(err)
	}
}

func modbusFrame(tx uint16, unit byte, pdu []byte) []byte {
	b := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(b, tx)
	binary.BigEndian.PutUint16(b[4:], uint16(1+len(pdu)))
	b[6] = unit
	copy(b[7:], pdu)
	return b
}

func TestModbusIdentityOneKnownUnit(t *testing.T) {
	request, err := modbusIdentityRequest(0x1234, 7)
	if err != nil || !bytes.Equal(request, []byte{0x12, 0x34, 0, 0, 0, 5, 7, 0x2b, 0x0e, 1, 0}) {
		t.Fatalf("request %x: %v", request, err)
	}
	for _, unit := range []byte{0, 248, 254} {
		if _, err := modbusIdentityRequest(1, unit); err == nil {
			t.Fatalf("accepted unit %d", unit)
		}
	}
	if _, err := modbusIdentityRequest(1, 255); err != nil {
		t.Fatal(err)
	}
	pdu := []byte{0x2b, 0x0e, 1, 1, 0, 0, 3, 0, 3, 'A', 'B', 'C', 1, 1, 'X', 2, 3, '1', '.', '2'}
	reply, err := readModbusIdentityReply(iotest.OneByteReader(bytes.NewReader(modbusFrame(0x1234, 7, pdu))), 0x1234, 7)
	if err != nil || string(reply.Objects[0]) != "ABC" || string(reply.Objects[2]) != "1.2" || reply.MoreFollows {
		t.Fatalf("reply %+v: %v", reply, err)
	}
}

func TestModbusIdentityRejectsMalformedAndRetainsExceptions(t *testing.T) {
	pdu := []byte{0x2b, 0x0e, 1, 1, 0, 0, 2, 0, 1, 'A', 0, 1, 'B'}
	cases := [][]byte{modbusFrame(2, 7, pdu), modbusFrame(1, 8, pdu), modbusFrame(1, 7, pdu), modbusFrame(1, 7, []byte{0x2b, 0x0e, 1, 1, 0, 0, 1, 0, 4, 'A'})}
	for _, frame := range cases {
		if _, err := readModbusIdentityReply(bytes.NewReader(frame), 1, 7); err == nil {
			t.Fatalf("accepted malformed frame %x", frame)
		}
	}
	reply, err := readModbusIdentityReply(bytes.NewReader(modbusFrame(1, 7, []byte{0xab, 1})), 1, 7)
	if err != nil || reply.Exception != 1 {
		t.Fatalf("exception %+v: %v", reply, err)
	}
	reply, err = readModbusIdentityReply(bytes.NewReader(modbusFrame(1, 7, []byte{0x2b, 0x0e, 1, 1, 0xff, 2, 1, 0, 1, 'A'})), 1, 7)
	if err != nil || !reply.MoreFollows || reply.NextObject != 2 {
		t.Fatalf("continuation %+v: %v", reply, err)
	}
}

func TestModbusPlanExecutesOneRequestPerSelectedUnit(t *testing.T) {
	unit := 7
	now := time.Now().UTC()
	p := Plan{SchemaVersion: 2, ID: "fixture", Purpose: "enrich", Profile: ProfileModbusIdentityTCP, CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Targets: []Target{{AssetID: "unit7", IP: "127.0.0.1", Port: 502, UnitID: &unit, RequestedFields: []string{"vendor", "product_code", "identity_revision"}}}, Budget: Budget{MaxTargets: 1, MaxConnections: 1, MaxRequests: 1, MaxBytesSent: 11, MaxBytesReceived: 260, TimeoutMS: 2000, MaxDurationMS: 5000, Concurrency: 1, RequestsPerSecond: 1}}
	var err error
	p.PlanHash, err = Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			req := make([]byte, 11)
			if _, e := io.ReadFull(b, req); e != nil {
				return
			}
			want, _ := modbusIdentityRequest(1, 7)
			if !bytes.Equal(req, want) {
				return
			}
			_, _ = b.Write(modbusFrame(1, 7, []byte{0x2b, 0x0e, 1, 1, 0, 0, 3, 0, 3, 'A', 'B', 'C', 1, 1, 'X', 2, 3, '1', '.', '2'}))
		}()
		return a, nil
	}
	result, err := execute(context.Background(), p, dial)
	if err != nil {
		t.Fatal(err)
	}
	got := result.Outcomes[0]
	if calls != 1 || got.Status != "success" || got.Metrics.Connections != 1 || got.Metrics.Requests != 1 || got.Metrics.BytesSent != 11 || len(got.Observations) != 3 || got.Observations[2].VersionKind != "modbus_identity_revision" {
		t.Fatalf("calls %d outcome %+v", calls, got)
	}
}
