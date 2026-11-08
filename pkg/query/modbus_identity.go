package query

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode/utf8"
)

type modbusBudgetReader struct {
	r       io.Reader
	ledger  *ledger
	metrics *Metrics
}

func (r modbusBudgetReader) Read(dst []byte) (int, error) {
	if !r.ledger.take("received", len(dst)) {
		return 0, errBudget
	}
	n, err := r.r.Read(dst)
	r.metrics.BytesReceived += n
	r.ledger.release("received", len(dst)-n)
	return n, err
}

func executeModbusTarget(conn net.Conn, target Target, l *ledger, outcome Outcome, ctx, parent context.Context) Outcome {
	fail := func(err error) Outcome {
		outcome.Status = statusFor(err, ctx, parent)
		outcome.Error = err.Error()
		return outcome
	}
	request, err := modbusIdentityRequest(1, byte(*target.UnitID))
	if err != nil {
		return fail(err)
	}
	if !l.take("requests", 1) || !l.take("sent", len(request)) {
		return fail(errBudget)
	}
	n, err := conn.Write(request)
	outcome.Metrics.Requests = 1
	outcome.Metrics.BytesSent = n
	l.release("sent", len(request)-n)
	if err != nil {
		return fail(err)
	}
	if n != len(request) {
		return fail(io.ErrShortWrite)
	}
	reply, err := readModbusIdentityReply(modbusBudgetReader{conn, l, &outcome.Metrics}, 1, byte(*target.UnitID))
	if err != nil {
		return fail(err)
	}
	if reply.Exception != 0 {
		outcome.Status = "error"
		if reply.Exception <= 3 {
			outcome.Status = "unsupported"
		}
		outcome.Error = fmt.Sprintf("Modbus exception 0x%02x", reply.Exception)
		return outcome
	}
	component := fmt.Sprintf("modbus_unit:%d", *target.UnitID)
	fields := map[byte]string{0: "vendor", 1: "product_code", 2: "identity_revision"}
	for id := byte(0); id <= 2; id++ {
		raw, ok := reply.Objects[id]
		if !ok {
			continue
		}
		if !utf8.Valid(raw) {
			return fail(fmt.Errorf("identity object %d is not UTF-8", id))
		}
		for _, ch := range string(raw) {
			if ch < 0x20 {
				return fail(fmt.Errorf("identity object %d contains a control character", id))
			}
		}
		value := strings.TrimSpace(string(raw))
		if value == "" {
			continue
		}
		obs := Observation{Field: fields[id], Value: value, RawValue: string(raw), Protocol: "modbus", Operation: "ReadDeviceIdentificationBasic", Component: component}
		if id == 2 {
			obs.VersionKind = "modbus_identity_revision"
		}
		outcome.Observations = append(outcome.Observations, obs)
	}
	if target.Expected.Vendor != "" && !strings.EqualFold(strings.TrimSpace(target.Expected.Vendor), strings.TrimSpace(string(reply.Objects[0]))) {
		outcome.Status = "identity_conflict"
		outcome.Error = "returned vendor conflicts with planned identity"
		return outcome
	}
	outcome.Status = "success"
	if reply.MoreFollows {
		outcome.Status = "partial"
		outcome.Error = fmt.Sprintf("additional identity objects available at 0x%02x; no continuation was sent", reply.NextObject)
	}
	for _, f := range target.RequestedFields {
		found := false
		for _, o := range outcome.Observations {
			if o.Field == f {
				found = true
				break
			}
		}
		if !found {
			outcome.Status = "partial"
		}
	}
	return outcome
}

// modbusIdentityRequest requests only the basic identity objects at one
// explicitly selected unit. Unit zero is excluded because gateways may treat
// it as a serial broadcast. There is no alternate-unit or operation fallback.
func modbusIdentityRequest(transaction uint16, unit byte) ([]byte, error) {
	if unit == 0 || unit > 247 && unit != 255 {
		return nil, fmt.Errorf("unit must be 1–247 or 255")
	}
	request := make([]byte, 11)
	binary.BigEndian.PutUint16(request[:2], transaction)
	binary.BigEndian.PutUint16(request[4:6], 5)
	request[6] = unit
	copy(request[7:], []byte{0x2b, 0x0e, 0x01, 0x00})
	return request, nil
}

type modbusIdentityReply struct {
	Objects     map[byte][]byte
	MoreFollows bool
	NextObject  byte
	Exception   byte
	BytesRead   int
}

// readModbusIdentityReply reads exactly one bounded MBAP frame. It retains
// continuation metadata but never requests another page automatically.
func readModbusIdentityReply(r io.Reader, transaction uint16, unit byte) (modbusIdentityReply, error) {
	var reply modbusIdentityReply
	var header [7]byte
	n, err := io.ReadFull(r, header[:])
	reply.BytesRead += n
	if err != nil {
		return reply, fmt.Errorf("read MBAP header: %w", err)
	}
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if binary.BigEndian.Uint16(header[:2]) != transaction || binary.BigEndian.Uint16(header[2:4]) != 0 || header[6] != unit {
		return reply, fmt.Errorf("response transaction, protocol, or unit mismatch")
	}
	if length < 3 || length > 254 {
		return reply, fmt.Errorf("invalid MBAP length %d", length)
	}
	pdu := make([]byte, length-1)
	n, err = io.ReadFull(r, pdu)
	reply.BytesRead += n
	if err != nil {
		return reply, fmt.Errorf("read Modbus response: %w", err)
	}
	if pdu[0] == 0xab {
		if len(pdu) != 2 || pdu[1] == 0 {
			return reply, fmt.Errorf("invalid Modbus exception")
		}
		reply.Exception = pdu[1]
		return reply, nil
	}
	if len(pdu) < 7 || pdu[0] != 0x2b || pdu[1] != 0x0e || pdu[2] != 1 {
		return reply, fmt.Errorf("invalid device identification response")
	}
	if pdu[3] != 1 && pdu[3] != 2 && pdu[3] != 3 && pdu[3] != 0x81 && pdu[3] != 0x82 && pdu[3] != 0x83 {
		return reply, fmt.Errorf("invalid conformity level")
	}
	if pdu[4] != 0 && pdu[4] != 0xff {
		return reply, fmt.Errorf("invalid continuation flag")
	}
	reply.MoreFollows, reply.NextObject = pdu[4] == 0xff, pdu[5]
	if !reply.MoreFollows && reply.NextObject != 0 {
		return reply, fmt.Errorf("unexpected next object")
	}
	reply.Objects = make(map[byte][]byte)
	offset := 7
	for i := 0; i < int(pdu[6]); i++ {
		if offset+2 > len(pdu) {
			return reply, fmt.Errorf("truncated identity object header")
		}
		id, size := pdu[offset], int(pdu[offset+1])
		offset += 2
		if id > 2 || offset+size > len(pdu) {
			return reply, fmt.Errorf("unexpected or truncated identity object")
		}
		if _, exists := reply.Objects[id]; exists {
			return reply, fmt.Errorf("duplicate identity object")
		}
		reply.Objects[id] = append([]byte(nil), pdu[offset:offset+size]...)
		offset += size
	}
	if offset != len(pdu) {
		return reply, fmt.Errorf("unexpected trailing response data")
	}
	return reply, nil
}
