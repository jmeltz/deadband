package query

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

type Result struct {
	PlanID      string    `json:"plan_id"`
	PlanHash    string    `json:"plan_hash"`
	StartedAt   string    `json:"started_at"`
	CompletedAt string    `json:"completed_at"`
	Outcomes    []Outcome `json:"outcomes"`
}

type Outcome struct {
	AssetID      string        `json:"asset_id"`
	IP           string        `json:"ip"`
	Status       string        `json:"status"`
	ObservedAt   string        `json:"observed_at"`
	Observations []Observation `json:"observations"`
	Metrics      Metrics       `json:"metrics"`
	Error        string        `json:"error,omitempty"`
}

type Observation struct {
	Field       string `json:"field"`
	Value       string `json:"value"`
	RawValue    string `json:"raw_value,omitempty"`
	Protocol    string `json:"protocol"`
	Operation   string `json:"operation"`
	Component   string `json:"component"`
	VersionKind string `json:"version_kind,omitempty"`
}

type Metrics struct {
	Connections   int `json:"connections"`
	Requests      int `json:"requests"`
	BytesSent     int `json:"bytes_sent"`
	BytesReceived int `json:"bytes_received"`
}

var errBudget = errors.New("query budget exhausted")

type ledger struct {
	sync.Mutex
	used        Metrics
	budget      Budget
	next        time.Time
	nextRequest time.Time
}

func (l *ledger) take(field string, n int) bool {
	l.Lock()
	defer l.Unlock()
	var used *int
	var limit int
	switch field {
	case "connections":
		used = &l.used.Connections
		limit = l.budget.MaxConnections
	case "requests":
		used = &l.used.Requests
		limit = l.budget.MaxRequests
	case "sent":
		used = &l.used.BytesSent
		limit = l.budget.MaxBytesSent
	case "received":
		used = &l.used.BytesReceived
		limit = l.budget.MaxBytesReceived
	}
	if used == nil || n > limit-*used {
		return false
	}
	*used += n
	return true
}

func (l *ledger) release(field string, n int) {
	l.Lock()
	defer l.Unlock()
	if field == "sent" {
		l.used.BytesSent -= n
	}
	if field == "received" {
		l.used.BytesReceived -= n
	}
}

// pace bounds new connection attempts as well as application requests, so a
// network full of refused targets cannot bypass the profile's traffic rate.
func (l *ledger) pace(ctx context.Context, request bool) error {
	l.Lock()
	at := time.Now()
	next := &l.next
	if request {
		next = &l.nextRequest
	}
	if next.After(at) {
		at = *next
	}
	*next = at.Add(time.Second / time.Duration(l.budget.RequestsPerSecond))
	l.Unlock()
	delay := time.Until(at)
	if delay <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Execute validates the whole immutable plan before opening any connection.
// A valid plan always returns one outcome per target, including unstarted or
// canceled targets. Per-target execution failures live in outcomes; the error
// return is reserved for invalid input plans.
func Execute(ctx context.Context, p Plan) (Result, error) {
	d := &net.Dialer{}
	return execute(ctx, p, d.DialContext)
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func execute(ctx context.Context, p Plan, dial dialFunc) (Result, error) {
	if err := Validate(p); err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	r := Result{PlanID: p.ID, PlanHash: p.PlanHash, StartedAt: now.Format(time.RFC3339Nano), Outcomes: make([]Outcome, len(p.Targets))}
	deadline := now.Add(time.Duration(p.Budget.MaxDurationMS) * time.Millisecond)
	expires, _ := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if expires.Before(deadline) {
		deadline = expires
	}
	execCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	l := &ledger{budget: p.Budget}
	var wg sync.WaitGroup
	jobs := make(chan int)
	for i := 0; i < p.Budget.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				r.Outcomes[i] = executeTarget(execCtx, ctx, p.Targets[i], p.Budget, l, dial, p.Profile)
			}
		}()
	}
	for i := range p.Targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	r.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return r, nil
}

func executeTarget(ctx, parent context.Context, t Target, b Budget, l *ledger, dial dialFunc, profile string) (o Outcome) {
	o = Outcome{AssetID: t.AssetID, IP: t.IP, Observations: []Observation{}}
	defer func() { o.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano) }()
	fail := func(err error) Outcome { o.Status = statusFor(err, ctx, parent); o.Error = err.Error(); return o }
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := l.pace(ctx, false); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if !l.take("connections", 1) {
		return fail(errBudget)
	}
	o.Metrics.Connections = 1
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutMS)*time.Millisecond)
	defer cancel()
	conn, err := dial(probeCtx, "tcp", net.JoinHostPort(t.IP, strconv.Itoa(t.Port)))
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	if d, ok := probeCtx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	stop := context.AfterFunc(probeCtx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := probeCtx.Err(); err != nil {
		return fail(err)
	}
	if err := l.pace(probeCtx, true); err != nil {
		return fail(err)
	}
	if profile == ProfileModbusIdentityTCP {
		return executeModbusTarget(conn, t, l, o, ctx, parent)
	}
	if !l.take("requests", 1) {
		return fail(errBudget)
	}
	if !l.take("sent", 24) {
		return fail(errBudget)
	}
	req := make([]byte, 24)
	binary.LittleEndian.PutUint16(req, 0x63)
	n, err := conn.Write(req)
	o.Metrics.Requests = 1
	o.Metrics.BytesSent = n
	l.release("sent", 24-n)
	if err != nil {
		return fail(err)
	}
	if n != 24 {
		return fail(io.ErrShortWrite)
	}
	read := func(dst []byte) error {
		if !l.take("received", len(dst)) {
			return errBudget
		}
		n, err := io.ReadFull(conn, dst)
		o.Metrics.BytesReceived += n
		l.release("received", len(dst)-n)
		return err
	}
	header := make([]byte, 24)
	if err := read(header); err != nil {
		return fail(err)
	}
	length := int(binary.LittleEndian.Uint16(header[2:4]))
	if binary.LittleEndian.Uint16(header[:2]) != 0x63 || binary.LittleEndian.Uint32(header[4:8]) != 0 || binary.LittleEndian.Uint64(header[12:20]) != 0 || binary.LittleEndian.Uint32(header[20:24]) != 0 {
		return fail(fmt.Errorf("invalid ListIdentity encapsulation header"))
	}
	if binary.LittleEndian.Uint32(header[8:12]) != 0 {
		o.Status = "unsupported"
		o.Error = "ListIdentity returned an encapsulation error"
		return o
	}
	if length < 2 || length > MaxResponseBytes-24 {
		return fail(fmt.Errorf("invalid ListIdentity response length %d", length))
	}
	body := make([]byte, length)
	if err := read(body); err != nil {
		return fail(err)
	}
	identity, err := parseIdentity(body)
	if err != nil {
		return fail(err)
	}
	o.Observations = identity.observations()
	if identity.conflicts(t.Expected) {
		o.Status = "identity_conflict"
		o.Error = "returned identity conflicts with the planned asset"
		return o
	}
	o.Status = "success"
	values := map[string]string{"vendor": identity.vendor, "model": identity.model, "firmware": identity.firmware, "serial": identity.serial}
	for _, f := range t.RequestedFields {
		if values[f] == "" {
			o.Status = "partial"
		}
	}
	return o
}

func statusFor(err error, ctx, parent context.Context) string {
	if parent.Err() != nil {
		return "canceled"
	}
	if ctx.Err() != nil || errors.Is(err, errBudget) {
		return "budget_exhausted"
	}
	// The socket deadline can fire just before context's timer goroutine runs.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return "budget_exhausted"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	return "error"
}

type identity struct {
	vendor, model, firmware, serial   string
	rawModel, rawRevision             string
	vendorID, deviceType, productCode uint16
}

func parseIdentity(body []byte) (identity, error) {
	var id identity
	if len(body) < 2 {
		return id, fmt.Errorf("missing identity item count")
	}
	count := int(binary.LittleEndian.Uint16(body))
	offset := 2
	found := false
	if count < 1 || count > 16 {
		return id, fmt.Errorf("invalid identity item count")
	}
	for i := 0; i < count; i++ {
		if offset+4 > len(body) {
			return id, fmt.Errorf("truncated identity item")
		}
		typ := binary.LittleEndian.Uint16(body[offset:])
		size := int(binary.LittleEndian.Uint16(body[offset+2:]))
		offset += 4
		if size > len(body)-offset {
			return id, fmt.Errorf("truncated identity data")
		}
		data := body[offset : offset+size]
		offset += size
		if typ != 0x0c {
			continue
		}
		if found {
			return id, fmt.Errorf("multiple identity items for one endpoint")
		}
		found = true
		if len(data) < 34 || binary.LittleEndian.Uint16(data[:2]) != 1 {
			return id, fmt.Errorf("invalid identity item layout")
		}
		nameLen := int(data[32])
		if 34+nameLen != len(data) {
			return id, fmt.Errorf("invalid identity product-name length")
		}
		id.vendorID = binary.LittleEndian.Uint16(data[18:20])
		id.deviceType = binary.LittleEndian.Uint16(data[20:22])
		id.productCode = binary.LittleEndian.Uint16(data[22:24])
		if !utf8.Valid(data[33 : 33+nameLen]) {
			return id, fmt.Errorf("identity product name is not UTF-8")
		}
		id.rawModel = string(data[33 : 33+nameLen])
		for _, r := range id.rawModel {
			if r < 0x20 {
				return id, fmt.Errorf("identity product name contains a control character")
			}
		}
		id.model = strings.TrimSpace(id.rawModel)
		id.firmware = fmt.Sprintf("%d.%03d", data[24], data[25])
		id.rawRevision = fmt.Sprintf("%d.%d", data[24], data[25])
		id.serial = fmt.Sprintf("%08X", binary.LittleEndian.Uint32(data[28:32]))
		id.vendor = vendorName(id.vendorID)
	}
	if !found || offset != len(body) {
		return id, fmt.Errorf("missing or malformed ListIdentity item")
	}
	return id, nil
}

func vendorName(id uint16) string {
	// IDs are retained separately so unknown vendors never become invented names.
	switch id {
	case 1:
		return "Rockwell Automation"
	case 2:
		return "Neles (Metso)"
	case 5:
		return "ODVA"
	case 7:
		return "SMC"
	case 40:
		return "WAGO"
	case 44:
		return "Yaskawa"
	case 47:
		return "Omron"
	case 56:
		return "Molex"
	case 68:
		return "Eaton"
	case 75:
		return "ABB"
	case 90:
		return "TURCK"
	case 97:
		return "Danfoss"
	case 105:
		return "PEPPERL+FUCHS"
	case 108:
		return "Beckhoff"
	case 134:
		return "Mitsubishi Electric"
	case 166:
		return "Festo"
	case 181:
		return "Pilz"
	case 246:
		return "Yamazaki Mazak"
	case 266:
		return "Schneider Electric"
	case 283:
		return "Siemens"
	case 287:
		return "Leuze"
	case 315:
		return "SEW-EURODRIVE"
	case 324:
		return "Banner Engineering"
	case 326:
		return "Emerson / GE"
	case 356, 591:
		return "Fanuc"
	case 480:
		return "Balluff"
	case 562:
		return "Phoenix Contact"
	case 586:
		return "ifm electronic"
	case 655:
		return "Murrelektronik"
	case 671:
		return "Honeywell"
	case 678:
		return "Cognex"
	case 792:
		return "Keyence"
	case 808:
		return "SICK"
	case 913:
		return "Moxa"
	}
	return ""
}

func (id identity) observations() []Observation {
	fields := [][2]string{{"vendor", id.vendor}, {"model", id.model}, {"firmware", id.firmware}, {"serial", id.serial}, {"vendor_id", strconv.Itoa(int(id.vendorID))}, {"device_type", strconv.Itoa(int(id.deviceType))}, {"product_code", strconv.Itoa(int(id.productCode))}}
	out := make([]Observation, 0, len(fields))
	for _, f := range fields {
		if f[1] == "" {
			continue
		}
		o := Observation{Field: f[0], Value: f[1], RawValue: f[1], Protocol: "enip", Operation: "ListIdentity", Component: "identity"}
		if f[0] == "model" {
			o.RawValue = id.rawModel
		}
		if f[0] == "firmware" {
			o.VersionKind = "identity_revision"
			o.RawValue = id.rawRevision
		}
		out = append(out, o)
	}
	return out
}

func (id identity) conflicts(e ExpectedIdentity) bool {
	// No fuzzy model matching or serial-based asset reassignment is performed.
	if e.Vendor != "" && canonicalVendor(e.Vendor) != canonicalVendor(id.vendor) {
		return true
	}
	for _, p := range [][2]string{{e.Model, id.model}, {e.Serial, id.serial}} {
		if strings.TrimSpace(p[0]) != "" && (p[1] == "" || !strings.EqualFold(strings.TrimSpace(p[0]), strings.TrimSpace(p[1]))) {
			return true
		}
	}
	return false
}

func canonicalVendor(v string) string {
	v = strings.ToLower(strings.Join(strings.Fields(v), " "))
	switch v {
	case "sick ag", "sick inc.":
		return "sick"
	case "rockwell", "rockwell automation, inc.", "allen-bradley", "allen bradley":
		return "rockwell automation"
	case "beckhoff automation", "beckhoff automation gmbh & co. kg":
		return "beckhoff"
	case "schneider", "schneider electric industries sas":
		return "schneider electric"
	case "siemens ag":
		return "siemens"
	}
	return v
}
