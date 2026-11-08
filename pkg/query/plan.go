// Package query executes explicitly scoped, bounded asset enrichment plans.
// It intentionally has no dependency on the discovery dispatcher: a profile
// cannot acquire additional protocols or post-scan work through a fallback.
package query

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion            = 1
	ProfileENIPIdentityTCP   = "enip-identity-tcp-v1"
	ProfileModbusIdentityTCP = "modbus-device-id-basic-tcp-v1"
	MaxTargets               = 256
	MaxResponseBytes         = 4096
)

// Input fields are deliberately serialized even when empty. Hashing includes
// every input field except plan_hash. Timestamps retain their original RFC3339
// spelling. Object keys are sorted recursively, arrays retain order, strings
// use JSON escaping without HTML escaping, and numbers are integers. This is
// equivalent to recursively sorting this schema then JSON.stringify in JS.
type Plan struct {
	SchemaVersion int      `json:"schema_version"`
	ID            string   `json:"id"`
	Purpose       string   `json:"purpose"`
	Profile       string   `json:"profile"`
	CreatedAt     string   `json:"created_at"`
	ExpiresAt     string   `json:"expires_at"`
	Targets       []Target `json:"targets"`
	Budget        Budget   `json:"budget"`
	PlanHash      string   `json:"plan_hash"`
}

type Target struct {
	AssetID         string           `json:"asset_id"`
	IP              string           `json:"ip"`
	Port            int              `json:"port"`
	RequestedFields []string         `json:"requested_fields"`
	Expected        ExpectedIdentity `json:"expected"`
	UnitID          *int             `json:"unit_id,omitempty"`
}

type ExpectedIdentity struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
	Serial string `json:"serial"`
}

// Byte limits count application bytes, excluding transport headers and TCP
// retransmissions. Connections count attempts, including refused attempts.
type Budget struct {
	MaxTargets        int `json:"max_targets"`
	MaxConnections    int `json:"max_connections"`
	MaxRequests       int `json:"max_requests"`
	MaxBytesSent      int `json:"max_bytes_sent"`
	MaxBytesReceived  int `json:"max_bytes_received"`
	TimeoutMS         int `json:"timeout_ms"`
	MaxDurationMS     int `json:"max_duration_ms"`
	Concurrency       int `json:"concurrency"`
	RequestsPerSecond int `json:"requests_per_second"`
}

func NewPlan(targets []Target, purpose string) (Plan, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Plan{}, err
	}
	now := time.Now().UTC()
	n := len(targets)
	p := Plan{SchemaVersion: SchemaVersion, ID: hex.EncodeToString(id[:]), Purpose: purpose,
		Profile: ProfileENIPIdentityTCP, CreatedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Targets: targets,
		Budget: Budget{MaxTargets: MaxTargets, MaxConnections: n, MaxRequests: n,
			MaxBytesSent: 24 * n, MaxBytesReceived: MaxResponseBytes * n,
			TimeoutMS: 2000, MaxDurationMS: 300000, Concurrency: 1, RequestsPerSecond: 2}}
	var err error
	p.PlanHash, err = Hash(p)
	if err != nil {
		return Plan{}, err
	}
	if err = Validate(p); err != nil {
		return Plan{}, err
	}
	return p, nil
}

// NewModbusLabPlan scopes a basic identification request to a single known unit.
// The returned plan contains no fallback, discovery sweep, or firmware claim.
func NewModbusLabPlan(target Target) (Plan, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Plan{}, err
	}
	now := time.Now().UTC()
	p := Plan{SchemaVersion: 2, ID: hex.EncodeToString(id[:]), Purpose: "enrich", Profile: ProfileModbusIdentityTCP, CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano), Targets: []Target{target}, Budget: Budget{MaxTargets: 1, MaxConnections: 1, MaxRequests: 1, MaxBytesSent: 11, MaxBytesReceived: 260, TimeoutMS: 2000, MaxDurationMS: 5000, Concurrency: 1, RequestsPerSecond: 1}}
	var err error
	p.PlanHash, err = Hash(p)
	if err != nil {
		return Plan{}, err
	}
	if err = Validate(p); err != nil {
		return Plan{}, err
	}
	return p, nil
}

// Decode rejects unknown fields, duplicate object keys, oversized input and
// trailing JSON before the plan can reach the executor.
func Decode(r io.Reader) (Plan, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if err != nil {
		return Plan{}, err
	}
	if len(data) > 1<<20 {
		return Plan{}, fmt.Errorf("query plan exceeds 1 MiB")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Plan{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Plan
	if err := dec.Decode(&p); err != nil {
		return Plan{}, fmt.Errorf("invalid query plan: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Plan{}, fmt.Errorf("query plan must contain one JSON value")
	}
	if err := Validate(p); err != nil {
		return Plan{}, err
	}
	return p, nil
}

func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return fmt.Errorf("invalid JSON key")
				}
				if seen[key] {
					return fmt.Errorf("duplicate query plan key %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("query plan must contain one JSON value")
	}
	return nil
}

func Hash(p Plan) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var obj map[string]any
	if err := d.Decode(&obj); err != nil {
		return "", err
	}
	delete(obj, "plan_hash")
	var out bytes.Buffer
	if err := canonical(&out, obj); err != nil {
		return "", err
	}
	h := sha256.Sum256(out.Bytes())
	return hex.EncodeToString(h[:]), nil
}

func canonical(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case string:
		out.WriteByte('"')
		for _, r := range x {
			switch r {
			case '"':
				out.WriteString(`\"`)
			case '\\':
				out.WriteString(`\\`)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 0x20 {
					fmt.Fprintf(out, `\u%04x`, r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := canonical(out, k); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := canonical(out, x[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := canonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	default:
		var b bytes.Buffer
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		if err := e.Encode(v); err != nil {
			return err
		}
		out.Write(bytes.TrimSuffix(b.Bytes(), []byte{'\n'}))
	}
	return nil
}

func Validate(p Plan) error { return validateAt(p, time.Now()) }
func validateAt(p Plan, now time.Time) error {
	bad := func(s string) error { return fmt.Errorf("invalid query plan: %s", s) }
	if !(p.SchemaVersion == SchemaVersion && p.Profile == ProfileENIPIdentityTCP || p.SchemaVersion == 2 && p.Profile == ProfileModbusIdentityTCP) {
		return bad("unsupported schema_version")
	}
	if p.Purpose != "enrich" && p.Purpose != "verify" {
		return bad("purpose must be enrich or verify")
	}
	if p.Profile == ProfileModbusIdentityTCP && (p.Purpose != "enrich" || p.Budget.Concurrency != 1 || p.Budget.RequestsPerSecond != 1) {
		return bad("Modbus lab profile requires identity enrichment at one request per second")
	}
	if strings.TrimSpace(p.ID) == "" || len(p.ID) > 128 {
		return bad("id is required and limited to 128 bytes")
	}
	created, err := time.Parse(time.RFC3339Nano, p.CreatedAt)
	if err != nil {
		return bad("created_at must be RFC3339")
	}
	expires, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil {
		return bad("expires_at must be RFC3339")
	}
	if created.After(now.Add(time.Minute)) || !expires.After(created) || !expires.After(now) || expires.Sub(created) > 24*time.Hour {
		return bad("expired or invalid plan window")
	}
	b := p.Budget
	if len(p.Targets) < 1 || len(p.Targets) > MaxTargets || b.MaxTargets < len(p.Targets) || b.MaxTargets > MaxTargets {
		return bad("target limit must cover 1..256 targets")
	}
	if b.MaxConnections < 1 || b.MaxConnections > b.MaxTargets || b.MaxRequests < 1 || b.MaxRequests > b.MaxTargets {
		return bad("connections and requests must be 1..max_targets")
	}
	minSent, maxSent, minReceived, maxReceived := 24, 24*b.MaxTargets, 24, MaxResponseBytes*b.MaxTargets
	if p.Profile == ProfileModbusIdentityTCP {
		minSent, maxSent, minReceived, maxReceived = 11, 11*b.MaxTargets, 9, 260*b.MaxTargets
	}
	if b.MaxBytesSent < minSent || b.MaxBytesSent > maxSent || b.MaxBytesReceived < minReceived || b.MaxBytesReceived > maxReceived {
		return bad("invalid application byte budget")
	}
	if b.TimeoutMS < 1 || b.TimeoutMS > 10000 || b.MaxDurationMS < 1 || b.MaxDurationMS > 300000 || b.Concurrency < 1 || b.Concurrency > 8 || b.RequestsPerSecond < 1 || b.RequestsPerSecond > 10 {
		return bad("execution limits outside supported bounds")
	}
	seenAssets := map[string]bool{}
	seenEndpoints := map[string]bool{}
	for _, t := range p.Targets {
		if strings.TrimSpace(t.AssetID) == "" || len(t.AssetID) > 128 || seenAssets[t.AssetID] {
			return bad("asset_id must be nonempty and unique")
		}
		seenAssets[t.AssetID] = true
		ip, err := netip.ParseAddr(t.IP)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != t.IP || t.IP == "255.255.255.255" || ip.As4()[0] == 0 || ip.As4()[0] >= 240 {
			return bad("target must be a canonical IPv4 unicast literal")
		}
		endpointKey := t.IP
		if p.Profile == ProfileENIPIdentityTCP {
			if t.Port != 44818 || t.UnitID != nil {
				return bad("invalid ENIP endpoint")
			}
		} else {
			if t.Port != 502 || t.UnitID == nil || *t.UnitID < 1 || *t.UnitID > 247 && *t.UnitID != 255 || t.Expected.Serial != "" || t.Expected.Model != "" {
				return bad("invalid Modbus endpoint or identity")
			}
			endpointKey = fmt.Sprintf("%s/%d", t.IP, *t.UnitID)
		}
		if seenEndpoints[endpointKey] {
			return bad("duplicate physical endpoint")
		}
		seenEndpoints[endpointKey] = true
		if len(t.RequestedFields) == 0 || len(t.RequestedFields) > 4 {
			return bad("requested_fields is required")
		}
		fields := map[string]bool{}
		for _, f := range t.RequestedFields {
			allowed := f == "vendor" || p.Profile == ProfileENIPIdentityTCP && (f == "model" || f == "firmware" || f == "serial") || p.Profile == ProfileModbusIdentityTCP && (f == "product_code" || f == "identity_revision")
			if !allowed || fields[f] {
				return bad("unsupported or duplicate requested field")
			}
			fields[f] = true
		}
		for _, s := range []string{t.Expected.Vendor, t.Expected.Model, t.Expected.Serial} {
			if len(s) > 256 {
				return bad("expected identity field exceeds 256 bytes")
			}
		}
	}
	h, err := Hash(p)
	if err != nil {
		return err
	}
	if p.PlanHash != h {
		return bad("plan_hash mismatch")
	}
	return nil
}
