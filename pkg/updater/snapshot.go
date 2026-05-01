package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
)

// defaultSnapshotURL is the canonical pre-built advisory snapshot. The host
// is owned by the deadband project; the file is regenerated on a regular
// cadence from CISA's CSAF feed. When the snapshot is unreachable we fall
// back to per-file fetch from cisagov/CSAF.
const defaultSnapshotURL = "https://deadband.org/advisories.latest.json"

// snapshotHTTPTimeout caps any single snapshot fetch. Snapshots are small
// (~tens of MB even at full CISA scope) and a 60s ceiling avoids wedging
// behind a misconfigured CDN.
const snapshotHTTPTimeout = 60 * time.Second

// loadFromSnapshot fetches a pre-built advisory database from a single URL,
// verifying its SHA-256 checksum against the sibling ".sha256" file. Returns
// a populated *advisory.Database or an error describing why the snapshot
// could not be used. Callers should fall back to per-file fetch on any error.
//
// The checksum protects against transit corruption only — it is not a
// signature. Real signing will follow once the hosting infrastructure exists.
func loadFromSnapshot(url string, progress func(string)) (*advisory.Database, error) {
	if progress != nil {
		progress(fmt.Sprintf("Fetching snapshot from %s", url))
	}

	client := &http.Client{Timeout: snapshotHTTPTimeout}

	body, err := fetchSnapshotBody(client, url)
	if err != nil {
		return nil, err
	}

	checksum, err := fetchSnapshotChecksum(client, url+".sha256")
	if err != nil {
		return nil, fmt.Errorf("snapshot checksum: %w", err)
	}

	got := sha256.Sum256(body)
	gotHex := hex.EncodeToString(got[:])
	if gotHex != checksum {
		return nil, fmt.Errorf("snapshot checksum mismatch: got %s, want %s", gotHex, checksum)
	}

	var db advisory.Database
	if err := json.Unmarshal(body, &db); err != nil {
		return nil, fmt.Errorf("parsing snapshot json: %w", err)
	}
	if len(db.Advisories) == 0 {
		return nil, fmt.Errorf("snapshot contains zero advisories — refusing to install")
	}

	// Stamp the source so consumers can tell snapshot vs per-file in the UI.
	db.Source = "deadband-snapshot"
	if db.Updated.IsZero() {
		db.Updated = time.Now().UTC()
	}

	if progress != nil {
		progress(fmt.Sprintf("Snapshot verified: %d advisories", len(db.Advisories)))
	}
	return &db, nil
}

func fetchSnapshotBody(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snapshot %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func fetchSnapshotChecksum(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// .sha256 file format is "<hex>  <filename>\n" or just "<hex>\n".
	field := strings.TrimSpace(strings.SplitN(string(raw), " ", 2)[0])
	if len(field) != 64 {
		return "", fmt.Errorf("unexpected checksum format: %q", field)
	}
	return strings.ToLower(field), nil
}

// snapshotSourceMode classifies how Update() should treat opts.Source.
type snapshotSourceMode int

const (
	sourceSnapshotDefault snapshotSourceMode = iota // empty → try default snapshot
	sourceSnapshotURL                                // explicit http(s):// URL
	sourcePerFileGitHub                              // "github" forces per-file fetch
	sourceLocalMirror                                // local path → existing air-gap behavior
)

// classifySource decides how to interpret opts.Source. Returns the mode and,
// for sourceSnapshotURL, the URL to fetch.
func classifySource(source string) (snapshotSourceMode, string) {
	source = strings.TrimSpace(source)
	switch {
	case source == "":
		return sourceSnapshotDefault, defaultSnapshotURL
	case source == "github":
		return sourcePerFileGitHub, ""
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		return sourceSnapshotURL, source
	default:
		return sourceLocalMirror, ""
	}
}
