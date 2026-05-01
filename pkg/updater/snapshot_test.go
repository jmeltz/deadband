package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
)

func TestClassifySource(t *testing.T) {
	tests := []struct {
		in   string
		mode snapshotSourceMode
	}{
		{"", sourceSnapshotDefault},
		{"  ", sourceSnapshotDefault},
		{"github", sourcePerFileGitHub},
		{"https://example.com/x.json", sourceSnapshotURL},
		{"http://localhost:8080/x.json", sourceSnapshotURL},
		{"/var/lib/csaf-mirror", sourceLocalMirror},
		{"./local-mirror", sourceLocalMirror},
	}
	for _, tt := range tests {
		got, _ := classifySource(tt.in)
		if got != tt.mode {
			t.Errorf("classifySource(%q): got %v, want %v", tt.in, got, tt.mode)
		}
	}
}

// fixtureSnapshotServer serves a JSON snapshot + matching .sha256 file. The
// JSON content can be tampered via the bodyOverride hook so we can exercise
// checksum-mismatch handling.
func fixtureSnapshotServer(t *testing.T, db advisory.Database, bodyOverride []byte) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal db: %v", err)
	}
	sum := sha256.Sum256(body) // checksum of canonical body
	checksum := hex.EncodeToString(sum[:]) + "  advisories.latest.json\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/x.json", func(w http.ResponseWriter, r *http.Request) {
		out := body
		if bodyOverride != nil {
			out = bodyOverride
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	mux.HandleFunc("/x.json.sha256", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksum))
	})
	return httptest.NewServer(mux)
}

func TestLoadFromSnapshot_Happy(t *testing.T) {
	db := advisory.Database{
		Updated: time.Now().UTC(),
		Source:  "test",
		Advisories: []advisory.Advisory{
			{ID: "ICSA-99-001", Title: "Test"},
		},
	}
	srv := fixtureSnapshotServer(t, db, nil)
	defer srv.Close()

	got, err := loadFromSnapshot(srv.URL+"/x.json", nil)
	if err != nil {
		t.Fatalf("loadFromSnapshot: %v", err)
	}
	if len(got.Advisories) != 1 || got.Advisories[0].ID != "ICSA-99-001" {
		t.Errorf("unexpected advisories: %+v", got.Advisories)
	}
	if got.Source != "deadband-snapshot" {
		t.Errorf("Source = %q, want deadband-snapshot", got.Source)
	}
}

func TestLoadFromSnapshot_ChecksumMismatch(t *testing.T) {
	db := advisory.Database{
		Updated:    time.Now().UTC(),
		Source:     "test",
		Advisories: []advisory.Advisory{{ID: "ICSA-99-001"}},
	}
	tampered := []byte(`{"advisories":[{"id":"ICSA-EVIL-001"}]}`)
	srv := fixtureSnapshotServer(t, db, tampered)
	defer srv.Close()

	_, err := loadFromSnapshot(srv.URL+"/x.json", nil)
	if err == nil {
		t.Fatal("expected checksum-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error message: %v (expected 'checksum mismatch')", err)
	}
}

func TestLoadFromSnapshot_HTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := loadFromSnapshot(srv.URL+"/x.json", nil)
	if err == nil {
		t.Fatal("expected HTTP error, got nil")
	}
}

func TestLoadFromSnapshot_EmptyAdvisories(t *testing.T) {
	db := advisory.Database{Source: "test"} // zero advisories
	srv := fixtureSnapshotServer(t, db, nil)
	defer srv.Close()

	_, err := loadFromSnapshot(srv.URL+"/x.json", nil)
	if err == nil {
		t.Fatal("expected error refusing empty snapshot")
	}
	if !strings.Contains(err.Error(), "zero advisories") {
		t.Errorf("error message: %v (expected 'zero advisories')", err)
	}
}
