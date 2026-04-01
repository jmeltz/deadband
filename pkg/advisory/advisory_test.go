package advisory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDatabase(t *testing.T) {
	db, err := LoadDatabase("../../testdata/advisories.json")
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}
	if len(db.Advisories) != 5 {
		t.Errorf("expected 5 advisories, got %d", len(db.Advisories))
	}
	if db.Advisories[0].ID != "ICSA-24-179-01" {
		t.Errorf("first advisory ID = %q, want ICSA-24-179-01", db.Advisories[0].ID)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	db, err := LoadDatabase("../../testdata/advisories.json")
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}

	tmp := filepath.Join(t.TempDir(), "test-db.json")
	if err := SaveDatabase(tmp, db); err != nil {
		t.Fatalf("SaveDatabase: %v", err)
	}

	db2, err := LoadDatabase(tmp)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(db2.Advisories) != len(db.Advisories) {
		t.Errorf("round-trip: got %d advisories, want %d", len(db2.Advisories), len(db.Advisories))
	}

	// Verify tmp file was created (not leftover .tmp)
	if _, err := os.Stat(tmp + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file was not cleaned up")
	}
}

func TestStats(t *testing.T) {
	db, err := LoadDatabase("../../testdata/advisories.json")
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}
	stats := db.Stats()
	if stats == "" {
		t.Error("Stats() returned empty string")
	}
}
