package advisory

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestLoadDatabase_BackwardCompat(t *testing.T) {
	// testdata/advisories.json has no first_seen/last_seen fields
	db, err := LoadDatabase("../../testdata/advisories.json")
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}
	for _, a := range db.Advisories {
		if a.FirstSeen != nil {
			t.Errorf("advisory %s: expected nil FirstSeen for old DB, got %v", a.ID, a.FirstSeen)
		}
		if a.LastSeen != nil {
			t.Errorf("advisory %s: expected nil LastSeen for old DB, got %v", a.ID, a.LastSeen)
		}
	}
	if db.PreviousUpdated != nil {
		t.Errorf("expected nil PreviousUpdated for old DB, got %v", db.PreviousUpdated)
	}
}

func TestStalenessStats(t *testing.T) {
	now := time.Now()
	recent := now.Add(-24 * time.Hour)
	old := now.Add(-8 * 30 * 24 * time.Hour) // 8 months ago
	prevUpdate := now.Add(-7 * 24 * time.Hour)

	db := &Database{
		Advisories: []Advisory{
			{ID: "A", FirstSeen: &recent},  // added since prevUpdate, not chronic
			{ID: "B", FirstSeen: &old},      // not added since, but chronic
			{ID: "C", FirstSeen: nil},        // no timestamp
		},
	}

	added, chronic := db.StalenessStats(&prevUpdate)
	if added != 1 {
		t.Errorf("addedSince = %d, want 1", added)
	}
	if chronic != 1 {
		t.Errorf("chronic = %d, want 1", chronic)
	}
}

func TestStalenessStats_NilSince(t *testing.T) {
	db := &Database{
		Advisories: []Advisory{{ID: "A"}},
	}
	added, _ := db.StalenessStats(nil)
	if added != -1 {
		t.Errorf("addedSince = %d, want -1 when since is nil", added)
	}
}

func TestSaveLoadRoundTrip_WithTimestamps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	prev := now.Add(-24 * time.Hour)

	db := &Database{
		Updated:         now,
		PreviousUpdated: &prev,
		Source:          "test",
		Advisories: []Advisory{
			{
				ID:        "TEST-01",
				FirstSeen: &prev,
				LastSeen:  &now,
			},
		},
	}

	tmp := filepath.Join(t.TempDir(), "test-db.json")
	if err := SaveDatabase(tmp, db); err != nil {
		t.Fatalf("SaveDatabase: %v", err)
	}

	db2, err := LoadDatabase(tmp)
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}

	if db2.PreviousUpdated == nil || !db2.PreviousUpdated.Equal(prev) {
		t.Errorf("PreviousUpdated = %v, want %v", db2.PreviousUpdated, prev)
	}
	a := db2.Advisories[0]
	if a.FirstSeen == nil || !a.FirstSeen.Equal(prev) {
		t.Errorf("FirstSeen = %v, want %v", a.FirstSeen, prev)
	}
	if a.LastSeen == nil || !a.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", a.LastSeen, now)
	}
}
