package updater

import (
	"testing"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
)

func TestMergeAdvisories_NewAdvisoryGetsFirstSeen(t *testing.T) {
	now := time.Now().UTC()
	existing := make(map[string]advisory.Advisory)

	fetched := []advisory.Advisory{
		{ID: "ICSA-24-001-01", Title: "New Advisory"},
	}

	result := mergeAdvisories(existing, fetched, now)
	a := result["ICSA-24-001-01"]
	if a.FirstSeen == nil {
		t.Fatal("expected FirstSeen to be set for new advisory")
	}
	if !a.FirstSeen.Equal(now) {
		t.Errorf("FirstSeen = %v, want %v", a.FirstSeen, now)
	}
	if a.LastSeen == nil || !a.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", a.LastSeen, now)
	}
}

func TestMergeAdvisories_ExistingPreservesFirstSeen(t *testing.T) {
	oldTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	existing := map[string]advisory.Advisory{
		"ICSA-24-001-01": {
			ID:        "ICSA-24-001-01",
			Title:     "Old Title",
			FirstSeen: &oldTime,
			LastSeen:  &oldTime,
		},
	}

	fetched := []advisory.Advisory{
		{ID: "ICSA-24-001-01", Title: "Updated Title"},
	}

	result := mergeAdvisories(existing, fetched, now)
	a := result["ICSA-24-001-01"]

	if a.Title != "Updated Title" {
		t.Errorf("Title = %q, want %q", a.Title, "Updated Title")
	}
	if a.FirstSeen == nil || !a.FirstSeen.Equal(oldTime) {
		t.Errorf("FirstSeen = %v, want %v (should be preserved)", a.FirstSeen, oldTime)
	}
	if a.LastSeen == nil || !a.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", a.LastSeen, now)
	}
}

func TestMergeAdvisories_MixedNewAndExisting(t *testing.T) {
	oldTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	existing := map[string]advisory.Advisory{
		"EXISTING-01": {ID: "EXISTING-01", FirstSeen: &oldTime},
	}

	fetched := []advisory.Advisory{
		{ID: "EXISTING-01"},
		{ID: "NEW-01"},
	}

	result := mergeAdvisories(existing, fetched, now)

	if len(result) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(result))
	}
	if !result["EXISTING-01"].FirstSeen.Equal(oldTime) {
		t.Error("existing advisory FirstSeen should be preserved")
	}
	if !result["NEW-01"].FirstSeen.Equal(now) {
		t.Error("new advisory FirstSeen should be set to now")
	}
}
