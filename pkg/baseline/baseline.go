package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/diff"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

// Baseline stores a snapshot of discovered devices for drift detection.
type Baseline struct {
	Version   int                `json:"version"`
	UpdatedAt time.Time          `json:"updated_at"`
	Devices   []inventory.Device `json:"devices"`
}

// DefaultPath returns the default baseline file location (~/.deadband/baseline.json).
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "baseline.json"
	}
	return filepath.Join(home, ".deadband", "baseline.json")
}

// Load reads a baseline from the given path.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &b, nil
}

// Save writes a baseline to the given path, creating directories as needed.
func Save(path string, b *Baseline) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating baseline directory: %w", err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}
	return nil
}

// NewFromDevices creates a Baseline from a device list.
func NewFromDevices(devices []inventory.Device) *Baseline {
	return &Baseline{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Devices:   devices,
	}
}

// Compare loads the baseline at path and computes a diff against the current devices.
func Compare(path string, devices []inventory.Device, db *advisory.Database, opts matcher.FilterOpts) (*diff.DiffReport, error) {
	b, err := Load(path)
	if err != nil {
		return nil, err
	}
	report := diff.Compute(b.Devices, devices, db, opts)
	report.BaseFile = "baseline (" + b.UpdatedAt.Format("2006-01-02 15:04:05") + ")"
	report.CompareFile = "current scan"
	return report, nil
}
