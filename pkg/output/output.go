package output

import (
	"fmt"
	"io"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/diff"
	"github.com/jmeltz/deadband/pkg/matcher"
)

type Summary struct {
	Vulnerable int
	Potential  int
	OK         int
	NoMatch    int
}

type ResultWriter interface {
	WriteHeader(dbInfo advisory.Database, deviceCount int) error
	WriteResult(result matcher.Result) error
	WriteSummary(summary Summary, totalDevices int) error
	Flush() error
}

func NewWriter(w io.Writer, format string) (ResultWriter, error) {
	switch format {
	case "text":
		return &textWriter{w: w}, nil
	case "csv":
		return newCSVWriter(w), nil
	case "json":
		return newJSONWriter(w), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}

// DiffWriter writes a diff report in a specific format.
type DiffWriter interface {
	WriteDiff(report *diff.DiffReport) error
	Flush() error
}

// NewDiffWriter creates a DiffWriter for the given format.
func NewDiffWriter(w io.Writer, format string) (DiffWriter, error) {
	switch format {
	case "text":
		return &diffTextWriter{w: w}, nil
	case "csv":
		return newDiffCSVWriter(w), nil
	case "json":
		return &diffJSONWriter{w: w}, nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}
