package output

import (
	"fmt"
	"io"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/compliance"
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

// WriterOpts configures optional features for output writers.
type WriterOpts struct {
	Compliance []compliance.ControlMapping
}

func NewWriter(w io.Writer, format string) (ResultWriter, error) {
	return NewWriterWithOpts(w, format, WriterOpts{})
}

func NewWriterWithOpts(w io.Writer, format string, opts WriterOpts) (ResultWriter, error) {
	switch format {
	case "text":
		return &textWriter{w: w}, nil
	case "csv":
		return newCSVWriter(w), nil
	case "json":
		jw := newJSONWriter(w)
		jw.compliance = opts.Compliance
		return jw, nil
	case "html":
		hw := newHTMLWriter(w)
		hw.compliance = opts.Compliance
		return hw, nil
	case "sarif":
		return newSARIFWriter(w), nil
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
