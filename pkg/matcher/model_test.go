package matcher

import "testing"

func TestModelMatches(t *testing.T) {
	tests := []struct {
		model    string
		products []string
		match    bool
		minConf  Confidence
	}{
		// Exact match after normalization (strip /D suffix)
		{"1756-EN2T/D", []string{"1756-EN2T"}, true, ConfidenceHigh},
		// Exact match
		{"1756-EN2T", []string{"1756-EN2T"}, true, ConfidenceHigh},
		// Substring match
		{"1756-EN2T/D", []string{"ControlLogix 5580", "1756-EN2T"}, true, ConfidenceHigh},
		// Glob match
		{"1756-l83e", []string{"1756-l8*"}, true, ConfidenceLow},
		// No match
		{"CompactLogix", []string{"ControlLogix 5580"}, false, ConfidenceLow},
		// Empty model
		{"", []string{"1756-EN2T"}, false, ConfidenceLow},
		// AC500 substring
		{"AC500", []string{"AC500", "AC500-S"}, true, ConfidenceHigh},
	}
	for _, tt := range tests {
		match, conf := ModelMatches(tt.model, tt.products)
		if match != tt.match {
			t.Errorf("ModelMatches(%q, %v) match = %v, want %v", tt.model, tt.products, match, tt.match)
		}
		if match && confidenceRank(conf) < confidenceRank(tt.minConf) {
			t.Errorf("ModelMatches(%q, %v) confidence = %v, want at least %v", tt.model, tt.products, conf, tt.minConf)
		}
	}
}
