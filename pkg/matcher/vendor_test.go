package matcher

import "testing"

func TestNormalizeVendor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Exact alias matches
		{"Rockwell", "Rockwell Automation"},
		{"Allen-Bradley", "Rockwell Automation"},
		{"A-B", "Rockwell Automation"},
		{"Rockwell Automation", "Rockwell Automation"},
		{"abb", "ABB"},
		{"ABB Ltd", "ABB"},
		{"Siemens AG", "Siemens"},
		{"schneider", "Schneider Electric"},
		{"GE", "Emerson / GE"},
		{"Emerson", "Emerson / GE"},
		{"GE Vernova", "Emerson / GE"},
		{"omron", "Omron"},
		{"Omron Corporation", "Omron"},
		{"Hitachi Energy", "Hitachi Energy"},
		{"Eaton", "Eaton"},
		{"Advantech", "Advantech"},
		{"Fuji Electric", "Fuji Electric"},
		{"AVEVA", "AVEVA"},
		{"OSIsoft LLC", "AVEVA"},
		{"Invensys", "AVEVA"},
		{"CODESYS", "CODESYS"},
		{"3S-Smart Software Solutions GmbH", "CODESYS"},
		{"ICONICS", "ICONICS"},
		{"Festo", "Festo"},
		{"B&R", "B&R"},

		// Schneider Electric variants
		{"Schneider Electric Software, LLC", "Schneider Electric"},

		// Emerson / GE variants
		{"General Electric (GE)", "Emerson / GE"},
		{"GE Healthcare", "Emerson / GE"},
		{"Emerson Process Management", "Emerson / GE"},

		// Johnson Controls variants (exact alias)
		{"Johnson Controls Inc.", "Johnson Controls"},
		{"Johnson Controls Inc", "Johnson Controls"},
		{"Johnson Controls, Inc.", "Johnson Controls"},

		// Mitsubishi Electric variants
		{"Mitsubishi Electric Corporation", "Mitsubishi Electric"},

		// Carrier (separate from JCI)
		{"Carrier", "Carrier"},
		{"Carrier LenelS2", "Carrier"},

		// Passthrough for unknown
		{"Unknown Corp", "Unknown Corp"},
		{"", ""},
	}
	for _, tt := range tests {
		got := NormalizeVendor(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeVendor(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeVendorSubstringMatching(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Compound Johnson Controls strings from CSAF
		{"Sensormatic Electronics, LLC, Johnson Controls Inc.", "Johnson Controls"},
		{"Exacq Technologies, Johnson Controls Inc.", "Johnson Controls"},
		{"Kantech, Johnson Controls Inc.", "Johnson Controls"},
		{"CKS, a subsidiary of Johnson Controls Inc.", "Johnson Controls"},
		{"Sensormatic Electronics, LLC, a subsidiary of Johnson Controls Inc.", "Johnson Controls"},
		{"Sensormatic Electronics, a subsidiary of Johnson Controls, Inc.", "Johnson Controls"},
		{"Automated Logic Corporation (ALC)", "Johnson Controls"},

		// Compound Phoenix Contact strings
		{"PHOENIX CONTACT, Innominate Security Technologies", "Phoenix Contact"},

		// Compound Mitsubishi strings
		{"Mitsubishi Electric Iconics Digital Solutions", "Mitsubishi Electric"},
		{"Mitsubishi Electric Iconics Digital Solutions, Mitsubishi Electric", "Mitsubishi Electric"},

		// Compound Schneider / ecosystem
		{"AVEVA Software, LLC and Schneider Electric Software, LLC", "Schneider Electric"},

		// Compound GE strings
		{"Silex Technology and GE Healthcare", "Emerson / GE"},

		// Sensormatic alone (no "Johnson Controls" in string)
		{"Sensormatic Electronics", "Johnson Controls"},
		{"Sensormatic Electronics, LLC", "Johnson Controls"},

		// ICONICS variants (substring → Mitsubishi Electric)
		{"ICONICS, Mitsubishi Electric", "ICONICS"},  // exact alias hit first
		{"Mitsubishi Electric Iconics Digital Solutions and Mitsubishi Electric", "Mitsubishi Electric"},
	}
	for _, tt := range tests {
		got := NormalizeVendor(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeVendor(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestVendorMatches(t *testing.T) {
	tests := []struct {
		inv, adv string
		want     bool
	}{
		// Basic matches
		{"Rockwell", "Rockwell Automation", true},
		{"A-B", "Rockwell Automation", true},
		{"ABB", "ABB", true},
		{"Siemens", "Rockwell Automation", false},

		// Case-insensitive passthrough (not in alias map)
		{"Unknown", "Unknown", true},
		{"Unknown", "UNKNOWN", true},
		{"unknown", "Unknown", true},

		// Emerson / GE unification
		{"Emerson", "GE", true},
		{"GE Digital", "Emerson Electric", true},

		// Johnson Controls variants match each other
		{"Johnson Controls", "Johnson Controls Inc.", true},
		{"JCI", "Johnson Controls, Inc.", true},

		// Substring-matched compounds match canonical
		{"Sensormatic Electronics, LLC, Johnson Controls Inc.", "Johnson Controls", true},
		{"Sensormatic Electronics, LLC, Johnson Controls Inc.", "JCI", true},

		// Different vendors don't match
		{"Hitachi Energy", "ABB", false},
		{"AVEVA", "Schneider Electric", false},
		{"ICONICS", "Mitsubishi Electric", false},
	}
	for _, tt := range tests {
		got := VendorMatches(tt.inv, tt.adv)
		if got != tt.want {
			t.Errorf("VendorMatches(%q, %q) = %v, want %v", tt.inv, tt.adv, got, tt.want)
		}
	}
}
