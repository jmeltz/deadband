package matcher

import "testing"

func TestNormalizeVendor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Rockwell", "Rockwell Automation"},
		{"Allen-Bradley", "Rockwell Automation"},
		{"A-B", "Rockwell Automation"},
		{"Rockwell Automation", "Rockwell Automation"},
		{"abb", "ABB"},
		{"ABB Ltd", "ABB"},
		{"Siemens AG", "Siemens"},
		{"schneider", "Schneider Electric"},
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

func TestVendorMatches(t *testing.T) {
	tests := []struct {
		inv, adv string
		want     bool
	}{
		{"Rockwell", "Rockwell Automation", true},
		{"A-B", "Rockwell Automation", true},
		{"ABB", "ABB", true},
		{"Siemens", "Rockwell Automation", false},
		{"Unknown", "Unknown", true},
	}
	for _, tt := range tests {
		got := VendorMatches(tt.inv, tt.adv)
		if got != tt.want {
			t.Errorf("VendorMatches(%q, %q) = %v, want %v", tt.inv, tt.adv, got, tt.want)
		}
	}
}
