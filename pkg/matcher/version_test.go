package matcher

import "testing"

func TestVersionAffected(t *testing.T) {
	tests := []struct {
		firmware string
		versions []string
		affected bool
		conf     Confidence
	}{
		// Tier 1: operator-prefixed
		{"11.002", []string{"<=12.0"}, true, ConfidenceHigh},
		{"13.000", []string{"<=12.0"}, false, ConfidenceHigh},
		{"11.002", []string{"<v12.0"}, true, ConfidenceHigh},
		{"32.014", []string{"<V4.0.400"}, false, ConfidenceHigh},
		{"3.4.1", []string{"<v3.5.0"}, true, ConfidenceHigh},
		{"3.5.0", []string{"<v3.5.0"}, false, ConfidenceHigh},
		{"28.011", []string{"<V34.014"}, true, ConfidenceHigh},
		{"34.014", []string{"<V34.014"}, false, ConfidenceHigh},

		// vers:all/* — all versions
		{"11.002", []string{"vers:all/*"}, true, ConfidenceHigh},
		{"99.99", []string{"vers:all/*"}, true, ConfidenceHigh},

		// Tier 2: prose
		{"28.011", []string{"v33 and prior"}, true, ConfidenceMedium},
		{"34.000", []string{"v33 and prior"}, false, ConfidenceMedium},
		{"2.9.4", []string{"all versions before 3.0"}, true, ConfidenceMedium},

		// Empty firmware — flag conservatively
		{"", []string{"<=12.0"}, true, ConfidenceLow},

		// Multi-branch affected_versions (must NOT exit early on first non-matching branch)
		{"4.9.0", []string{"<3.0.0", "<4.10.1"}, true, ConfidenceHigh},
		{"4.12.0", []string{"<3.0.0", "<4.10.1"}, false, ConfidenceHigh},

		// CSAF vers:<scheme>/ prefixes (bounded vs wildcard)
		{"4.13.1", []string{"vers:all/<4.12.2.16"}, false, ConfidenceHigh},
		{"4.11.0", []string{"vers:all/<4.12.2.16"}, true, ConfidenceHigh},
		{"3.1.4024.10", []string{"vers:intdot/<3.1.4024.53"}, true, ConfidenceHigh},
		{"3.1.4024.65", []string{"vers:intdot/<3.1.4024.53"}, false, ConfidenceHigh},

		// Pipe-bounded intervals and discrete version lists
		{"6.2.1", []string{">=5.x|<=6.5.1"}, true, ConfidenceHigh},
		{"4.9.0", []string{">=5.x|<=6.5.1"}, false, ConfidenceHigh},
		{"6.6.0", []string{">=5.x|<=6.5.1"}, false, ConfidenceHigh},
		{"2.11", []string{"2.10|2.11|2.12"}, true, ConfidenceHigh},
		{"2.13", []string{"2.10|2.11|2.12"}, false, ConfidenceHigh},
		{"2.2.0", []string{"vers:intdot/>=1.0|<1.5|>=2.0|<2.3"}, true, ConfidenceHigh},
		{"1.8.0", []string{"vers:intdot/>=1.0|<1.5|>=2.0|<2.3"}, false, ConfidenceHigh},

		// Beckhoff Build strings & letter-prefixed revisions
		{"3.1.4020", []string{"<=3.1 Build 4022.4"}, true, ConfidenceHigh},
		{"3.1.4024", []string{"<=3.1 Build 4022.4"}, false, ConfidenceHigh},
		{"4.1", []string{"<R4.2"}, true, ConfidenceHigh},
		{"4.3", []string{"<R4.2"}, false, ConfidenceHigh},
		{"4.90", []string{"<= C4.93"}, true, ConfidenceHigh},
		{"4.95", []string{"<= C4.93"}, false, ConfidenceHigh},
		{"12.0", []string{"< FW14"}, true, ConfidenceHigh},
		{"14.1", []string{"< FW14"}, false, ConfidenceHigh},
	}
	for _, tt := range tests {
		affected, conf := VersionAffected(tt.firmware, tt.versions)
		if affected != tt.affected {
			t.Errorf("VersionAffected(%q, %v) affected = %v, want %v", tt.firmware, tt.versions, affected, tt.affected)
		}
		if conf != tt.conf {
			t.Errorf("VersionAffected(%q, %v) confidence = %v, want %v", tt.firmware, tt.versions, conf, tt.conf)
		}
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"11.002", []int{11, 2}},
		{"4.0.400", []int{4, 0, 400}},
		{"v32.014", []int{32, 14}},
		{"V3.5.0", []int{3, 5, 0}},
	}
	for _, tt := range tests {
		got, err := parseVersion(tt.input)
		if err != nil {
			t.Errorf("parseVersion(%q) error: %v", tt.input, err)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseVersion(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseVersion(%q) = %v, want %v", tt.input, got, tt.want)
				break
			}
		}
	}
}
