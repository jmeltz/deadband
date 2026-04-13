package matcher

import "strings"

// vendorAliases maps canonical vendor names to known alias strings.
// Each alias is stored lowercase. The canonical name itself is also indexed.
var vendorAliases = map[string][]string{
	// --- Major PLC / DCS vendors ---
	"Rockwell Automation": {"rockwell", "allen-bradley", "a-b", "ra", "rockwell automation"},
	"Siemens":             {"siemens", "siemens ag", "simens"},
	"Schneider Electric":  {"schneider", "schneider electric", "se", "schneider electric software, llc", "schneider electric software"},
	"ABB":                 {"abb", "abb ltd"},
	"Mitsubishi Electric": {"mitsubishi", "mitsubishi electric", "mitsubishi electric corporation", "mitsubishi electric europe b.v.", "mitsubishi electric india"},
	"Emerson / GE":        {"emerson", "emerson electric", "ge", "general electric", "ge digital", "ge vernova", "emerson / ge", "general electric (ge)", "ge healthcare", "emerson process management", "general electric (ge) and emerson"},
	"Honeywell":           {"honeywell"},
	"Yokogawa":            {"yokogawa", "yokogawa electric"},
	"Omron":               {"omron", "omron corporation"},

	// --- Power / energy ---
	"Hitachi Energy": {"hitachi energy"},
	"Eaton":          {"eaton", "eaton cooper power systems", "eaton's cooper", "cooper power systems"},

	// --- Building automation ---
	"Trane":            {"trane", "trane technologies"},
	"Johnson Controls": {"johnson controls", "jci", "johnson controls inc.", "johnson controls inc", "johnson controls, inc."},
	"Carrier":          {"carrier", "carrier lenels2"},

	// --- Field devices / IO ---
	"Phoenix Contact":  {"phoenix contact", "phoenix", "innominate", "phoenix contact software", "innominate security technologies"},
	"Moxa":             {"moxa"},
	"WAGO":             {"wago", "wago kontakttechnik"},
	"Delta Electronics": {"delta", "delta electronics"},
	"Beckhoff":         {"beckhoff", "beckhoff automation"},
	"Festo":            {"festo", "festo didactic", "festo didactic se"},

	// --- Industrial IoT / edge ---
	"Advantech": {"advantech", "advantech/broadwin", "advantech/browin"},

	// --- Drives / motion ---
	"Fuji Electric": {"fuji electric"},
	"B&R":           {"b&r", "b&r industrial automation"},

	// --- SCADA / HMI software (Schneider ecosystem) ---
	"AVEVA":   {"aveva", "aveva software, llc", "aveva software", "osisoft", "osisoft llc", "invensys", "indusoft"},
	"CODESYS": {"codesys", "codesys, gmbh", "codesys gmbh", "3s-smart software solutions gmbh", "3s-smart software solutions", "3s smart software solutions", "3s codesys", "3s"},

	// --- SCADA / HMI software (Mitsubishi ecosystem) ---
	"ICONICS": {"iconics", "iconics, mitsubishi electric"},

	// --- Other ICS-relevant vendors ---
	"AutomationDirect": {"automationdirect", "automation direct"},
	"PEPPERL+FUCHS":    {"pepperl+fuchs"},
}

// vendorPatterns provides substring matching for compound/variant vendor strings
// that can't be handled by exact alias lookup (e.g., "Sensormatic Electronics, LLC,
// Johnson Controls Inc."). Patterns are checked in order; longer patterns first
// to avoid false positives.
var vendorPatterns = []struct {
	pattern   string
	canonical string
}{
	{"schneider electric", "Schneider Electric"},
	{"johnson controls", "Johnson Controls"},
	{"phoenix contact", "Phoenix Contact"},
	{"mitsubishi electric", "Mitsubishi Electric"},
	{"general electric", "Emerson / GE"},
	{"delta electronics", "Delta Electronics"},
	{"hitachi energy", "Hitachi Energy"},
	{"fuji electric", "Fuji Electric"},
	{"automation direct", "AutomationDirect"},
	{"automationdirect", "AutomationDirect"},
	{"sensormatic", "Johnson Controls"},
	{"automated logic", "Johnson Controls"},
	{"lenels2", "Johnson Controls"},
	{"exacq", "Johnson Controls"},
	{"kantech", "Johnson Controls"},
	{"ge healthcare", "Emerson / GE"},
	{"emerson", "Emerson / GE"},
	{"rockwell", "Rockwell Automation"},
	{"advantech", "Advantech"},
	{"beckhoff", "Beckhoff"},
	{"honeywell", "Honeywell"},
	{"yokogawa", "Yokogawa"},
	{"iconics", "Mitsubishi Electric"},
	{"invensys", "AVEVA"},
	{"indusoft", "AVEVA"},
	{"osisoft", "AVEVA"},
	{"codesys", "CODESYS"},
	{"3s-smart", "CODESYS"},
	{"3s smart", "CODESYS"},
	{"siemens", "Siemens"},
	{"phoenix", "Phoenix Contact"},
	{"omron", "Omron"},
	{"moxa", "Moxa"},
	{"wago", "WAGO"},
	{"eaton", "Eaton"},
	{"festo", "Festo"},
	{"trane", "Trane"},
	{"aveva", "AVEVA"},
}

var reverseAliases map[string]string

func init() {
	reverseAliases = make(map[string]string)
	for canonical, aliases := range vendorAliases {
		reverseAliases[strings.ToLower(canonical)] = canonical
		for _, alias := range aliases {
			reverseAliases[strings.ToLower(alias)] = canonical
		}
	}
}

// NormalizeVendor maps a vendor string to its canonical name.
// First tries exact alias lookup, then falls back to substring pattern matching.
func NormalizeVendor(input string) string {
	lower := strings.ToLower(strings.TrimSpace(input))
	if lower == "" {
		return input
	}

	// Exact alias lookup
	if canonical, ok := reverseAliases[lower]; ok {
		return canonical
	}

	// Substring pattern matching for compound vendor strings
	for _, p := range vendorPatterns {
		if strings.Contains(lower, p.pattern) {
			return p.canonical
		}
	}

	return input
}

// VendorMatches reports whether two vendor strings refer to the same vendor.
// Uses case-insensitive comparison after normalization so that vendors not in the
// alias map still match regardless of case (e.g., "Carrier" == "CARRIER").
func VendorMatches(inventoryVendor, advisoryVendor string) bool {
	return strings.EqualFold(NormalizeVendor(inventoryVendor), NormalizeVendor(advisoryVendor))
}
