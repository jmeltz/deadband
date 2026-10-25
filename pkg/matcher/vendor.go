package matcher

import "strings"

// vendorAliases maps canonical vendor names to known alias strings.
// Each alias is stored lowercase. The canonical name itself is also indexed.
var vendorAliases = map[string][]string{
	// --- Major PLC / DCS vendors ---
	"Rockwell Automation": {"rockwell", "allen-bradley", "a-b", "ra", "rockwell automation"},
	"Siemens":             {"siemens", "siemens ag", "simens"},
	"Schneider Electric":  {"schneider", "schneider electric", "se", "schneider electric software, llc", "schneider electric software", "apc", "apc by schneider electric", "american power conversion"},
	"ABB":                 {"abb", "abb ltd"},
	"Mitsubishi Electric": {"mitsubishi", "mitsubishi electric", "mitsubishi electric corporation", "mitsubishi electric europe b.v.", "mitsubishi electric india", "m700", "m800", "m80", "e80"},
	"Emerson / GE":        {"emerson", "emerson electric", "ge", "general electric", "ge digital", "ge vernova", "emerson / ge", "general electric (ge)", "ge healthcare", "emerson process management", "general electric (ge) and emerson"},
	"Honeywell":           {"honeywell"},
	"Yokogawa":            {"yokogawa", "yokogawa electric"},
	"Omron":               {"omron", "omron corporation"},

	// --- Power / energy / critical server-room thermal & UPS ---
	"Hitachi Energy": {"hitachi energy"},
	"Eaton":          {"eaton", "eaton cooper power systems", "eaton's cooper", "cooper power systems"},
	"Vertiv":         {"vertiv", "vertiv co", "liebert", "emerson network power", "avocent"},
	"Rittal":         {"rittal", "rittal gmbh", "rittal gmbh & co. kg"},

	// --- Building automation & cold-chain refrigeration / EMS ---
	"Trane":            {"trane", "trane technologies"},
	"Johnson Controls": {"johnson controls", "jci", "johnson controls inc.", "johnson controls inc", "johnson controls, inc."},
	"Carrier":          {"carrier", "carrier lenels2"},
	"Danfoss":          {"danfoss", "danfoss a/s", "danfoss power solutions"},
	"CAREL":            {"carel", "carel industries", "carel industries s.p.a."},
	"Copeland":         {"copeland", "copeland lp", "dixell", "emerson retail solutions", "emerson climate technologies"},
	"Vaisala":          {"vaisala", "vaisala oyj", "veriteq"},
	"Testo":            {"testo", "testo se", "testo se & co. kgaa"},
	"ELPRO":            {"elpro", "elpro-buchs", "elpro-buchs ag"},
	"Sensaphone":       {"sensaphone"},
	"Rees Scientific":  {"rees scientific", "rees"},

	// --- Field devices / IO / Auto-ID / Intralogistics ---
	"Phoenix Contact":   {"phoenix contact", "phoenix", "innominate", "phoenix contact software", "innominate security technologies"},
	"Moxa":              {"moxa"},
	"WAGO":              {"wago", "wago kontakttechnik"},
	"Delta Electronics": {"delta", "delta electronics"},
	"Beckhoff":          {"beckhoff", "beckhoff automation", "beckhoff automation gmbh"},
	"Festo":             {"festo", "festo didactic", "festo didactic se"},
	"KNAPP":             {"knapp", "knapp ag", "knapp logistik", "kisoft", "apostore"},
	"Swisslog":          {"swisslog", "swisslog healthcare", "swisslog logistics"},
	"Dematic":           {"dematic", "kion", "dematic corp"},
	"SICK":              {"sick", "sick ag"},
	"Cognex":            {"cognex", "cognex corporation"},
	"Pilz":              {"pilz", "pilz gmbh", "pilz gmbh & co. kg"},
	"TURCK":             {"turck", "hans turck", "hans turck gmbh"},
	"Zebra":             {"zebra", "zebra technologies"},
	"SEW-EURODRIVE":     {"sew-eurodrive", "sew eurodrive", "sew-eurodrive gmbh"},
	"LOYTEC":            {"loytec", "loytec electronics"},
	"Belimo":            {"belimo"},
	"Distech Controls":  {"distech", "distech controls"},
	"Daikin":            {"daikin", "daikin applied"},

	// --- Industrial IoT / edge ---
	"Advantech": {"advantech", "advantech/broadwin", "advantech/browin"},

	// --- Drives / motion ---
	"Fuji Electric": {"fuji electric"},
	"B&R":           {"b&r", "b&r industrial automation", "abb b&r", "bernecker + rainer", "bernecker & rainer"},

	// --- SCADA / HMI software (Schneider ecosystem) ---
	"AVEVA":   {"aveva", "aveva software, llc", "aveva software", "osisoft", "osisoft llc", "invensys", "indusoft"},
	"CODESYS": {"codesys", "codesys, gmbh", "codesys gmbh", "3s-smart software solutions gmbh", "3s-smart software solutions", "3s smart software solutions", "3s codesys", "3s"},

	// --- SCADA / HMI software (Mitsubishi ecosystem) ---
	"ICONICS": {"iconics", "iconics, mitsubishi electric"},

	// --- Other ICS-relevant vendors ---
	"AutomationDirect": {"automationdirect", "automation direct"},
	"PEPPERL+FUCHS":    {"pepperl+fuchs"},

	// --- CNC controllers / machine tools (job shop market) ---
	"Fanuc":           {"fanuc", "fanuc america", "ge fanuc", "fanuc robotics", "fanuc corporation"},
	"Haas Automation": {"haas", "haas cnc", "haas automation", "haas automation, inc.", "haas automation inc"},
	"Heidenhain":      {"heidenhain", "dr. johannes heidenhain", "johannes heidenhain"},
	"Okuma":           {"okuma", "okuma america", "okuma corporation"},
	"Yamazaki Mazak":  {"mazak", "mazatrol", "yamazaki mazak"},
}

// vendorPatterns provides substring matching for compound/variant vendor strings
// that can't be handled by exact alias lookup (e.g., "Sensormatic Electronics, LLC,
// Johnson Controls Inc."). Patterns are checked in order; longer patterns first
// to avoid false positives.
var vendorPatterns = []struct {
	pattern   string
	canonical string
}{
	{"american power conversion", "Schneider Electric"},
	{"apc by schneider", "Schneider Electric"},
	{"emerson network power", "Vertiv"},
	{"emerson retail solutions", "Copeland"},
	{"emerson climate", "Copeland"},
	{"abb b&r", "B&R"},
	{"b&r industrial", "B&R"},
	{"bernecker", "B&R"},
	{"sew-eurodrive", "SEW-EURODRIVE"},
	{"sew eurodrive", "SEW-EURODRIVE"},
	{"rees scientific", "Rees Scientific"},
	{"swisslog", "Swisslog"},
	{"dematic", "Dematic"},
	{"knapp", "KNAPP"},
	{"kisoft", "KNAPP"},
	{"danfoss", "Danfoss"},
	{"copeland", "Copeland"},
	{"dixell", "Copeland"},
	{"carel", "CAREL"},
	{"vaisala", "Vaisala"},
	{"testo", "Testo"},
	{"elpro", "ELPRO"},
	{"sensaphone", "Sensaphone"},
	{"vertiv", "Vertiv"},
	{"liebert", "Vertiv"},
	{"rittal", "Rittal"},
	{"cognex", "Cognex"},
	{"zebra", "Zebra"},
	{"sick ag", "SICK"},
	{"turck", "TURCK"},
	{"pilz", "Pilz"},
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

	// --- CNC controllers / machine tools (job shop market) ---
	// Longest first to avoid false positives ("ge fanuc" must beat "fanuc"
	// only because "fanuc" canonicalizes the same way; both safe here).
	{"yamazaki mazak", "Yamazaki Mazak"},
	{"haas automation", "Haas Automation"},
	{"johannes heidenhain", "Heidenhain"},
	{"ge fanuc", "Fanuc"},
	{"fanuc", "Fanuc"},
	{"haas", "Haas Automation"},
	{"mazak", "Yamazaki Mazak"},
	{"okuma", "Okuma"},
	{"heidenhain", "Heidenhain"},
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
