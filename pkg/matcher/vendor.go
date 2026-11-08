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
	"Trane":             {"trane", "trane technologies"},
	"Johnson Controls":  {"johnson controls", "jci", "johnson controls inc.", "johnson controls inc", "johnson controls, inc."},
	"Carrier":           {"carrier", "carrier corporation", "carrier global", "carrier lenels2", "lenels2", "automated logic", "automated logic corporation", "automated logic corporation (alc)", "alc"},
	"Tridium":           {"tridium", "tridium inc.", "tridium inc", "niagara", "vykon"},
	"Delta Controls":    {"delta controls", "delta controls inc.", "delta controls inc"},
	"SAUTER":            {"sauter", "sauter controls", "fr. sauter", "fr. sauter ag"},
	"Reliable Controls": {"reliable controls", "reliable controls corporation"},
	"KMC Controls":      {"kmc controls", "kmc controls, inc.", "kmc"},
	"Priva":             {"priva", "priva b.v.", "priva bv"},
	"Kieback & Peter":   {"kieback & peter", "kieback&peter", "kieback & peter gmbh", "kieback & peter gmbh & co. kg"},
	"GEA":               {"gea", "gea group", "gea refrigeration"},
	"Mayekawa":          {"mayekawa", "mycom"},
	"Danfoss":           {"danfoss", "danfoss a/s", "danfoss drives", "danfoss power solutions"},
	"CAREL":             {"carel", "carel industries", "carel industries s.p.a."},
	"Copeland":          {"copeland", "copeland lp", "dixell", "emerson retail solutions", "emerson climate technologies"},
	"Vaisala":           {"vaisala", "vaisala oyj", "veriteq"},
	"Testo":             {"testo", "testo se", "testo se & co. kgaa"},
	"ELPRO":             {"elpro", "elpro-buchs", "elpro-buchs ag"},
	"Sensaphone":        {"sensaphone"},
	"Rees Scientific":   {"rees scientific", "rees"},

	// --- Field devices / IO / Auto-ID / Intralogistics ---
	"Phoenix Contact":    {"phoenix contact", "phoenix", "innominate", "phoenix contact software", "innominate security technologies"},
	"Moxa":               {"moxa", "moxa inc."},
	"WAGO":               {"wago", "wago kontakttechnik", "wago gmbh", "wago gmbh & co. kg"},
	"Weidmüller":         {"weidmüller", "weidmueller", "weidmuller", "weidmüller interface"},
	"Delta Electronics":  {"delta", "delta electronics"},
	"Beckhoff":           {"beckhoff", "beckhoff automation", "beckhoff automation gmbh", "beckhoff automation gmbh & co. kg"},
	"Festo":              {"festo", "festo se", "festo se & co. kg", "festo didactic", "festo didactic se"},
	"KNAPP":              {"knapp", "knapp ag", "knapp logistik", "kisoft", "apostore"},
	"Swisslog":           {"swisslog", "swisslog healthcare", "swisslog logistics"},
	"Dematic":            {"dematic", "kion", "dematic corp"},
	"Vanderlande":        {"vanderlande", "vanderlande industries"},
	"TGW":                {"tgw", "tgw logistics", "tgw logistics group"},
	"SSI Schaefer":       {"ssi schaefer", "ssi schäfer"},
	"AutoStore":          {"autostore", "autostore system"},
	"Interroll":          {"interroll", "interroll group"},
	"Pulseroller":        {"pulseroller", "conveylinx"},
	"SICK":               {"sick", "sick ag"},
	"Cognex":             {"cognex", "cognex corporation"},
	"Leuze":              {"leuze", "leuze electronic", "leuze electronic gmbh"},
	"Keyence":            {"keyence", "keyence corporation"},
	"Banner Engineering": {"banner engineering"},
	"Balluff":            {"balluff", "balluff gmbh"},
	"ifm electronic":     {"ifm", "ifm electronic"},
	"Murrelektronik":     {"murrelektronik"},
	"SMC":                {"smc", "smc corporation"},
	"Pilz":               {"pilz", "pilz gmbh", "pilz gmbh & co. kg"},
	"TURCK":              {"turck", "hans turck", "hans turck gmbh", "hans turck gmbh & co. kg"},
	"Zebra":              {"zebra", "zebra technologies"},
	"SEW-EURODRIVE":      {"sew-eurodrive", "sew eurodrive", "sew-eurodrive gmbh"},
	"Lenze":              {"lenze", "lenze se"},
	"Yaskawa":            {"yaskawa", "yaskawa electric"},
	"LOYTEC":             {"loytec", "loytec electronics"},
	"Belimo":             {"belimo", "belimo automation"},
	"Distech Controls":   {"distech", "distech controls"},
	"Daikin":             {"daikin", "daikin applied", "mcquay"},

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
	"PEPPERL+FUCHS":    {"pepperl+fuchs", "pepperl-fuchs", "pepperl + fuchs"},

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
	{"reliable controls", "Reliable Controls"},
	{"delta controls", "Delta Controls"},
	{"distech controls", "Distech Controls"},
	{"kmc controls", "KMC Controls"},
	{"kieback & peter", "Kieback & Peter"},
	{"kieback&peter", "Kieback & Peter"},
	{"banner engineering", "Banner Engineering"},
	{"pepperl+fuchs", "PEPPERL+FUCHS"},
	{"pepperl-fuchs", "PEPPERL+FUCHS"},
	{"weidmüller", "Weidmüller"},
	{"weidmueller", "Weidmüller"},
	{"weidmuller", "Weidmüller"},
	{"vanderlande", "Vanderlande"},
	{"ssi schaefer", "SSI Schaefer"},
	{"ssi schäfer", "SSI Schaefer"},
	{"autostore", "AutoStore"},
	{"interroll", "Interroll"},
	{"pulseroller", "Pulseroller"},
	{"conveylinx", "Pulseroller"},
	{"murrelektronik", "Murrelektronik"},
	{"ifm electronic", "ifm electronic"},
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
	{"tridium", "Tridium"},
	{"vykon", "Tridium"},
	{"loytec", "LOYTEC"},
	{"belimo", "Belimo"},
	{"sauter", "SAUTER"},
	{"priva", "Priva"},
	{"daikin", "Daikin"},
	{"mcquay", "Daikin"},
	{"mayekawa", "Mayekawa"},
	{"cognex", "Cognex"},
	{"keyence", "Keyence"},
	{"leuze", "Leuze"},
	{"lenze", "Lenze"},
	{"yaskawa", "Yaskawa"},
	{"balluff", "Balluff"},
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
	{"automated logic", "Carrier"},
	{"lenels2", "Carrier"},
	{"carrier", "Carrier"},
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

var brProductMarkers = []string{
	"x20", "apc", "automation pc", "automation runtime",
	"automation studio", "pvi", "aprol", "mapp", "system diagnostics manager", "b&r",
}

// VendorMatchesForDevice extends VendorMatches for acquired/OEM-branded product lines:
//   - B&R Industrial Automation hardware/runtime advisories published under parent "ABB"
//   - OEM-branded Tridium Niagara controllers (Honeywell WEBs, JCI FX, Distech EC-Net) matching "Tridium" advisories
func VendorMatchesForDevice(inventoryVendor, inventoryModel, advisoryVendor string, advisoryProducts []string) bool {
	if VendorMatches(inventoryVendor, advisoryVendor) {
		return true
	}
	normInv := NormalizeVendor(inventoryVendor)
	normAdv := NormalizeVendor(advisoryVendor)

	// B&R <-> ABB cross-matching when advisory products belong to B&R product families
	if (normInv == "B&R" && normAdv == "ABB") || (normInv == "ABB" && normAdv == "B&R") {
		for _, p := range advisoryProducts {
			lp := strings.ToLower(p)
			for _, marker := range brProductMarkers {
				if strings.Contains(lp, marker) {
					return true
				}
			}
		}
	}

	// OEM-rebranded Tridium Niagara stations/JACEs inherit upstream Tridium Niagara advisories
	lowerModel := strings.ToLower(inventoryModel)
	if normAdv == "Tridium" && (strings.Contains(lowerModel, "niagara") || strings.Contains(lowerModel, "jace")) {
		return true
	}

	// Copeland (formerly Emerson Climate Technologies / Dixell) <-> Emerson historical CISA advisories
	if (normInv == "Copeland" && normAdv == "Emerson / GE") || (normInv == "Emerson / GE" && normAdv == "Copeland") {
		copelandMarkers := []string{"xweb", "dixell", "site supervisor", "e2", "e3", "xc pro"}
		for _, p := range advisoryProducts {
			lp := strings.ToLower(p)
			for _, m := range copelandMarkers {
				if strings.Contains(lp, m) {
					return true
				}
			}
		}
	}

	return false
}
