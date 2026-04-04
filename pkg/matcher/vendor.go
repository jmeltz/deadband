package matcher

import "strings"

var vendorAliases = map[string][]string{
	"Rockwell Automation": {"rockwell", "allen-bradley", "a-b", "ra", "rockwell automation"},
	"ABB":                 {"abb", "abb ltd"},
	"Siemens":             {"siemens", "siemens ag"},
	"Schneider Electric":  {"schneider", "schneider electric", "se"},
	"Honeywell":           {"honeywell"},
	"Emerson":             {"emerson", "emerson electric"},
	"Yokogawa":            {"yokogawa", "yokogawa electric"},
	"Omron":               {"omron"},
	"Mitsubishi Electric": {"mitsubishi", "mitsubishi electric"},
	"GE":                  {"ge", "general electric", "ge digital"},
	"Phoenix Contact":     {"phoenix contact", "phoenix"},
	"Moxa":                {"moxa"},
	"WAGO":                {"wago"},
	"Delta Electronics":   {"delta", "delta electronics"},
	"Beckhoff":            {"beckhoff", "beckhoff automation"},
	"Trane":               {"trane", "trane technologies"},
	"Johnson Controls":    {"johnson controls", "jci"},
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

func NormalizeVendor(input string) string {
	if canonical, ok := reverseAliases[strings.ToLower(strings.TrimSpace(input))]; ok {
		return canonical
	}
	return input
}

func VendorMatches(inventoryVendor, advisoryVendor string) bool {
	return NormalizeVendor(inventoryVendor) == NormalizeVendor(advisoryVendor)
}
