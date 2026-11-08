package server

func validDiscoveryMode(mode string) bool {
	switch mode {
	case "", "auto", "cip", "s7", "modbus", "melsec", "bacnet", "fins", "srtp", "opcua", "ads", "sick", "fox", "ancillary", "haas", "fanuc", "mazak", "http":
		return true
	default:
		return false
	}
}
