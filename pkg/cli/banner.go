package cli

import "fmt"

const Version = "0.5.0"

func PrintBanner(toolName, version, description string) {
	fmt.Printf("[deadband] %s v%s — %s\n", toolName, version, description)
	fmt.Println("[deadband] READ-ONLY tool — no configuration changes or write operations on OT devices")
}
