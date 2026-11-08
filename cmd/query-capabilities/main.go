// query-capabilities generates or verifies the shared query capability artifact.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jmeltz/deadband/pkg/capability"
)

func main() {
	out := flag.String("out", "docs/generated/query-capabilities.json", "Generated artifact path (- for stdout)")
	check := flag.Bool("check", false, "Fail if the committed artifact differs from the Go registry")
	flag.Parse()
	var b bytes.Buffer
	if err := capability.Write(&b); err != nil {
		fail(err)
	}
	if *check {
		existing, err := os.ReadFile(*out)
		if err != nil {
			fail(err)
		}
		if !bytes.Equal(existing, b.Bytes()) {
			fail(fmt.Errorf("capability artifact differs; run go run ./cmd/query-capabilities"))
		}
		return
	}
	if *out == "-" {
		_, err := os.Stdout.Write(b.Bytes())
		if err != nil {
			fail(err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, b.Bytes(), 0644); err != nil {
		fail(err)
	}
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
