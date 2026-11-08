package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jmeltz/deadband/pkg/query"
)

// query plan never contacts a device. query run executes only the hashed
// profile. JSON results retain evidence; the local web asset workflow also
// correlates observations and reassessment with persistent asset IDs.
func runQuery(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: deadband query plan --targets targets.json [-purpose enrich|verify] [-o plan.json]; deadband query run --plan plan.json [-dry-run] [-o result.json]")
	}
	f := flag.NewFlagSet("query "+args[0], flag.ContinueOnError)
	output := f.String("o", "-", "JSON output path (- for stdout)")
	switch args[0] {
	case "plan":
		targetPath := f.String("targets", "", "JSON array of explicit asset targets (asset_id, ip, port, requested_fields, expected)")
		purpose := f.String("purpose", "enrich", "enrich or verify")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *targetPath == "" || f.NArg() != 0 {
			return fmt.Errorf("--targets is required")
		}
		in, err := os.Open(*targetPath)
		if err != nil {
			return err
		}
		defer in.Close()
		d := json.NewDecoder(io.LimitReader(in, 1<<20))
		d.DisallowUnknownFields()
		var targets []query.Target
		if err := d.Decode(&targets); err != nil {
			return err
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return fmt.Errorf("targets must contain one JSON array")
		}
		p, err := query.NewPlan(targets, *purpose)
		if err != nil {
			return err
		}
		return writeQueryJSON(*output, p)
	case "run":
		planPath := f.String("plan", "", "Previously generated immutable query plan")
		dryRun := f.Bool("dry-run", false, "Validate and print the plan without network I/O")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *planPath == "" || f.NArg() != 0 {
			return fmt.Errorf("--plan is required")
		}
		in, err := os.Open(*planPath)
		if err != nil {
			return err
		}
		defer in.Close()
		p, err := query.Decode(in)
		if err != nil {
			return err
		}
		if *dryRun {
			return writeQueryJSON(*output, p)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		r, err := query.Execute(ctx, p)
		if err != nil {
			return err
		}
		return writeQueryJSON(*output, r)
	default:
		return fmt.Errorf("unsupported query command %q (use plan or run)", args[0])
	}
}

func writeQueryJSON(path string, v any) error {
	var w io.Writer = os.Stdout
	if path != "-" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	return e.Encode(v)
}
