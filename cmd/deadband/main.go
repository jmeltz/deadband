package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/diff"
	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
	"github.com/jmeltz/deadband/pkg/output"
	"github.com/jmeltz/deadband/pkg/server"
	"github.com/jmeltz/deadband/pkg/updater"
)

func main() {
	// Handle "serve" subcommand before flag.Parse()
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serveFlags := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := serveFlags.String("addr", ":8484", "Listen address (e.g. :8484)")
		dbPath := serveFlags.String("db", advisory.DefaultDBPath(), "Path to advisory database")
		serveFlags.Parse(os.Args[2:])

		srv, err := server.New(*addr, *dbPath)
		if err != nil {
			log.Fatalf("[deadband] Error: %v", err)
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("[deadband] Error: %v", err)
		}
		return
	}

	var (
		inventoryPath string
		comparePath   string
		inputFormat   string
		dbPath        string
		outputPath    string
		outFormat     string
		minConfidence string
		minCVSS       float64
		vendorFilter  string
		dryRun        bool
		update        bool
		stats         bool
		since         string
		source        string
		cidr        string
		scanMode    string
		legacyHTTP  bool
		scanTimeout time.Duration
		httpTimeout time.Duration
		concurrency int
	)

	flag.StringVar(&inventoryPath, "inventory", "", "Path to device inventory file (CSV, JSON, or flat)")
	flag.StringVar(&inventoryPath, "i", "", "Path to device inventory file (alias for --inventory)")
	flag.StringVar(&comparePath, "compare", "", "Path to second inventory file for diff mode")
	flag.StringVar(&inputFormat, "format", "auto", "Input format: csv, json, flat, auto")
	flag.StringVar(&dbPath, "db", advisory.DefaultDBPath(), "Path to advisory database cache")
	flag.StringVar(&outputPath, "output", "-", "Output file path (- for stdout)")
	flag.StringVar(&outputPath, "o", "-", "Output file path (alias for --output)")
	flag.StringVar(&outFormat, "out-format", "text", "Output format: text, csv, json")
	flag.StringVar(&minConfidence, "min-confidence", "low", "Minimum confidence: low, medium, high")
	flag.Float64Var(&minCVSS, "min-cvss", 0.0, "Minimum CVSS v3 score filter")
	flag.StringVar(&vendorFilter, "vendor", "", "Filter to a specific vendor")
	flag.BoolVar(&dryRun, "dry-run", false, "Parse and report counts only, emit no results")
	flag.BoolVar(&update, "update", false, "Fetch/refresh advisory database from CISA CSAF repo")
	flag.BoolVar(&stats, "stats", false, "Show advisory DB metadata")
	flag.StringVar(&since, "since", "", "Only fetch advisories published after this date (YYYY-MM-DD)")
	flag.StringVar(&source, "source", "", "Local CSAF mirror path (for air-gapped update)")

	// Discovery flags
	flag.StringVar(&cidr, "cidr", "", "Discover devices on network (e.g. 10.0.1.0/24)")
	flag.StringVar(&scanMode, "mode", "auto", "Discovery mode: auto, cip, s7, http")
	flag.BoolVar(&legacyHTTP, "legacy-http", false, "Use HTTP scraping (alias for --mode http)")
	flag.DurationVar(&scanTimeout, "timeout", 2*time.Second, "TCP/UDP scan timeout")
	flag.DurationVar(&httpTimeout, "http-timeout", 5*time.Second, "HTTP scrape timeout")
	flag.IntVar(&concurrency, "concurrency", 50, "Concurrent scan workers")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: deadband [flags]\n\n")
		fmt.Fprintf(os.Stderr, "ICS firmware vulnerability gap detector\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  deadband --inventory <file>   Check devices against advisory database\n")
		fmt.Fprintf(os.Stderr, "  deadband --cidr <range>       Discover devices (Rockwell CIP + Siemens S7) and check\n")
		fmt.Fprintf(os.Stderr, "  deadband --inventory <base> --compare <new>  Diff two inventory snapshots\n")
		fmt.Fprintf(os.Stderr, "  deadband --update             Fetch/refresh advisory database\n")
		fmt.Fprintf(os.Stderr, "  deadband --stats              Show advisory DB metadata\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if update {
		runUpdate(dbPath, since, source)
		return
	}

	if stats {
		runStats(dbPath)
		return
	}

	if cidr != "" {
		if legacyHTTP {
			scanMode = "http"
		}
		devices := runDiscover(cidr, scanMode, scanTimeout, httpTimeout, concurrency, dryRun)
		if dryRun || len(devices) == 0 {
			return
		}
		runCheckDevices(devices, dbPath, outputPath, outFormat, minConfidence, minCVSS, vendorFilter)
		return
	}

	if inventoryPath != "" && comparePath != "" {
		runDiff(inventoryPath, comparePath, inputFormat, dbPath, outputPath, outFormat, minConfidence, minCVSS, vendorFilter)
		return
	}

	if inventoryPath == "" {
		fmt.Fprintf(os.Stderr, "Error: --inventory/-i or --cidr is required\n\n")
		flag.Usage()
		os.Exit(2)
	}

	runCheck(inventoryPath, inputFormat, dbPath, outputPath, outFormat, minConfidence, minCVSS, vendorFilter, dryRun)
}

func runDiscover(cidr string, scanMode string, scanTimeout, httpTimeout time.Duration, concurrency int, dryRun bool) []inventory.Device {
	cli.PrintBanner("deadband", cli.Version, "ICS firmware vulnerability gap detector")

	ips, err := discover.ExpandCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	mode := discover.DiscoveryMode(scanMode)

	if dryRun {
		fmt.Printf("[deadband] Dry run: would scan %d hosts (mode: %s)\n", len(ips), mode)
		return nil
	}

	opts := discover.Opts{
		CIDR:        cidr,
		Timeout:     scanTimeout,
		HTTPTimeout: httpTimeout,
		Concurrency: concurrency,
		Mode:        mode,
		Progress: func(msg string) {
			fmt.Printf("[deadband] %s\n", msg)
		},
	}

	devices, err := discover.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("[deadband] Discovered %d devices\n", len(devices))

	if len(devices) == 0 {
		fmt.Println("[deadband] No devices found.")
	}

	return devices
}

func runCheckDevices(devices []inventory.Device, dbPath, outputPath, outFormat, minConfidence string, minCVSS float64, vendorFilter string) {
	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[deadband] %s\n", db.Stats())
	fmt.Printf("[deadband] Checking %d discovered devices against advisory database...\n", len(devices))

	conf := matcher.ParseConfidence(minConfidence)
	opts := matcher.FilterOpts{
		MinConfidence: conf,
		MinCVSS:       minCVSS,
		Vendor:        vendorFilter,
	}

	results := matcher.MatchAll(devices, db, opts)

	var w *os.File
	if outputPath == "" || outputPath == "-" {
		w = os.Stdout
	} else {
		w, err = os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Error creating output file: %v\n", err)
			os.Exit(2)
		}
		defer w.Close()
	}

	fmt.Println()

	writer, err := output.NewWriter(w, outFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if err := writer.WriteHeader(*db, len(devices)); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	summary := output.Summary{}
	for _, r := range results {
		switch strings.ToUpper(r.Status) {
		case "VULNERABLE":
			summary.Vulnerable++
		case "POTENTIAL":
			summary.Potential++
		case "OK":
			summary.OK++
		}
		if err := writer.WriteResult(r); err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
			os.Exit(2)
		}
	}
	summary.NoMatch = len(devices) - len(results)

	if err := writer.WriteSummary(summary, len(devices)); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if summary.Vulnerable > 0 || summary.Potential > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func runUpdate(dbPath, since, source string) {
	cli.PrintBanner("deadband", cli.Version, "ICS firmware vulnerability gap detector")
	fmt.Println("[deadband] Updating advisory database...")

	opts := updater.UpdateOpts{
		DBPath: dbPath,
		Since:  since,
		Source: source,
		Progress: func(msg string) {
			fmt.Printf("[deadband] %s\n", msg)
		},
	}

	db, err := updater.Update(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("[deadband] %s\n", db.Stats())
}

func runStats(dbPath string) {
	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	cli.PrintBanner("deadband", cli.Version, "ICS firmware vulnerability gap detector")
	fmt.Printf("[deadband] %s\n", db.Stats())

	vendors := make(map[string]int)
	for _, a := range db.Advisories {
		vendors[a.Vendor]++
	}
	fmt.Println("[deadband] Vendors covered:")
	for v, count := range vendors {
		fmt.Printf("  %s: %d advisories\n", v, count)
	}

	addedSince, chronic := db.StalenessStats(db.PreviousUpdated)
	if addedSince >= 0 {
		fmt.Printf("[deadband] %d advisories added since last update\n", addedSince)
	}
	if chronic > 0 {
		fmt.Printf("[deadband] %d chronic advisories (first seen >6 months ago)\n", chronic)
	}
}

func runDiff(basePath, comparePath, inputFormat, dbPath, outputPath, outFormat, minConfidence string, minCVSS float64, vendorFilter string) {
	cli.PrintBanner("deadband", cli.Version, "ICS firmware vulnerability gap detector")

	baseDevices, err := inventory.ParseFile(basePath, inputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error loading base inventory: %v\n", err)
		os.Exit(2)
	}

	compareDevices, err := inventory.ParseFile(comparePath, inputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error loading compare inventory: %v\n", err)
		os.Exit(2)
	}

	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[deadband] %s\n", db.Stats())
	fmt.Printf("[deadband] Comparing %d (base) vs %d (compare) devices...\n", len(baseDevices), len(compareDevices))

	conf := matcher.ParseConfidence(minConfidence)
	opts := matcher.FilterOpts{
		MinConfidence: conf,
		MinCVSS:       minCVSS,
		Vendor:        vendorFilter,
	}

	report := diff.Compute(baseDevices, compareDevices, db, opts)
	report.BaseFile = basePath
	report.CompareFile = comparePath

	var w *os.File
	if outputPath == "" || outputPath == "-" {
		w = os.Stdout
	} else {
		w, err = os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Error creating output file: %v\n", err)
			os.Exit(2)
		}
		defer w.Close()
	}

	fmt.Println()

	writer, err := output.NewDiffWriter(w, outFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if err := writer.WriteDiff(report); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if len(report.NewVulnerabilities) > 0 {
		os.Exit(1)
	}
}

func runCheck(inventoryPath, inputFormat, dbPath, outputPath, outFormat, minConfidence string, minCVSS float64, vendorFilter string, dryRun bool) {
	cli.PrintBanner("deadband", cli.Version, "ICS firmware vulnerability gap detector")

	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[deadband] %s\n", db.Stats())

	devices, err := inventory.ParseFile(inventoryPath, inputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[deadband] Checking %d devices against advisory database...\n", len(devices))

	if dryRun {
		fmt.Printf("[deadband] Dry run: parsed %d devices and %d advisories, no results emitted\n", len(devices), len(db.Advisories))
		os.Exit(0)
	}

	conf := matcher.ParseConfidence(minConfidence)
	opts := matcher.FilterOpts{
		MinConfidence: conf,
		MinCVSS:       minCVSS,
		Vendor:        vendorFilter,
	}

	results := matcher.MatchAll(devices, db, opts)

	var w *os.File
	if outputPath == "" || outputPath == "-" {
		w = os.Stdout
	} else {
		w, err = os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Error creating output file: %v\n", err)
			os.Exit(2)
		}
		defer w.Close()
	}

	fmt.Println()

	writer, err := output.NewWriter(w, outFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if err := writer.WriteHeader(*db, len(devices)); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	summary := output.Summary{}
	for _, r := range results {
		switch strings.ToUpper(r.Status) {
		case "VULNERABLE":
			summary.Vulnerable++
		case "POTENTIAL":
			summary.Potential++
		case "OK":
			summary.OK++
		}
		if err := writer.WriteResult(r); err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
			os.Exit(2)
		}
	}
	summary.NoMatch = len(devices) - len(results)

	if err := writer.WriteSummary(summary, len(devices)); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if summary.Vulnerable > 0 || summary.Potential > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}
