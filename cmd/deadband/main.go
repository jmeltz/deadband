package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
	"github.com/jmeltz/deadband/pkg/output"
	"github.com/jmeltz/deadband/pkg/updater"
)

func main() {
	var (
		inventoryPath string
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
		cidr          string
		scanTimeout   time.Duration
		httpTimeout   time.Duration
		concurrency   int
	)

	flag.StringVar(&inventoryPath, "inventory", "", "Path to device inventory file (CSV, JSON, or flat)")
	flag.StringVar(&inventoryPath, "i", "", "Path to device inventory file (alias for --inventory)")
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
	flag.StringVar(&cidr, "cidr", "", "Discover Rockwell devices on network (e.g. 10.0.1.0/24)")
	flag.DurationVar(&scanTimeout, "timeout", 2*time.Second, "TCP port scan timeout")
	flag.DurationVar(&httpTimeout, "http-timeout", 5*time.Second, "HTTP scrape timeout")
	flag.IntVar(&concurrency, "concurrency", 50, "Concurrent scan workers")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: deadband [flags]\n\n")
		fmt.Fprintf(os.Stderr, "ICS firmware vulnerability gap detector\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  deadband --inventory <file>   Check devices against advisory database\n")
		fmt.Fprintf(os.Stderr, "  deadband --cidr <range>       Discover devices and check against advisories\n")
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
		devices := runDiscover(cidr, scanTimeout, httpTimeout, concurrency, dryRun)
		if dryRun || len(devices) == 0 {
			return
		}
		runCheckDevices(devices, dbPath, outputPath, outFormat, minConfidence, minCVSS, vendorFilter)
		return
	}

	if inventoryPath == "" {
		fmt.Fprintf(os.Stderr, "Error: --inventory/-i or --cidr is required\n\n")
		flag.Usage()
		os.Exit(2)
	}

	runCheck(inventoryPath, inputFormat, dbPath, outputPath, outFormat, minConfidence, minCVSS, vendorFilter, dryRun)
}

func runDiscover(cidr string, scanTimeout, httpTimeout time.Duration, concurrency int, dryRun bool) []inventory.Device {
	cli.PrintBanner("deadband", cli.Version, "ICS firmware vulnerability gap detector")

	ips, err := discover.ExpandCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if dryRun {
		fmt.Printf("[deadband] Dry run: would scan %d hosts on port %d\n", len(ips), discover.EIPPort)
		return nil
	}

	opts := discover.Opts{
		CIDR:        cidr,
		Timeout:     scanTimeout,
		HTTPTimeout: httpTimeout,
		Concurrency: concurrency,
		Progress: func(msg string) {
			fmt.Printf("[deadband] %s\n", msg)
		},
	}

	devices, err := discover.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("[deadband] Discovered %d Rockwell devices\n", len(devices))

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
