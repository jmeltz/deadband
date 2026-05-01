package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/asset"
	"github.com/jmeltz/deadband/pkg/baseline"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/compliance"
	"github.com/jmeltz/deadband/pkg/diff"
	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/enrichment"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/matcher"
	"github.com/jmeltz/deadband/pkg/output"
	"github.com/jmeltz/deadband/pkg/pcap"
	"github.com/jmeltz/deadband/pkg/server"
	"github.com/jmeltz/deadband/pkg/updater"
)

func main() {
	// Handle subcommands before flag.Parse()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
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
		case "pcap":
			runPCAP(os.Args[2:])
			return
		}
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
		cidr            string
		scanMode        string
		legacyHTTP      bool
		scanTimeout     time.Duration
		httpTimeout     time.Duration
		concurrency     int
		prioritize       bool
		skipEnrichment   bool
		complianceFlag   string
		saveBaseline     bool
		compareBaseline  bool
		baselinePath     string
		autoSaveAssets   bool
		assetStorePath   string
		serve           bool
		serveAddr       string
		siteName        string
	)

	flag.StringVar(&inventoryPath, "inventory", "", "Path to device inventory file (CSV, JSON, or flat)")
	flag.StringVar(&inventoryPath, "i", "", "Path to device inventory file (alias for --inventory)")
	flag.StringVar(&comparePath, "compare", "", "Path to second inventory file for diff mode")
	flag.StringVar(&inputFormat, "format", "auto", "Input format: csv, json, flat, auto")
	flag.StringVar(&dbPath, "db", advisory.DefaultDBPath(), "Path to advisory database cache")
	flag.StringVar(&outputPath, "output", "-", "Output file path (- for stdout)")
	flag.StringVar(&outputPath, "o", "-", "Output file path (alias for --output)")
	flag.StringVar(&outFormat, "out-format", "text", "Output format: text, csv, json, html, sarif")
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
	flag.StringVar(&scanMode, "mode", "auto", "Discovery mode: auto, cip, s7, modbus, melsec, bacnet, fins, srtp, opcua, http")
	flag.BoolVar(&legacyHTTP, "legacy-http", false, "Use HTTP scraping (alias for --mode http)")
	flag.DurationVar(&scanTimeout, "timeout", 2*time.Second, "TCP/UDP scan timeout")
	flag.DurationVar(&httpTimeout, "http-timeout", 5*time.Second, "HTTP scrape timeout")
	flag.IntVar(&concurrency, "concurrency", 50, "Concurrent scan workers")

	// Enrichment flags
	flag.BoolVar(&prioritize, "prioritize", false, "Sort results by risk score (KEV > EPSS > CVSS)")
	flag.BoolVar(&skipEnrichment, "skip-enrichment", false, "Skip KEV/EPSS fetch during update")

	// Compliance flags
	flag.StringVar(&complianceFlag, "compliance", "", "Include compliance mappings: iec62443, nist-csf, nerc-cip, all (comma-separated)")

	// Baseline flags
	flag.BoolVar(&saveBaseline, "save-baseline", false, "Save current device list as baseline after scan")
	flag.BoolVar(&compareBaseline, "compare-baseline", false, "Compare current scan against saved baseline")
	flag.StringVar(&baselinePath, "baseline", baseline.DefaultPath(), "Custom baseline file path")

	// Asset inventory flags
	flag.BoolVar(&autoSaveAssets, "auto-save-assets", false, "Auto-import discovered devices into asset inventory")
	flag.StringVar(&assetStorePath, "asset-store", asset.DefaultPath(), "Asset inventory file path")

	// Server flags
	flag.BoolVar(&serve, "serve", false, "Start the web UI and API server")
	flag.StringVar(&serveAddr, "addr", ":8484", "Listen address for --serve (e.g. :8484)")

	// Report flags
	flag.StringVar(&siteName, "site-name", "", "Site name for HTML report cover (e.g. \"Acme Job Shop\")")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: deadband [flags]\n\n")
		fmt.Fprintf(os.Stderr, "OT asset inventory & vulnerability scanner\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  deadband --inventory <file>   Check devices against advisory database\n")
		fmt.Fprintf(os.Stderr, "  deadband --cidr <range>       Discover devices (CIP + S7 + Modbus) and check\n")
		fmt.Fprintf(os.Stderr, "  deadband --inventory <base> --compare <new>  Diff two inventory snapshots\n")
		fmt.Fprintf(os.Stderr, "  deadband pcap <file>          Extract devices from pcap capture (passive)\n")
		fmt.Fprintf(os.Stderr, "  deadband --serve              Start the web UI and API server\n")
		fmt.Fprintf(os.Stderr, "  deadband --update             Fetch/refresh advisory database\n")
		fmt.Fprintf(os.Stderr, "  deadband --stats              Show advisory DB metadata\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if serve {
		srv, err := server.New(serveAddr, dbPath)
		if err != nil {
			log.Fatalf("[deadband] Error: %v", err)
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("[deadband] Error: %v", err)
		}
		return
	}

	if update {
		runUpdate(dbPath, since, source, skipEnrichment)
		return
	}

	if stats {
		runStats(dbPath)
		return
	}

	// Load enrichment data for check commands
	enrichDir := enrichmentDir(dbPath)
	edb := enrichment.LoadFromDir(enrichDir)

	if cidr != "" {
		if legacyHTTP {
			scanMode = "http"
		}
		devices := runDiscover(cidr, scanMode, scanTimeout, httpTimeout, concurrency, dryRun)
		if dryRun || len(devices) == 0 {
			return
		}
		if autoSaveAssets {
			saveDiscoveredAssets(devices, assetStorePath)
		}
		runCheckDevices(devices, dbPath, outputPath, outFormat, minConfidence, minCVSS, vendorFilter, edb, prioritize, complianceFlag, saveBaseline, compareBaseline, baselinePath, autoSaveAssets, assetStorePath, siteName)
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

	runCheck(inventoryPath, inputFormat, dbPath, outputPath, outFormat, minConfidence, minCVSS, vendorFilter, dryRun, edb, prioritize, complianceFlag, saveBaseline, compareBaseline, baselinePath, autoSaveAssets, assetStorePath, siteName)
}

func runDiscover(cidr string, scanMode string, scanTimeout, httpTimeout time.Duration, concurrency int, dryRun bool) []inventory.Device {
	cli.PrintBanner("deadband", cli.Version, "OT asset inventory & vulnerability scanner")

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

func runPCAP(args []string) {
	pcapFlags := flag.NewFlagSet("pcap", flag.ExitOnError)
	dbPath := pcapFlags.String("db", advisory.DefaultDBPath(), "Path to advisory database")
	outputPath := pcapFlags.String("o", "-", "Output file path")
	outFormat := pcapFlags.String("out-format", "text", "Output format: text, csv, json, html, sarif")
	minConfidence := pcapFlags.String("min-confidence", "low", "Minimum confidence: low, medium, high")
	minCVSS := pcapFlags.Float64("min-cvss", 0.0, "Minimum CVSS v3 score filter")
	vendorFilter := pcapFlags.String("vendor", "", "Filter to a specific vendor")
	prioritize := pcapFlags.Bool("prioritize", false, "Sort results by risk score")
	skipEnrichment := pcapFlags.Bool("skip-enrichment", false, "Skip enrichment data")
	complianceFlag := pcapFlags.String("compliance", "", "Include compliance mappings")
	siteName := pcapFlags.String("site-name", "", "Site name for HTML report cover")
	pcapFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: deadband pcap <file.pcap> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Passive device extraction from pcap capture file.\n\n")
		pcapFlags.PrintDefaults()
	}
	pcapFlags.Parse(args)

	if pcapFlags.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Error: pcap file path required\n\n")
		pcapFlags.Usage()
		os.Exit(2)
	}
	pcapPath := pcapFlags.Arg(0)

	cli.PrintBanner("deadband", cli.Version, "OT asset inventory & vulnerability scanner")
	fmt.Printf("[deadband] Analyzing pcap: %s\n", pcapPath)

	result, err := pcap.Analyze(pcapPath, func(msg string) {
		fmt.Printf("[deadband] %s\n", msg)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}

	if len(result.Devices) == 0 {
		fmt.Println("[deadband] No ICS devices found in pcap.")
		return
	}

	// Load enrichment data
	var edb *enrichment.DB
	if !*skipEnrichment {
		edb = enrichment.LoadFromDir(enrichmentDir(*dbPath))
	}

	// Run vulnerability check on extracted devices
	runCheckDevices(result.Devices, *dbPath, *outputPath, *outFormat, *minConfidence, *minCVSS, *vendorFilter, edb, *prioritize, *complianceFlag, false, false, "", false, "", *siteName)
}

func runCheckDevices(devices []inventory.Device, dbPath, outputPath, outFormat, minConfidence string, minCVSS float64, vendorFilter string, edb *enrichment.DB, prioritize bool, complianceFlag string, saveBase, compareBase bool, basePath string, saveAssets bool, assetStorePath, siteName string) {
	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[deadband] %s\n", db.Stats())
	if edb.Loaded() {
		stats := edb.GetStats()
		fmt.Printf("[deadband] Enrichment: %d KEV entries, %d EPSS scores\n", stats.KEVCount, stats.EPSSCount)
	}
	fmt.Printf("[deadband] Checking %d discovered devices against advisory database...\n", len(devices))

	conf := matcher.ParseConfidence(minConfidence)
	opts := matcher.FilterOpts{
		MinConfidence: conf,
		MinCVSS:       minCVSS,
		Vendor:        vendorFilter,
	}

	results := matcher.MatchAll(devices, db, opts)
	enrichResults(results, edb)

	if prioritize {
		sortByRisk(results)
	}

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

	writerOpts := output.WriterOpts{SiteName: siteName}
	if complianceFlag != "" {
		frameworks := strings.Split(complianceFlag, ",")
		writerOpts.Compliance = compliance.ForFrameworks(frameworks)
	}

	writer, err := output.NewWriterWithOpts(w, outFormat, writerOpts)
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

	if saveAssets {
		writeVulnStateToAssets(results, assetStorePath)
	}

	runBaseline(devices, db, opts, basePath, saveBase, compareBase)

	if summary.Vulnerable > 0 || summary.Potential > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func runUpdate(dbPath, since, source string, skipEnrichment bool) {
	cli.PrintBanner("deadband", cli.Version, "OT asset inventory & vulnerability scanner")
	progress := func(msg string) {
		fmt.Printf("[deadband] %s\n", msg)
	}

	fmt.Println("[deadband] Updating advisory database...")
	opts := updater.UpdateOpts{
		DBPath:   dbPath,
		Since:    since,
		Source:   source,
		Progress: progress,
	}

	db, err := updater.Update(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[deadband] %s\n", db.Stats())

	// Fetch KEV + EPSS enrichment data
	if !skipEnrichment {
		enrichDir := enrichmentDir(dbPath)
		if source != "" {
			// Air-gapped: load from source directory
			edb := enrichment.LoadFromDir(source)
			if edb.Loaded() {
				if err := edb.SaveToDir(enrichDir); err != nil {
					progress(fmt.Sprintf("Warning: failed to save enrichment data: %v", err))
				} else {
					stats := edb.GetStats()
					progress(fmt.Sprintf("Enrichment (local): %d KEV entries, %d EPSS scores", stats.KEVCount, stats.EPSSCount))
				}
			}
		} else {
			edb, _ := enrichment.FetchAll(progress)
			if edb.Loaded() {
				if err := edb.SaveToDir(enrichDir); err != nil {
					progress(fmt.Sprintf("Warning: failed to save enrichment data: %v", err))
				}
			}
		}
	}
}

func runStats(dbPath string) {
	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	cli.PrintBanner("deadband", cli.Version, "OT asset inventory & vulnerability scanner")
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
	cli.PrintBanner("deadband", cli.Version, "OT asset inventory & vulnerability scanner")

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

func runCheck(inventoryPath, inputFormat, dbPath, outputPath, outFormat, minConfidence string, minCVSS float64, vendorFilter string, dryRun bool, edb *enrichment.DB, prioritize bool, complianceFlag string, saveBase, compareBase bool, basePath string, saveAssets bool, assetStorePath, siteName string) {
	cli.PrintBanner("deadband", cli.Version, "OT asset inventory & vulnerability scanner")

	db, err := advisory.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Error: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[deadband] %s\n", db.Stats())
	if edb.Loaded() {
		stats := edb.GetStats()
		fmt.Printf("[deadband] Enrichment: %d KEV entries, %d EPSS scores\n", stats.KEVCount, stats.EPSSCount)
	}

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
	enrichResults(results, edb)

	if prioritize {
		sortByRisk(results)
	}

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

	writerOpts := output.WriterOpts{SiteName: siteName}
	if complianceFlag != "" {
		frameworks := strings.Split(complianceFlag, ",")
		writerOpts.Compliance = compliance.ForFrameworks(frameworks)
	}

	writer, err := output.NewWriterWithOpts(w, outFormat, writerOpts)
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

	if saveAssets {
		writeVulnStateToAssets(results, assetStorePath)
	}

	runBaseline(devices, db, opts, basePath, saveBase, compareBase)

	if summary.Vulnerable > 0 || summary.Potential > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// runBaseline handles --compare-baseline and --save-baseline after a check completes.
func runBaseline(devices []inventory.Device, db *advisory.Database, opts matcher.FilterOpts, basePath string, save, compare bool) {
	if !save && !compare {
		return
	}

	if compare {
		report, err := baseline.Compare(basePath, devices, db, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Baseline compare: %v\n", err)
		} else {
			changes := len(report.NewDevices) + len(report.RemovedDevices) + len(report.FirmwareChanges) + len(report.NewVulnerabilities)
			if changes == 0 {
				fmt.Println("[deadband] Baseline: no drift detected")
			} else {
				fmt.Printf("[deadband] Baseline drift: %d new, %d removed, %d firmware changes, %d new vulnerabilities\n",
					len(report.NewDevices), len(report.RemovedDevices),
					len(report.FirmwareChanges), len(report.NewVulnerabilities))
				for _, d := range report.NewDevices {
					fmt.Printf("  + %s %s (fw %s)\n", d.IP, d.Model, d.Firmware)
				}
				for _, d := range report.RemovedDevices {
					fmt.Printf("  - %s %s (fw %s)\n", d.IP, d.Model, d.Firmware)
				}
				for _, fc := range report.FirmwareChanges {
					fmt.Printf("  ~ %s %s: %s -> %s\n", fc.Device.IP, fc.Device.Model, fc.OldFirmware, fc.NewFirmware)
				}
				for _, nv := range report.NewVulnerabilities {
					for _, m := range nv.NewMatches {
						fmt.Printf("  ! %s %s: new advisory %s (CVSS %.1f)\n", nv.Device.IP, nv.Device.Model, m.Advisory.ID, m.Advisory.CVSSv3Max)
					}
				}
			}
		}
	}

	if save {
		b := baseline.NewFromDevices(devices)
		if err := baseline.Save(basePath, b); err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Error saving baseline: %v\n", err)
		} else {
			fmt.Printf("[deadband] Baseline saved: %d devices -> %s\n", len(devices), basePath)
		}
	}
}

// enrichmentDir returns the directory where enrichment data (KEV/EPSS) is cached,
// colocated with the advisory database.
func enrichmentDir(dbPath string) string {
	return filepath.Dir(dbPath)
}

// enrichResults populates KEV/EPSS/RiskScore fields on each Match from the enrichment DB.
func enrichResults(results []matcher.Result, edb *enrichment.DB) {
	if edb == nil || !edb.Loaded() {
		return
	}
	for i := range results {
		for j := range results[i].Matches {
			m := &results[i].Matches[j]
			ae := edb.EnrichAdvisory(m.Advisory.CVEs, m.Advisory.CVSSv3Max)
			m.KEV = ae.KEV
			m.KEVRansomware = ae.KEVRansomware
			m.EPSSScore = ae.MaxEPSS
			m.EPSSPercentile = ae.MaxEPSSPercent
			m.RiskScore = ae.RiskScore
		}
	}
}

// sortByRisk reorders results by highest risk score (across all matched advisories).
func sortByRisk(results []matcher.Result) {
	sort.Slice(results, func(i, j int) bool {
		return maxRiskScore(results[i]) > maxRiskScore(results[j])
	})
}

func maxRiskScore(r matcher.Result) float64 {
	maxScore := 0.0
	for _, m := range r.Matches {
		if m.RiskScore > maxScore {
			maxScore = m.RiskScore
		}
	}
	return maxScore
}

// saveDiscoveredAssets imports discovered devices into the persistent asset inventory.
func saveDiscoveredAssets(devices []inventory.Device, storePath string) {
	store := asset.LoadOrEmpty(storePath)
	result := store.Import(devices, "discovery")
	if err := asset.Save(storePath, store); err != nil {
		fmt.Fprintf(os.Stderr, "[deadband] Warning: failed to save assets: %v\n", err)
		return
	}
	fmt.Printf("[deadband] Assets: %d added, %d updated (%d total)\n", result.Added, result.Updated, result.Total)
}

// writeVulnStateToAssets updates vulnerability state on persisted assets that match check results.
func writeVulnStateToAssets(results []matcher.Result, storePath string) {
	store := asset.LoadOrEmpty(storePath)
	if len(store.Assets) == 0 {
		return
	}

	// Index assets by IP+Vendor+Model for fast lookup
	idx := make(map[string]*asset.Asset, len(store.Assets))
	for i := range store.Assets {
		a := &store.Assets[i]
		key := strings.ToLower(a.IP + "|" + a.Vendor + "|" + a.Model)
		idx[key] = a
	}

	now := time.Now().UTC()
	updated := 0
	for _, r := range results {
		key := strings.ToLower(r.Device.IP + "|" + r.Device.Vendor + "|" + r.Device.Model)
		a, ok := idx[key]
		if !ok {
			continue
		}

		// Use the highest confidence from matched advisories
		bestConf := "LOW"
		for _, m := range r.Matches {
			c := strings.ToUpper(string(m.Confidence))
			if c == "HIGH" || (c == "MEDIUM" && bestConf != "HIGH") {
				bestConf = c
			}
		}
		vs := &asset.VulnState{
			CheckedAt:  now,
			Status:     strings.ToUpper(r.Status),
			Confidence: bestConf,
		}

		var maxRisk float64
		var cveCount, kevCount int
		for _, m := range r.Matches {
			va := asset.VulnAdvisory{
				ID:        m.Advisory.ID,
				Title:     m.Advisory.Title,
				CVEs:      m.Advisory.CVEs,
				CVSSv3:    m.Advisory.CVSSv3Max,
				KEV:       m.KEV,
				RiskScore: m.RiskScore,
			}
			vs.Advisories = append(vs.Advisories, va)
			cveCount += len(m.Advisory.CVEs)
			if m.KEV {
				kevCount++
			}
			if m.RiskScore > maxRisk {
				maxRisk = m.RiskScore
			}
		}
		vs.RiskScore = maxRisk
		vs.CVECount = cveCount
		vs.KEVCount = kevCount

		a.VulnState = vs
		updated++
	}

	if updated > 0 {
		if err := asset.Save(storePath, store); err != nil {
			fmt.Fprintf(os.Stderr, "[deadband] Warning: failed to save asset vuln state: %v\n", err)
			return
		}
		fmt.Printf("[deadband] Updated vulnerability state for %d assets\n", updated)
	}
}
