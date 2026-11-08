package updater

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
)

const (
	csafBaseURL = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white"
	indexURL    = csafBaseURL + "/index.txt"
)

type UpdateOpts struct {
	DBPath   string
	Since    string // YYYY-MM-DD
	Source   string // local path for air-gapped update
	Progress func(msg string)
}

func Update(opts UpdateOpts) (*advisory.Database, error) {
	// Snapshot path: when opts.Source is empty (default) or an http(s) URL,
	// try to fetch a single pre-built advisories.json — much faster and
	// resilient to GitHub egress filtering. On any failure we transparently
	// fall back to the per-file CSAF path. opts.Source == "github" forces
	// per-file fetch and skips the snapshot probe entirely.
	mode, snapshotURL := classifySource(opts.Source)
	isOnlineMode := mode == sourceSnapshotDefault || mode == sourcePerFileGitHub

	if mode == sourceSnapshotDefault || mode == sourceSnapshotURL {
		db, err := loadFromSnapshot(snapshotURL, opts.Progress)
		if err == nil {
			if isOnlineMode {
				now := time.Now().UTC()
				snapMap := make(map[string]advisory.Advisory, len(db.Advisories))
				for _, a := range db.Advisories {
					snapMap[a.ID] = a
				}
				rolieCount, nvdCount := mergeSupplementalOnlineFeeds(snapMap, opts.Since, now, opts.Progress)
				if rolieCount > 0 || nvdCount > 0 {
					db.Advisories = db.Advisories[:0]
					for _, a := range snapMap {
						db.Advisories = append(db.Advisories, a)
					}
					db.Source = formatSupplementalSource(db.Source, rolieCount, nvdCount)
				}
			}
			if saveErr := advisory.SaveDatabase(opts.DBPath, db); saveErr != nil {
				return nil, fmt.Errorf("saving snapshot database: %w", saveErr)
			}
			return db, nil
		}
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("snapshot unavailable (%v), falling back to per-file fetch", err))
		}
		// Explicit snapshot URL with checksum failure should not fall back —
		// the user asked for that specific snapshot. Default snapshot failure
		// falls through to the per-file path below.
		if mode == sourceSnapshotURL {
			return nil, err
		}
	}

	localSource := ""
	if mode == sourceLocalMirror {
		localSource = opts.Source
	}

	// Load existing DB for merge
	existing, _ := advisory.LoadDatabase(opts.DBPath)

	paths, err := fetchIndex(localSource)
	if err != nil {
		return nil, fmt.Errorf("fetching advisory index: %w", err)
	}

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Found %d advisory paths in index", len(paths)))
	}

	// Filter by --since if provided
	if opts.Since != "" {
		paths = filterPathsBySince(paths, opts.Since)
		if opts.Progress != nil {
			opts.Progress(fmt.Sprintf("Filtered to %d advisories since %s", len(paths), opts.Since))
		}
	}

	existingMap := make(map[string]advisory.Advisory)
	if existing != nil {
		for _, a := range existing.Advisories {
			existingMap[a.ID] = a
		}
		// Migrate old entries that lack FirstSeen: backfill with previous update time
		for id, a := range existingMap {
			if a.FirstSeen == nil {
				t := existing.Updated
				a.FirstSeen = &t
				existingMap[id] = a
			}
		}
	}

	now := time.Now().UTC()
	total := len(paths)

	// Fetch advisories concurrently with 100 workers
	type result struct {
		advisories []advisory.Advisory
		err        error
		path       string
	}

	work := make(chan string, len(paths))
	results := make(chan result, len(paths))
	var done atomic.Int64

	workers := 100
	if len(paths) < workers {
		workers = len(paths)
	}

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				doc, err := fetchAdvisory(localSource, p)
				if err != nil {
					results <- result{path: p, err: err}
				} else {
					results <- result{advisories: parseCSAF(doc), path: p}
				}
				n := done.Add(1)
				if opts.Progress != nil && (n%100 == 0 || int(n) == total) {
					opts.Progress(fmt.Sprintf("Fetched %d of %d advisories...", n, total))
				}
			}
		}()
	}

	go func() {
		for _, p := range paths {
			work <- p
		}
		close(work)
		wg.Wait()
		close(results)
	}()

	var fetched int
	for r := range results {
		if r.err != nil {
			if opts.Progress != nil {
				opts.Progress(fmt.Sprintf("Warning: skipping %s: %v", r.path, r.err))
			}
			continue
		}
		existingMap = mergeAdvisories(existingMap, r.advisories, now)
		fetched++
	}

	var rolieCount, nvdCount int
	if isOnlineMode {
		rolieCount, nvdCount = mergeSupplementalOnlineFeeds(existingMap, opts.Since, now, opts.Progress)
		fetched += rolieCount + nvdCount
	}

	// Build final DB
	db := &advisory.Database{
		Updated: now,
		Source:  formatSupplementalSource("cisagov/CSAF", rolieCount, nvdCount),
	}
	if existing != nil {
		db.PreviousUpdated = &existing.Updated
	}
	for _, a := range existingMap {
		db.Advisories = append(db.Advisories, a)
	}

	if err := advisory.SaveDatabase(opts.DBPath, db); err != nil {
		return nil, fmt.Errorf("saving advisory database: %w", err)
	}

	if opts.Progress != nil {
		opts.Progress(fmt.Sprintf("Fetched %d advisories, %d total in database", fetched, len(db.Advisories)))
	}

	return db, nil
}

func fetchIndex(source string) ([]string, error) {
	var reader io.Reader

	if source != "" {
		// Local source: read index.txt from the directory
		f, err := os.Open(filepath.Join(source, "index.txt"))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		reader = f
	} else {
		resp, err := http.Get(indexURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d fetching index", resp.StatusCode)
		}
		reader = resp.Body
	}

	var paths []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasSuffix(line, ".json") {
			paths = append(paths, line)
		}
	}
	return paths, scanner.Err()
}

func fetchAdvisory(source, path string) (*csafDoc, error) {
	var reader io.ReadCloser

	if source != "" {
		f, err := os.Open(filepath.Join(source, path))
		if err != nil {
			return nil, err
		}
		reader = f
	} else {
		url := csafBaseURL + "/" + path
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		reader = resp.Body
	}
	defer reader.Close()

	var doc csafDoc
	if err := json.NewDecoder(reader).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func parseCSAF(doc *csafDoc) []advisory.Advisory {
	vendor, products, versions := extractFromDoc(doc)

	// Deduplicate products and versions
	seen := make(map[string]bool)
	var uniqueProducts []string
	for _, p := range products {
		lower := strings.ToLower(p)
		if !seen[lower] {
			seen[lower] = true
			uniqueProducts = append(uniqueProducts, p)
		}
	}
	verSeen := make(map[string]bool)
	var uniqueVersions []string
	for _, v := range versions {
		if v != "" && !verSeen[v] {
			verSeen[v] = true
			uniqueVersions = append(uniqueVersions, v)
		}
	}

	// Collect CVEs, max CVSS, CWEs, and remediations from vulnerabilities
	var cves []string
	maxCVSS := 0.0
	cweSeen := make(map[string]bool)
	var weaknesses []advisory.Weakness
	remSeen := make(map[string]bool)
	var remediations []advisory.Remediation

	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE != "" {
			cves = append(cves, vuln.CVE)
		}
		for _, score := range vuln.Scores {
			var cvss csafCVSS
			if err := json.Unmarshal(score.CVSSv3, &cvss); err == nil {
				maxCVSS = math.Max(maxCVSS, cvss.BaseScore)
			}
		}
		// Extract CWE weakness types
		if vuln.CWE != nil && vuln.CWE.ID != "" && !cweSeen[vuln.CWE.ID] {
			cweSeen[vuln.CWE.ID] = true
			weaknesses = append(weaknesses, advisory.Weakness{
				ID:   vuln.CWE.ID,
				Name: vuln.CWE.Name,
			})
		}
		// Extract remediations
		for _, rem := range vuln.Remediations {
			key := rem.Category + ":" + rem.Details
			if !remSeen[key] {
				remSeen[key] = true
				remediations = append(remediations, advisory.Remediation{
					Category: rem.Category,
					Details:  rem.Details,
					URL:      rem.URL,
				})
			}
		}
	}

	// Extract summary and sectors from document notes
	var summary, fallbackDesc string
	var sectors []string
	for _, note := range doc.Document.Notes {
		switch note.Category {
		case "summary":
			if summary == "" {
				summary = note.Text
			}
		case "description":
			if fallbackDesc == "" {
				fallbackDesc = note.Text
			}
		case "general":
			// Parse "Critical Infrastructure Sectors:" from general notes
			if strings.Contains(note.Text, "Critical Infrastructure Sectors:") ||
				strings.Contains(note.Text, "CRITICAL INFRASTRUCTURE SECTORS") {
				sectors = parseSectors(note.Text)
			}
		}
	}
	if summary == "" {
		summary = fallbackDesc
	}
	if summary == "" {
		for _, vuln := range doc.Vulnerabilities {
			for _, note := range vuln.Notes {
				if note.Category == "summary" || note.Category == "description" {
					summary = note.Text
					break
				}
			}
			if summary != "" {
				break
			}
		}
	}

	// Resolve canonical advisory URL across CISA and non-CISA CSAF 2.0 publishers
	id := doc.Document.Tracking.ID
	url := resolveCSAFURL(doc)

	published := doc.Document.Tracking.InitialReleaseDate
	if published == "" {
		published = doc.Document.Tracking.CurrentReleaseDate
	}
	// Trim to date only
	if len(published) > 10 {
		published = published[:10]
	}

	if id == "" {
		return nil
	}

	return []advisory.Advisory{{
		ID:               id,
		Title:            doc.Document.Title,
		Vendor:           vendor,
		Products:         uniqueProducts,
		AffectedVersions: uniqueVersions,
		CVSSv3Max:        maxCVSS,
		CVEs:             cves,
		URL:              url,
		Published:        published,
		Summary:          summary,
		Weaknesses:       weaknesses,
		Sectors:          sectors,
		Remediations:     remediations,
	}}
}

func resolveCSAFURL(doc *csafDoc) string {
	id := doc.Document.Tracking.ID
	upperID := strings.ToUpper(id)
	isCISA := strings.HasPrefix(upperID, "ICSA-") || strings.HasPrefix(upperID, "ICSMA-") ||
		strings.Contains(strings.ToLower(doc.Document.Publisher.Namespace), "cisa.gov")

	if isCISA {
		for _, ref := range doc.Document.References {
			if ref.Category == "self" && strings.Contains(ref.URL, "cisa.gov") && !strings.HasSuffix(strings.ToLower(ref.URL), ".json") {
				return ref.URL
			}
		}
		for _, ref := range doc.Document.References {
			if strings.Contains(ref.URL, "cisa.gov") && !strings.HasSuffix(strings.ToLower(ref.URL), ".json") {
				return ref.URL
			}
		}
		if id != "" {
			return fmt.Sprintf("https://www.cisa.gov/news-events/ics-advisories/%s", strings.ToLower(id))
		}
		return ""
	}

	// Non-CISA CSAF publisher (CERT@VDE, Beckhoff, SICK, WAGO, Pilz, Festo, etc.):
	// 1. Prefer HTML/portal "self" reference (non-.json)
	for _, ref := range doc.Document.References {
		if ref.Category == "self" && isHTTPURL(ref.URL) && !strings.HasSuffix(strings.ToLower(ref.URL), ".json") {
			return ref.URL
		}
	}
	// 2. Prefer first external human-readable advisory reference
	for _, ref := range doc.Document.References {
		if ref.Category == "external" && isHTTPURL(ref.URL) {
			return ref.URL
		}
	}
	// 3. Fall back to canonical JSON "self" reference
	for _, ref := range doc.Document.References {
		if ref.Category == "self" && isHTTPURL(ref.URL) {
			return ref.URL
		}
	}
	// 4. Check vulnerability-level references
	for _, vuln := range doc.Vulnerabilities {
		for _, ref := range vuln.References {
			if isHTTPURL(ref.URL) {
				return ref.URL
			}
		}
	}
	if isHTTPURL(doc.Document.Publisher.Namespace) {
		return doc.Document.Publisher.Namespace
	}
	return ""
}

func isHTTPURL(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

// parseSectors extracts sector names from CISA background notes text.
// The text typically looks like:
// "Critical Infrastructure Sectors: Energy, Water and Wastewater Systems"
func parseSectors(text string) []string {
	// Try to find the sectors value after the label
	for _, prefix := range []string{
		"Critical Infrastructure Sectors:",
		"CRITICAL INFRASTRUCTURE SECTORS:",
	} {
		idx := strings.Index(text, prefix)
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(text[idx+len(prefix):])
		// Take until the next newline or bullet point
		if nl := strings.IndexAny(rest, "\n\r"); nl >= 0 {
			rest = rest[:nl]
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		parts := strings.Split(rest, ",")
		var sectors []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				sectors = append(sectors, p)
			}
		}
		return sectors
	}
	return nil
}

// mergeAdvisories merges a batch of newly fetched advisories into the existing map,
// preserving FirstSeen for known IDs and setting it for new ones.
func mergeAdvisories(existing map[string]advisory.Advisory, fetched []advisory.Advisory, now time.Time) map[string]advisory.Advisory {
	for _, a := range fetched {
		if prev, ok := existing[a.ID]; ok {
			a.FirstSeen = prev.FirstSeen
		} else {
			a.FirstSeen = &now
		}
		a.LastSeen = &now
		existing[a.ID] = a
	}
	return existing
}

func filterPathsBySince(paths []string, since string) []string {
	// Advisory paths contain year: e.g., "2024/icsa-24-179-01.json"
	sinceTime, err := time.Parse("2006-01-02", since)
	if err != nil {
		return paths
	}
	sinceYear := sinceTime.Year()

	var filtered []string
	for _, p := range paths {
		parts := strings.SplitN(p, "/", 2)
		if len(parts) < 2 {
			filtered = append(filtered, p)
			continue
		}
		var year int
		if _, err := fmt.Sscanf(parts[0], "%d", &year); err == nil {
			if year >= sinceYear {
				filtered = append(filtered, p)
			}
		} else {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

var (
	rolieFetcher = fetchROLIEAdvisories
	nvdFetcher   = fetchNVDAdvisories
)

func mergeSupplementalOnlineFeeds(
	existingMap map[string]advisory.Advisory,
	sinceStr string,
	now time.Time,
	progress func(string),
) (rolieAdded, nvdAdded int) {
	var sinceTime time.Time
	if sinceStr != "" {
		if parsed, err := time.Parse("2006-01-02", sinceStr); err == nil {
			sinceTime = parsed
		}
	}

	rolieAdvs := rolieFetcher(nil, sinceTime, progress)
	if len(rolieAdvs) > 0 {
		mergeAdvisories(existingMap, rolieAdvs, now)
		rolieAdded = len(rolieAdvs)
	}

	// Build set of CVEs already covered by structured CSAF advisories (CISA + ROLIE)
	coveredCVEs := make(map[string]bool, len(existingMap)*2)
	for _, a := range existingMap {
		if strings.HasPrefix(strings.ToUpper(a.ID), "CVE-") {
			continue
		}
		for _, cve := range a.CVEs {
			coveredCVEs[strings.ToUpper(strings.TrimSpace(cve))] = true
		}
	}

	nvdAdvs := nvdFetcher(nil, sinceTime, progress)
	if len(nvdAdvs) > 0 {
		var filteredNVD []advisory.Advisory
		for _, a := range nvdAdvs {
			if coveredCVEs[strings.ToUpper(a.ID)] {
				continue
			}
			filteredNVD = append(filteredNVD, a)
		}
		if len(filteredNVD) > 0 {
			mergeAdvisories(existingMap, filteredNVD, now)
			nvdAdded = len(filteredNVD)
		}
	}

	return rolieAdded, nvdAdded
}

func formatSupplementalSource(base string, rolieCount, nvdCount int) string {
	var parts []string
	parts = append(parts, base)
	if rolieCount > 0 {
		parts = append(parts, "csaf-rolie")
	}
	if nvdCount > 0 {
		parts = append(parts, "nvd-2.0")
	}
	return strings.Join(parts, "+")
}
