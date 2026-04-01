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
	// Load existing DB for merge
	existing, _ := advisory.LoadDatabase(opts.DBPath)

	paths, err := fetchIndex(opts.Source)
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
	}

	total := len(paths)
	var fetched int
	for i, p := range paths {
		if opts.Progress != nil && (i%50 == 0 || i == total-1) {
			opts.Progress(fmt.Sprintf("Fetching advisory %d of %d...", i+1, total))
		}

		doc, err := fetchAdvisory(opts.Source, p)
		if err != nil {
			if opts.Progress != nil {
				opts.Progress(fmt.Sprintf("Warning: skipping %s: %v", p, err))
			}
			continue
		}

		advisories := parseCSAF(doc)
		for _, a := range advisories {
			existingMap[a.ID] = a
		}
		fetched++
	}

	// Build final DB
	db := &advisory.Database{
		Updated: time.Now().UTC(),
		Source:  "cisagov/CSAF",
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
	vendor, products, versions, _ := extractFromTree(doc.ProductTree.Branches)

	// Deduplicate products
	seen := make(map[string]bool)
	var uniqueProducts []string
	for _, p := range products {
		lower := strings.ToLower(p)
		if !seen[lower] {
			seen[lower] = true
			uniqueProducts = append(uniqueProducts, p)
		}
	}

	// Collect CVEs and max CVSS
	var cves []string
	maxCVSS := 0.0
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
	}

	// Build URL from tracking ID
	id := doc.Document.Tracking.ID
	url := ""
	for _, ref := range doc.Document.References {
		if ref.Category == "self" && strings.Contains(ref.URL, "cisa.gov") {
			url = ref.URL
			break
		}
	}
	if url == "" && id != "" {
		url = fmt.Sprintf("https://www.cisa.gov/news-events/ics-advisories/%s", strings.ToLower(id))
	}

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
		AffectedVersions: versions,
		CVSSv3Max:        maxCVSS,
		CVEs:             cves,
		URL:              url,
		Published:        published,
	}}
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
