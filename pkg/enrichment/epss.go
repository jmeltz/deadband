package enrichment

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const epssURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// EPSSEntry holds the EPSS score and percentile for a single CVE.
type EPSSEntry struct {
	CVE        string
	Score      float64 // 0.0–1.0, probability of exploitation in next 30 days
	Percentile float64 // 0.0–1.0, relative rank
}

// EPSSData is the runtime lookup structure for EPSS scores.
type EPSSData struct {
	ModelVersion string
	ScoreDate    string
	Entries      map[string]EPSSEntry // keyed by CVE ID
}

// FetchEPSS downloads the current EPSS scores (gzipped CSV) and returns parsed data.
func FetchEPSS(progress func(string)) (*EPSSData, error) {
	if progress != nil {
		progress("Fetching EPSS scores...")
	}

	resp, err := http.Get(epssURL)
	if err != nil {
		return nil, fmt.Errorf("fetching EPSS scores: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS scores HTTP %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decompressing EPSS data: %w", err)
	}
	defer gz.Close()

	return parseEPSS(gz)
}

// LoadEPSSFromFile loads EPSS data from a local CSV file (uncompressed).
func LoadEPSSFromFile(path string) (*EPSSData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseEPSS(f)
}

func parseEPSS(r io.Reader) (*EPSSData, error) {
	data := &EPSSData{
		Entries: make(map[string]EPSSEntry, 250000),
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// First line is metadata: #model_version:v2024.01.01,score_date:2024-01-01T00:00:00+0000
		if lineNum == 1 && strings.HasPrefix(line, "#") {
			for _, part := range strings.Split(line[1:], ",") {
				kv := strings.SplitN(part, ":", 2)
				if len(kv) == 2 {
					switch kv[0] {
					case "model_version":
						data.ModelVersion = kv[1]
					case "score_date":
						data.ScoreDate = kv[1]
					}
				}
			}
			continue
		}

		// Second line is header: cve,epss,percentile
		if lineNum == 2 && strings.HasPrefix(line, "cve,") {
			continue
		}

		parts := strings.SplitN(line, ",", 4)
		if len(parts) < 3 {
			continue
		}

		cve := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}

		score, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
		if err != nil {
			continue
		}

		data.Entries[cve] = EPSSEntry{
			CVE:        cve,
			Score:      score,
			Percentile: percentile,
		}
	}

	return data, scanner.Err()
}

// SaveEPSS writes EPSS data as uncompressed CSV for caching.
func SaveEPSS(dir string, data *EPSSData) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	path := filepath.Join(dir, "epss_scores.csv")
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)
	// Write metadata header
	fmt.Fprintf(w, "#model_version:%s,score_date:%s\n", data.ModelVersion, data.ScoreDate)
	fmt.Fprintln(w, "cve,epss,percentile")
	for _, e := range data.Entries {
		fmt.Fprintf(w, "%s,%g,%g\n", e.CVE, e.Score, e.Percentile)
	}

	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
