package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
)

// ROLIEProvider describes a public OASIS CSAF 2.0 TLP:WHITE ROLIE feed endpoint.
type ROLIEProvider struct {
	Name    string
	FeedURL string
}

// DefaultROLIEProviders lists verified public unauthenticated TLP:WHITE OASIS CSAF 2.0
// ROLIE feeds covering European intralogistics, ASRS, safety PLC, sensor, and drive OEMs.
var DefaultROLIEProviders = []ROLIEProvider{
	{
		Name:    "CERT@VDE",
		FeedURL: "https://certvde.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "Beckhoff",
		FeedURL: "https://beckhoff.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "SICK",
		FeedURL: "https://www.sick.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "Pilz",
		FeedURL: "https://pilz.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "WAGO",
		FeedURL: "https://wago.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "Festo",
		FeedURL: "https://festo.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "TURCK",
		FeedURL: "https://turck.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "Lenze",
		FeedURL: "https://lenze.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "Pepperl+Fuchs",
		FeedURL: "https://pepperl-fuchs.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "Phoenix Contact",
		FeedURL: "https://phoenixcontact.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
	{
		Name:    "Weidmüller",
		FeedURL: "https://weidmueller.csaf-tp.certvde.com/.well-known/csaf/white/csaf-feed-tlp-white.json",
	},
}

type rolieFeedDoc struct {
	Feed rolieFeed `json:"feed"`
}

type rolieFeed struct {
	ID      string       `json:"id"`
	Title   string       `json:"title"`
	Updated string       `json:"updated"`
	Entries []rolieEntry `json:"entry"`
}

type rolieEntry struct {
	ID        string       `json:"id"`
	Title     string       `json:"title"`
	Published string       `json:"published"`
	Updated   string       `json:"updated"`
	Links     []rolieLink  `json:"link"`
	Content   rolieContent `json:"content"`
}

type rolieLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type rolieContent struct {
	Type string `json:"type"`
	Src  string `json:"src"`
}

const (
	rolieHTTPTimeout = 20 * time.Second
	rolieMaxBodySize = 16 * 1024 * 1024 // 16 MiB cap per feed/document
	rolieDocWorkers  = 16
)

// fetchROLIEAdvisories fetches advisories across DefaultROLIEProviders.
// Provider failures are non-fatal and reported via progress.
func fetchROLIEAdvisories(client *http.Client, since time.Time, progress func(string)) []advisory.Advisory {
	return fetchROLIEAdvisoriesFromProviders(client, DefaultROLIEProviders, since, progress)
}

func fetchROLIEAdvisoriesFromProviders(client *http.Client, providers []ROLIEProvider, since time.Time, progress func(string)) []advisory.Advisory {
	if len(providers) == 0 {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: rolieHTTPTimeout}
	}

	type docJob struct {
		provider string
		docURL   string
	}

	var (
		jobs   []docJob
		jobsMu sync.Mutex
		feedWg sync.WaitGroup
	)

	for _, prov := range providers {
		feedWg.Add(1)
		go func(p ROLIEProvider) {
			defer feedWg.Done()
			urls, err := fetchROLIEEntryURLs(client, p.FeedURL, since)
			if err != nil {
				if progress != nil {
					progress(fmt.Sprintf("Warning: CSAF ROLIE feed %s (%s) unavailable: %v", p.Name, p.FeedURL, err))
				}
				return
			}
			jobsMu.Lock()
			for _, u := range urls {
				jobs = append(jobs, docJob{provider: p.Name, docURL: u})
			}
			jobsMu.Unlock()
		}(prov)
	}
	feedWg.Wait()

	if len(jobs) == 0 {
		return nil
	}
	if progress != nil {
		progress(fmt.Sprintf("Fetching %d CSAF advisories from %d ROLIE provider feeds...", len(jobs), len(providers)))
	}

	// Deduplicate identical document URLs before fetching (coordinator + vendor feeds may cross-link)
	seenURL := make(map[string]bool, len(jobs))
	uniqueJobs := make([]docJob, 0, len(jobs))
	for _, j := range jobs {
		if !seenURL[j.docURL] {
			seenURL[j.docURL] = true
			uniqueJobs = append(uniqueJobs, j)
		}
	}

	work := make(chan docJob, len(uniqueJobs))
	for _, j := range uniqueJobs {
		work <- j
	}
	close(work)

	workers := rolieDocWorkers
	if len(uniqueJobs) < workers {
		workers = len(uniqueJobs)
	}

	var (
		mu         sync.Mutex
		byID       = make(map[string]advisory.Advisory)
		orderedIDs []string
		docWg      sync.WaitGroup
	)

	for range workers {
		docWg.Add(1)
		go func() {
			defer docWg.Done()
			for job := range work {
				doc, err := fetchCSAFDocumentURL(client, job.docURL)
				if err != nil {
					if progress != nil {
						progress(fmt.Sprintf("Warning: skipping ROLIE advisory %s (%s): %v", job.provider, job.docURL, err))
					}
					continue
				}
				advs := parseCSAF(doc)
				mu.Lock()
				for _, a := range advs {
					if a.ID == "" {
						continue
					}
					if _, exists := byID[a.ID]; !exists {
						orderedIDs = append(orderedIDs, a.ID)
						byID[a.ID] = a
					}
				}
				mu.Unlock()
			}
		}()
	}
	docWg.Wait()

	out := make([]advisory.Advisory, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		out = append(out, byID[id])
	}
	if progress != nil && len(out) > 0 {
		progress(fmt.Sprintf("Ingested %d unique CSAF advisories from ROLIE feeds", len(out)))
	}
	return out
}

func fetchROLIEEntryURLs(client *http.Client, feedURL string, since time.Time) ([]string, error) {
	base, err := url.Parse(feedURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Deadband-CSAF-Updater/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var feedDoc rolieFeedDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, rolieMaxBodySize)).Decode(&feedDoc); err != nil {
		return nil, fmt.Errorf("decoding ROLIE feed: %w", err)
	}

	var urls []string
	for _, entry := range feedDoc.Feed.Entries {
		if !since.IsZero() && !rolieEntryAfterOrEqual(entry, since) {
			continue
		}
		rawHref := strings.TrimSpace(entry.Content.Src)
		if rawHref == "" {
			for _, lnk := range entry.Links {
				if lnk.Rel == "self" && strings.HasSuffix(strings.ToLower(lnk.Href), ".json") {
					rawHref = strings.TrimSpace(lnk.Href)
					break
				}
			}
		}
		if rawHref == "" {
			for _, lnk := range entry.Links {
				if strings.HasSuffix(strings.ToLower(lnk.Href), ".json") {
					rawHref = strings.TrimSpace(lnk.Href)
					break
				}
			}
		}
		if rawHref == "" {
			continue
		}
		ref, err := url.Parse(rawHref)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref).String()
		if isHTTPURL(resolved) {
			urls = append(urls, resolved)
		}
	}
	return urls, nil
}

func rolieEntryAfterOrEqual(entry rolieEntry, since time.Time) bool {
	for _, candidate := range []string{entry.Updated, entry.Published} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339, candidate); err == nil {
			return !ts.Before(since)
		}
		if len(candidate) >= 10 {
			if ts, err := time.Parse("2006-01-02", candidate[:10]); err == nil {
				return !ts.Before(since)
			}
		}
	}
	// Keep entry if timestamp is missing/unparseable rather than silently dropping advisories
	return true
}

func fetchCSAFDocumentURL(client *http.Client, docURL string) (*csafDoc, error) {
	req, err := http.NewRequest(http.MethodGet, docURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Deadband-CSAF-Updater/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var doc csafDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, rolieMaxBodySize)).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
