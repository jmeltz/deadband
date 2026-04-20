package sentinel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/flow"
	"github.com/jmeltz/deadband/pkg/integration"
)

// Client communicates with Azure Log Analytics to query Sentinel flow data.
type Client struct {
	tenantID     string
	clientID     string
	clientSecret string
	workspaceID  string
	configID     string
	httpClient   *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// NewClient creates a Sentinel client from an integration config.
func NewClient(cfg integration.SentinelConfig) *Client {
	return &Client{
		tenantID:     cfg.TenantID,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		workspaceID:  cfg.WorkspaceID,
		configID:     cfg.ID,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

// TestConnection validates credentials by acquiring an OAuth2 token.
func (c *Client) TestConnection(ctx context.Context) error {
	return c.ensureToken(ctx)
}

// ensureToken acquires or refreshes the OAuth2 access token using client credentials.
func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.tenantID)

	data := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {"https://api.loganalytics.io/.default"},
		"grant_type":    {"client_credentials"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("parsing token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return fmt.Errorf("empty access token in response")
	}

	c.token = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)
	return nil
}

// QueryFlows executes a KQL query and returns parsed flow data as canonical
// FlowRecords. Records are tagged with SourceID "sentinel:<configID>" and
// SourceHash set to the sha256 of the executed query — this lets downstream
// code trace a flow back to the exact source config and KQL that produced it.
func (c *Client) QueryFlows(ctx context.Context, query string) ([]flow.FlowRecord, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	queryURL := fmt.Sprintf("https://api.loganalytics.io/v1/workspaces/%s/query", c.workspaceID)

	reqBody, _ := json.Marshal(map[string]string{"query": query})
	req, err := http.NewRequestWithContext(ctx, "POST", queryURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("creating query request: %w", err)
	}

	c.mu.Lock()
	token := c.token
	c.mu.Unlock()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading query response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Tables []struct {
			Columns []struct {
				Name string `json:"name"`
			} `json:"columns"`
			Rows [][]any `json:"rows"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing query response: %w", err)
	}

	if len(result.Tables) == 0 || len(result.Tables[0].Rows) == 0 {
		return nil, nil
	}

	colIdx := make(map[string]int, len(result.Tables[0].Columns))
	for i, col := range result.Tables[0].Columns {
		colIdx[col.Name] = i
	}

	sum := sha256.Sum256([]byte(query))
	meta := flowMeta{
		sourceID:   "sentinel:" + c.configID,
		sourceHash: hex.EncodeToString(sum[:]),
		ingestedAt: time.Now().UTC(),
	}
	return parseFlows(colIdx, result.Tables[0].Rows, meta), nil
}

type flowMeta struct {
	sourceID   string
	sourceHash string
	ingestedAt time.Time
}

// enrichmentKeys are the columns we pass through into FlowRecord.Enrichment.
// They match today's hardcoded KQL join; the preview-driven flow source in
// phase 2 replaces this with user-defined mappings.
var enrichmentKeys = []string{
	"DeviceHostname", "ComputerName", "UserName", "FullName", "JobTitle",
	"Department", "MailAddress", "CompanyName", "OsName",
}

func parseFlows(colIdx map[string]int, rows [][]any, meta flowMeta) []flow.FlowRecord {
	flows := make([]flow.FlowRecord, 0, len(rows))
	for _, row := range rows {
		rec := flow.FlowRecord{
			ObservedAt:      meta.ingestedAt,
			IngestedAt:      meta.ingestedAt,
			SourceZone:      toString(row, colIdx, "SourceZone"),
			SourceAddr:      toString(row, colIdx, "SourceAddr"),
			DestZone:        toString(row, colIdx, "DestZone"),
			DestAddr:        toString(row, colIdx, "DestAddr"),
			DestPort:        toInt(row, colIdx, "DestPort"),
			Protocol:        flow.ProtoTCP,
			ConnectionCount: toInt(row, colIdx, "ConnectionCount"),
			Kind:            flow.KindObserved,
			SourceID:        meta.sourceID,
			SourceHash:      meta.sourceHash,
		}

		enrichment := make(map[string]string)
		for _, k := range enrichmentKeys {
			if v := toString(row, colIdx, k); v != "" {
				enrichment[k] = v
			}
		}
		if natAddr := toString(row, colIdx, "DestNATAddr"); natAddr != "" {
			enrichment["DestNATAddr"] = natAddr
		}
		if natPort := toInt(row, colIdx, "DestNATPort"); natPort != 0 {
			enrichment["DestNATPort"] = fmt.Sprintf("%d", natPort)
		}
		if len(enrichment) > 0 {
			rec.Enrichment = enrichment
		}

		flows = append(flows, rec)
	}
	return flows
}

func toString(row []any, colIdx map[string]int, name string) string {
	idx, ok := colIdx[name]
	if !ok || idx >= len(row) {
		return ""
	}
	if s, ok := row[idx].(string); ok {
		return s
	}
	return ""
}

func toInt(row []any, colIdx map[string]int, name string) int {
	idx, ok := colIdx[name]
	if !ok || idx >= len(row) {
		return 0
	}
	switch v := row[idx].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}
