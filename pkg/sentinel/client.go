package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/integration"
)

// Client communicates with Azure Log Analytics to query Sentinel flow data.
type Client struct {
	tenantID    string
	clientID    string
	clientSecret string
	workspaceID string
	httpClient  *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// NewClient creates a Sentinel client from an integration config.
func NewClient(cfg integration.SentinelConfig) *Client {
	return &Client{
		tenantID:    cfg.TenantID,
		clientID:    cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		workspaceID: cfg.WorkspaceID,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
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

// QueryFlows executes a KQL query and returns parsed flow data.
func (c *Client) QueryFlows(ctx context.Context, query string) ([]SentinelFlow, error) {
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

	// Build column index
	colIdx := make(map[string]int, len(result.Tables[0].Columns))
	for i, col := range result.Tables[0].Columns {
		colIdx[col.Name] = i
	}

	return parseFlows(colIdx, result.Tables[0].Rows), nil
}

func parseFlows(colIdx map[string]int, rows [][]any) []SentinelFlow {

	flows := make([]SentinelFlow, 0, len(rows))
	for _, row := range rows {
		f := SentinelFlow{
			DeviceHostname:  toString(row, colIdx, "DeviceHostname"),
			SourceZone:      toString(row, colIdx, "SourceZone"),
			SourceAddr:      toString(row, colIdx, "SourceAddr"),
			DestZone:        toString(row, colIdx, "DestZone"),
			DestAddr:        toString(row, colIdx, "DestAddr"),
			DestPort:        toInt(row, colIdx, "DestPort"),
			DestNATAddr:     toString(row, colIdx, "DestNATAddr"),
			DestNATPort:     toInt(row, colIdx, "DestNATPort"),
			ConnectionCount: toInt(row, colIdx, "ConnectionCount"),
			ComputerName:    toString(row, colIdx, "ComputerName"),
			UserName:        toString(row, colIdx, "UserName"),
			FullName:        toString(row, colIdx, "FullName"),
			JobTitle:        toString(row, colIdx, "JobTitle"),
			Department:      toString(row, colIdx, "Department"),
			MailAddress:     toString(row, colIdx, "MailAddress"),
			CompanyName:     toString(row, colIdx, "CompanyName"),
			OsName:          toString(row, colIdx, "OsName"),
		}
		flows = append(flows, f)
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
