package integration

import "time"

// SentinelConfig holds Azure Sentinel/Log Analytics credentials for a site.
type SentinelConfig struct {
	ID           string     `json:"id"`
	SiteID       string     `json:"site_id"`
	Name         string     `json:"name"`
	TenantID     string     `json:"tenant_id"`
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"client_secret"`
	WorkspaceID  string     `json:"workspace_id"`
	DefaultQuery string     `json:"default_query,omitempty"`
	Enabled      bool       `json:"enabled"`
	LastQueryAt  *time.Time `json:"last_query_at,omitempty"`
}

// ASAConfig holds Cisco ASA SSH connection details for a site.
type ASAConfig struct {
	ID             string     `json:"id"`
	SiteID         string     `json:"site_id"`
	Name           string     `json:"name"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	Username       string     `json:"username"`
	Password       string     `json:"password"`
	KeyPath        string     `json:"key_path,omitempty"`
	EnablePassword string     `json:"enable_password,omitempty"`
	Enabled        bool       `json:"enabled"`
	LastCollectAt  *time.Time `json:"last_collect_at,omitempty"`
}
