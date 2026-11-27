// Package bridge integrates Layer 7 with raksa-siem HTTP endpoints.
package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luminariadev/raksa/internal/schema"
)

// Client calls raksa-siem REST endpoints with bounded timeouts and optional bearer auth.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient validates an http/https SIEM endpoint URL and returns a bounded client.
func NewClient(rawURL, token string, timeout time.Duration) (*Client, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid SIEM URL %q: %w", rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported SIEM URL scheme %q (expected http or https)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("SIEM URL %q missing host", rawURL)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL:    trimmed,
		token:      strings.TrimSpace(token),
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

// Health verifies /healthz returns 2xx.
func (c *Client) Health(ctx context.Context) error {
	_, err := c.doJSON(ctx, http.MethodGet, "/healthz", nil)
	return err
}

// IngestReport forwards a unified SuiteReport envelope to raksa-siem /api/v1/ingest.
func (c *Client) IngestReport(ctx context.Context, rep schema.SuiteReport) (map[string]any, error) {
	body, err := c.doJSON(ctx, http.MethodPost, "/api/v1/ingest", rep)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode SIEM ingest response: %w", err)
	}
	return out, nil
}

// Posture fetches live posture metrics from /api/v1/posture.
func (c *Client) Posture(ctx context.Context) (map[string]any, error) {
	body, err := c.doJSON(ctx, http.MethodGet, "/api/v1/posture", nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode SIEM posture response: %w", err)
	}
	return out, nil
}

// VerifyLedger checks remote tamper-evident audit ledger integrity via /api/v1/ledger/verify.
func (c *Client) VerifyLedger(ctx context.Context) (map[string]any, error) {
	body, err := c.doJSON(ctx, http.MethodGet, "/api/v1/ledger/verify", nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode SIEM ledger verify response: %w", err)
	}
	return out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build SIEM request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call SIEM %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read SIEM %s response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("SIEM %s returned HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
