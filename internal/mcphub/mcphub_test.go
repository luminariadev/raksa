package mcphub

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPHubCatalogAndHandshake(t *testing.T) {
	cat := Catalog()
	if len(cat) != 61 {
		t.Fatalf("expected 61 federated MCP tools (8 L7 + 53 L1-L6), got %d", len(cat))
	}

	hub := NewHub("", t.TempDir()+"/runs.ndjson")
	hub.UpstreamFn = func(_ context.Context, binary, toolName string, _ json.RawMessage) (string, bool, error) {
		return "proxied:" + binary + ":" + toolName, false, nil
	}

	stdin := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"raksa_defense_coverage","arguments":{"status":"covered"}}}` + "\n" +
			`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pipeguard_scan_repo","arguments":{"path":"."}}}` + "\n",
	)
	var stdout bytes.Buffer
	if err := hub.ServeStreams(stdin, &stdout); err != nil {
		t.Fatalf("ServeStreams: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 JSON-RPC responses, got %d:\n%s", len(lines), stdout.String())
	}

	var listResp struct {
		Result struct {
			Tools []any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Result.Tools) != 61 {
		t.Fatalf("tools/list returned %d tools, want 61", len(listResp.Result.Tools))
	}

	if !strings.Contains(lines[2], "Reconnaissance") {
		t.Fatalf("expected attack coverage matrix in id=3 response, got: %s", lines[2])
	}
	if !strings.Contains(lines[3], "proxied:raksa-pipeguard:pipeguard_scan_repo") {
		t.Fatalf("expected upstream dispatch in id=4 response, got: %s", lines[3])
	}
}
