package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa/internal/runner"
	"github.com/luminariadev/raksa/internal/schema"
)

func TestServerSecurityHeadersAuthCSRFAndWorkflows(t *testing.T) {
	ws := t.TempDir()
	hist := filepath.Join(t.TempDir(), "runs.ndjson")

	// Prepare local test fixture report so server loads clean baseline and scans deterministically
	repPath := filepath.Join(ws, "pipe.json")
	fixture := `{"schema_version":"1.0","tool":"raksa-pipeguard","layer":"devsecops","findings":[{"id":"p1","rule_id":"PIPE-001","layer":"devsecops","severity":"high","title":"Sample Secret Finding","description":"desc","target":"file://sample.env","mitre_d3fend":"D3-SYSV"}]}`
	if err := os.WriteFile(repPath, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	mockResolver := func(binary, _ string) (string, bool) {
		if binary == "raksa-pipeguard" {
			return "/bin/raksa-pipeguard", true
		}
		return "", false
	}
	mockExec := func(_ context.Context, _ string, _ ...string) runner.ExecResult {
		return runner.ExecResult{ExitCode: 2, Stdout: []byte(fixture)}
	}

	siemMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path == "/api/v1/ingest" {
			_, _ = w.Write([]byte(`{"ingested":1}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer siemMock.Close()

	srv, err := New(Config{
		Workspace:   ws,
		FromReports: repPath,
		HistoryPath: hist,
		SIEMURL:     siemMock.URL,
		Token:       "unit-test-token-123",
		Resolver:    mockResolver,
		Exec:        mockExec,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Check strict security headers on "/"
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, hdr := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"} {
		if resp.Header.Get(hdr) == "" {
			t.Fatalf("missing security header %s", hdr)
		}
	}

	// 2. Unauthenticated API call returns 401
	unauth, err := http.Get(ts.URL + "/api/v1/report")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated API call, got %d", unauth.StatusCode)
	}

	// 3. Cross-origin POST blocked with 403
	reqCSRF, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/siem/health", strings.NewReader("{}"))
	reqCSRF.Header.Set("X-Raksa-Token", "unit-test-token-123")
	reqCSRF.Header.Set("Origin", "https://evil.example")
	csrfResp, err := http.DefaultClient.Do(reqCSRF)
	if err != nil {
		t.Fatal(err)
	}
	csrfResp.Body.Close()
	if csrfResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 anti-CSRF rejection, got %d", csrfResp.StatusCode)
	}

	// 4. Authenticated MCP catalog (61 tools) + Scan + Fail-closed Waiver + SIEM bridge
	reqMCP, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/mcp-catalog", nil)
	reqMCP.Header.Set("X-Raksa-Token", "unit-test-token-123")
	mcpResp, err := http.DefaultClient.Do(reqMCP)
	if err != nil {
		t.Fatal(err)
	}
	var mcpBody struct {
		Total int `json:"total"`
	}
	_ = json.NewDecoder(mcpResp.Body).Decode(&mcpBody)
	mcpResp.Body.Close()
	if mcpBody.Total != 61 {
		t.Fatalf("expected 61 MCP tools from API, got %d", mcpBody.Total)
	}

	// Reject incomplete waiver missing reason
	badWaiver, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/waivers", strings.NewReader(`{"rule_id":"PIPE-001","expires_on":"2027-12-31"}`))
	badWaiver.Header.Set("X-Raksa-Token", "unit-test-token-123")
	bwResp, err := http.DefaultClient.Do(badWaiver)
	if err != nil {
		t.Fatal(err)
	}
	bwResp.Body.Close()
	if bwResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on waiver missing reason, got %d", bwResp.StatusCode)
	}

	// Valid waiver suppresses active PIPE-001 finding and raises posture to 100
	goodWaiver, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/waivers", strings.NewReader(`{"rule_id":"PIPE-001","reason":"Approved fixture waiver","expires_on":"2027-12-31"}`))
	goodWaiver.Header.Set("X-Raksa-Token", "unit-test-token-123")
	gwResp, err := http.DefaultClient.Do(goodWaiver)
	if err != nil {
		t.Fatal(err)
	}
	var updated schema.SuiteReport
	_ = json.NewDecoder(gwResp.Body).Decode(&updated)
	gwResp.Body.Close()
	if gwResp.StatusCode != http.StatusOK || updated.Posture.Score != 100 || updated.Summary.Total != 0 {
		t.Fatalf("expected waived report score 100, got code=%d score=%d total=%d", gwResp.StatusCode, updated.Posture.Score, updated.Summary.Total)
	}

	// SIEM ingest succeeds via mock bridge
	ingReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/siem/ingest", strings.NewReader("{}"))
	ingReq.Header.Set("X-Raksa-Token", "unit-test-token-123")
	ingResp, err := http.DefaultClient.Do(ingReq)
	if err != nil {
		t.Fatal(err)
	}
	ingResp.Body.Close()
	if ingResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on SIEM ingest, got %d", ingResp.StatusCode)
	}

	// Assistant config & chat endpoints enforce auth + return grounded read-only reply
	astCfgReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/assistant/config", nil)
	astCfgReq.Header.Set("X-Raksa-Token", "unit-test-token-123")
	astCfgResp, err := http.DefaultClient.Do(astCfgReq)
	if err != nil || astCfgResp.StatusCode != http.StatusOK {
		t.Fatalf("assistant config failed: status=%v err=%v", astCfgResp, err)
	}
	astCfgResp.Body.Close()

	astChatReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/assistant/chat", strings.NewReader(`{"mode":"local","prompt":"Prioritize risks and check ledger"}`))
	astChatReq.Header.Set("X-Raksa-Token", "unit-test-token-123")
	astChatResp, err := http.DefaultClient.Do(astChatReq)
	if err != nil {
		t.Fatal(err)
	}
	var chatOut struct {
		ReadOnly  bool   `json:"read_only"`
		Reply     string `json:"reply"`
		ToolCalls []any  `json:"tool_calls"`
	}
	_ = json.NewDecoder(astChatResp.Body).Decode(&chatOut)
	astChatResp.Body.Close()
	if astChatResp.StatusCode != http.StatusOK || !chatOut.ReadOnly || len(chatOut.ToolCalls) < 2 {
		t.Fatalf("unexpected assistant chat output: code=%d body=%+v", astChatResp.StatusCode, chatOut)
	}
}
