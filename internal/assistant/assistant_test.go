package assistant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luminariadev/raksa/internal/schema"
)

func TestOfflineDeterministicAssistantAndCitations(t *testing.T) {
	ctx := InputContext{
		Report: schema.SuiteReport{
			Posture: schema.PostureScore{Score: 58, Grade: "D"},
			Summary: schema.Summary{Total: 2, Critical: 1, High: 1},
			Findings: []schema.Finding{
				{ID: "1", RuleID: "PIPE-001", Layer: "devsecops", Severity: schema.SeverityCritical, Title: "Exposed token", Target: "file://.env", Remediation: "Revoke key"},
				{ID: "2", RuleID: "HOST-101", Layer: "host-hardening", Severity: schema.SeverityHigh, Title: "SSH root login", Target: "file:///etc/ssh/sshd_config", Remediation: "Set PermitRootLogin no"},
			},
		},
		HistoryPath: t.TempDir() + "/runs.ndjson",
	}

	res, err := Chat(context.Background(), ctx, ChatRequest{
		Mode:   "local",
		Prompt: "Prioritize top risks, verify ledger, and show attack gaps",
	})
	if err != nil {
		t.Fatalf("Chat local: %v", err)
	}
	if !res.ReadOnly || len(res.ToolCalls) < 3 {
		t.Fatalf("expected read-only response with tool calls, got %+v", res)
	}
	if !strings.Contains(res.Reply, "PIPE-001") || !strings.Contains(res.Reply, "Attack-vs-Defense Matrix Gaps") {
		t.Fatalf("unexpected reply:\n%s", res.Reply)
	}
}

func TestOllamaAndBYOKModesWithoutSecretLeak(t *testing.T) {
	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"message":{"content":"Patch HOST-101 first."}}`))
	}))
	defer ollamaSrv.Close()

	byokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer top-secret-byok-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Revoke token and verify ledger."}}]}`))
	}))
	defer byokSrv.Close()

	in := InputContext{HistoryPath: t.TempDir() + "/runs.ndjson"}

	if _, err := Chat(context.Background(), in, ChatRequest{Mode: "ollama", Endpoint: "ftp://bad.host", Prompt: "help"}); err == nil {
		t.Fatal("expected ftp:// scheme rejection")
	}

	olRes, err := Chat(context.Background(), in, ChatRequest{
		Mode:     "ollama",
		Endpoint: ollamaSrv.URL,
		Model:    "llama3.2",
		Prompt:   "What next?",
	})
	if err != nil || !strings.Contains(olRes.Reply, "HOST-101") {
		t.Fatalf("Ollama chat failed: res=%+v err=%v", olRes, err)
	}

	t.Setenv(EnvAIAPIKey, "top-secret-byok-key")
	t.Setenv(EnvAIEndpoint, byokSrv.URL)
	t.Setenv(EnvAIModel, "raksa-test-model")
	byokRes, err := Chat(context.Background(), in, ChatRequest{
		Mode:   "byok",
		Prompt: "Summarize remediation",
	})
	if err != nil || !strings.Contains(byokRes.Reply, "Revoke token") {
		t.Fatalf("BYOK chat failed: res=%+v err=%v", byokRes, err)
	}
	rawJSON, _ := json.Marshal(byokRes)
	if strings.Contains(string(rawJSON), "top-secret-byok-key") {
		t.Fatal("API key must never appear in serialized ChatResponse")
	}
}
