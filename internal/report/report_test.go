package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luminariadev/raksa/internal/schema"
)

func TestRenderAllFormatsAndHTMLEscaping(t *testing.T) {
	rep := schema.SuiteReport{
		SchemaVersion: "1.0",
		Tool:          "raksa",
		Version:       "0.1.0",
		Layer:         "orchestrator",
		Profile:       "full",
		Target:        ".",
		GeneratedAt:   "2026-11-27T12:00:00Z",
		Posture:       schema.PostureScore{Score: 75, Grade: "C"},
		Summary:       schema.Summary{Total: 1, Critical: 1},
		Layers: []schema.LayerExecution{
			{Layer: "pipeguard", Status: "findings", FindingsCount: 1, Posture: schema.PostureScore{Score: 75, Grade: "C"}},
		},
		Findings: []schema.Finding{
			{
				ID:          "f1",
				RuleID:      "PIPE-001",
				Layer:       "devsecops",
				Severity:    schema.SeverityCritical,
				Title:       "XSS-like title <script>alert(1)</script>",
				Description: "Secret leak detected",
				Target:      "file://.env",
				Remediation: "Revoke and move to secret store",
				MitreD3FEND: "D3-SYSV",
			},
		},
	}

	tbl, err := Render(rep, FormatTable)
	if err != nil || !strings.Contains(string(tbl), "PIPE-001") {
		t.Fatalf("table failed: %v", err)
	}
	md, err := Render(rep, FormatMarkdown)
	if err != nil || !strings.Contains(string(md), "Layer Breakdown (Hybrid Mode)") {
		t.Fatalf("markdown failed: %v", err)
	}
	sarifRaw, err := Render(rep, FormatSARIF)
	if err != nil {
		t.Fatalf("sarif failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(sarifRaw, &parsed); err != nil || parsed["version"] != "2.1.0" {
		t.Fatalf("invalid sarif json: %v", err)
	}
	htmlRaw, err := Render(rep, FormatHTML)
	if err != nil {
		t.Fatalf("html failed: %v", err)
	}
	htmlStr := string(htmlRaw)
	if strings.Contains(htmlStr, "<script>alert(1)</script>") || !strings.Contains(htmlStr, "&lt;script&gt;") {
		t.Fatal("expected HTML template auto-escaping on finding title")
	}
}
