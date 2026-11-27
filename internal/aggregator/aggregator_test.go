package aggregator

import (
	"testing"
	"time"

	"github.com/luminariadev/raksa/internal/policy"
)

func TestParseAndMergeDeduplicatesAndEnriches(t *testing.T) {
	raw1 := []byte(`{
		"schema_version": "1.0",
		"tool": "raksa-pipeguard",
		"layer": "devsecops",
		"findings": [
			{"id":"p1","rule_id":"PIPE-001","layer":"devsecops","severity":"critical","title":"Hardcoded key","description":"secret","target":"file://.env","mitre_d3fend":"D3-SYSV"},
			{"id":"p1-dup","rule_id":"PIPE-001","layer":"devsecops","severity":"critical","title":"Hardcoded key","description":"secret","target":"file://.env","mitre_d3fend":"D3-SYSV"}
		]
	}`)
	raw2 := []byte(`{"id":"h1","rule_id":"HOST-201","layer":"host-hardening","tool":"raksa-hostguard","severity":"medium","title":"Root USER in Dockerfile","description":"run as nonroot","target":"file://Dockerfile","mitre_d3fend":"D3-CISC"}` + "\n")

	r1, err := ParseReportBytes(raw1, "pipe.json")
	if err != nil {
		t.Fatalf("ParseReportBytes json: %v", err)
	}
	r2, err := ParseReportBytes(raw2, "host.ndjson")
	if err != nil {
		t.Fatalf("ParseReportBytes ndjson: %v", err)
	}

	merged := Merge([]UpstreamReport{r1, r2}, nil, MergeOptions{
		Profile: "repo",
		Target:  ".",
		Policy:  policy.DefaultConfig(),
		Now:     time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC),
	})

	if merged.DeduplicatedCount != 1 {
		t.Fatalf("expected 1 duplicate removed, got %d", merged.DeduplicatedCount)
	}
	if merged.Summary.Total != 2 || merged.Summary.Critical != 1 || merged.Summary.Medium != 1 {
		t.Fatalf("unexpected merged summary: %+v", merged.Summary)
	}
	if merged.Posture.Score != 68 || merged.Posture.Grade != "D" {
		t.Fatalf("expected posture 68 (D), got %+v", merged.Posture)
	}
	if merged.Findings[0].RuleID != "PIPE-001" || len(merged.Findings[0].Compliance) == 0 {
		t.Fatalf("expected sorted + compliance-enriched findings: %+v", merged.Findings)
	}
}
