package schema

import "testing"

func TestCatalogCountsAndAliases(t *testing.T) {
	rules, mcpTools := TotalCatalogCounts()
	if rules != 152 {
		t.Fatalf("expected 152 total rules across L1-L6, got %d", rules)
	}
	if mcpTools != 53 {
		t.Fatalf("expected 53 L1-L6 MCP tools, got %d", mcpTools)
	}

	aliases := map[string]string{
		"L1":                 "netguard",
		"raksa-hostguard":    "hostguard",
		"web-defense":        "webshield",
		"4":                  "pipeguard",
		"iocscan":            "iocscan",
		"observability-siem": "siem",
	}
	for input, want := range aliases {
		got, ok := ParseLayerAlias(input)
		if !ok || got != want {
			t.Fatalf("ParseLayerAlias(%q) = (%q, %v), want (%q, true)", input, got, ok, want)
		}
	}
	if _, ok := ParseLayerAlias("unknown"); ok {
		t.Fatal("expected unknown layer alias to fail")
	}
}

func TestPostureSummaryAndThreshold(t *testing.T) {
	findings := []Finding{
		{ID: "1", RuleID: "PIPE-001", Layer: "devsecops", Severity: SeverityHigh},
		{ID: "2", RuleID: "HOST-201", Layer: "host-hardening", Severity: SeverityMedium},
		{ID: "3", RuleID: "WEB-004", Layer: "web-defense", Severity: SeverityLow},
		{ID: "4", RuleID: "NET-004", Layer: "network-defense", Severity: SeverityInfo},
	}
	sum := BuildSummary(findings)
	if sum.Total != 4 || sum.Critical != 0 || sum.High != 1 || sum.Medium != 1 || sum.Low != 1 || sum.Info != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	posture := ComputePosture(findings)
	if posture.Score != 75 || posture.Grade != "C" {
		t.Fatalf("expected score 75 (C), got %+v", posture)
	}
	if !MeetsThreshold(findings, SeverityHigh) {
		t.Fatal("expected MeetsThreshold high to be true")
	}
	if MeetsThreshold(findings, SeverityCritical) {
		t.Fatal("expected MeetsThreshold critical to be false")
	}
	if MeetsThreshold(findings, SeverityNone) {
		t.Fatal("expected MeetsThreshold none to be false")
	}
}

func TestAttackDefenseMatrixNonEmpty(t *testing.T) {
	rows := AttackDefenseMatrix()
	if len(rows) < 12 {
		t.Fatalf("expected at least 12 attack-defense rows, got %d", len(rows))
	}
	for _, r := range rows {
		if r.Category == "" || r.MitreD3FEND == "" || len(r.Layers) == 0 {
			t.Fatalf("incomplete matrix row: %+v", r)
		}
	}
}
