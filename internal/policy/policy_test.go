package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luminariadev/raksa/internal/schema"
)

func TestWaiversFailClosedAndExpiration(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	findings := []schema.Finding{
		{ID: "1", RuleID: "NET-002", Layer: "network-defense", Target: "tcp://127.0.0.1:8484", Severity: schema.SeverityMedium},
		{ID: "2", RuleID: "PIPE-001", Layer: "devsecops", Target: "file://secrets.env", Severity: schema.SeverityCritical},
	}
	waivers := []Waiver{
		{RuleID: "NET-002", TargetContains: "127.0.0.1:8484", Reason: "Authorized dev SIEM", ExpiresOn: "2027-01-01"},
		{RuleID: "PIPE-001", Reason: "Expired waiver", ExpiresOn: "2025-01-01"},
		{RuleID: "PIPE-001", Reason: "", ExpiresOn: "2027-01-01"},
	}

	remaining, suppressed := ApplyWaivers(findings, waivers, now)
	if suppressed != 1 || len(remaining) != 1 || remaining[0].RuleID != "PIPE-001" {
		t.Fatalf("unexpected waiver filtering: suppressed=%d remaining=%+v", suppressed, remaining)
	}
}

func TestConfigValidationRejectsIncompleteWaiver(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".raksa.yml")
	bad := "profile: full\nwaivers:\n  - rule_id: HOST-101\n    expires_on: 2027-01-01\n"
	if err := os.WriteFile(cfgPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected missing waiver reason to fail validation")
	}
}

func TestBaselineRoundtripAndSuppression(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "baseline.json")
	findings := []schema.Finding{
		{ID: "a", RuleID: "HOST-101", Layer: "host-hardening", Target: "file:///etc/ssh/sshd_config", Title: "SSH root login", Severity: schema.SeverityCritical},
		{ID: "b", RuleID: "WEB-001", Layer: "web-defense", Target: "https://example.test", Title: "Missing HSTS", Severity: schema.SeverityMedium},
	}
	b := BuildBaseline(findings[:1], time.Now())
	if err := SaveBaseline(basePath, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	loaded, err := LoadBaseline(basePath)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	remaining, baselined := ApplyBaseline(findings, loaded)
	if baselined != 1 || len(remaining) != 1 || remaining[0].RuleID != "WEB-001" {
		t.Fatalf("unexpected baseline result: baselined=%d remaining=%+v", baselined, remaining)
	}
}
