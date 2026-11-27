package tui

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInteractiveTUIScriptedWorkflow(t *testing.T) {
	dir := t.TempDir()
	repPath := filepath.Join(dir, "fixture.json")
	raw := `{"schema_version":"1.0","tool":"raksa-pipeguard","layer":"devsecops","findings":[{"id":"p1","rule_id":"PIPE-001","layer":"devsecops","severity":"high","title":"Exposed token","description":"desc","target":"file://.env","mitre_d3fend":"D3-SYSV"}]}`
	if err := os.WriteFile(repPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	histPath := filepath.Join(t.TempDir(), "runs.ndjson")
	input := strings.NewReader("/matrix\n/ask prioritize top risk\n/verify\n0\n")
	var out bytes.Buffer

	err := Run(context.Background(), Options{
		Workspace:   dir,
		FromReports: repPath,
		HistoryPath: histPath,
	}, input, &out)
	if err != nil {
		t.Fatalf("tui.Run: %v", err)
	}

	txt := out.String()
	for _, want := range []string{
		"Raksa Interactive Defense Workbench",
		"╭",
		"╰",
		"D3-NTA",
		"PIPE-001",
		"History Ledger",
		"Exiting raksa interactive workbench",
	} {
		if !strings.Contains(txt, want) {
			t.Fatalf("expected %q in TUI output:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "\x1b[") {
		t.Fatalf("expected plain non-TTY buffer to omit ANSI escapes, got:\n%s", txt)
	}
}

func TestTUIRoundedTrueColorAndNoColor(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(t.TempDir(), "runs.ndjson")

	var colored bytes.Buffer
	if err := Run(context.Background(), Options{
		Workspace:   dir,
		HistoryPath: histPath,
		ForceColor:  true,
	}, strings.NewReader("0\n"), &colored); err != nil {
		t.Fatalf("tui.Run ForceColor: %v", err)
	}
	if !strings.Contains(colored.String(), "\x1b[38;2;") {
		t.Fatalf("expected TrueColor ANSI escape codes when ForceColor=true:\n%s", colored.String())
	}

	var plain bytes.Buffer
	if err := Run(context.Background(), Options{
		Workspace:   dir,
		HistoryPath: histPath,
		NoColor:     true,
		ForceColor:  true,
	}, strings.NewReader("0\n"), &plain); err != nil {
		t.Fatalf("tui.Run NoColor: %v", err)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Fatalf("expected NoColor=true to suppress ANSI escape codes:\n%s", plain.String())
	}
}

func TestTUISimpleModeGuideAndProToggle(t *testing.T) {
	dir := t.TempDir()
	repPath := filepath.Join(dir, "fixture.json")
	raw := `{"schema_version":"1.0","tool":"raksa-pipeguard","layer":"devsecops","findings":[{"id":"p1","rule_id":"PIPE-001","layer":"devsecops","severity":"critical","title":"Exposed API secret","remediation":"Move secret to vault.","target":"file://.env"}]}`
	if err := os.WriteFile(repPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	histPath := filepath.Join(t.TempDir(), "runs.ndjson")
	input := strings.NewReader("2\n4\n5\n0\n")
	var out bytes.Buffer

	if err := Run(context.Background(), Options{
		Workspace:   dir,
		FromReports: repPath,
		HistoryPath: histPath,
	}, input, &out); err != nil {
		t.Fatalf("tui.Run Simple->Pro: %v", err)
	}

	txt := out.String()
	for _, want := range []string{
		"Simple Quick Menu",
		"Scan Project Now",
		"Issues & Recommended Fixes",
		"Move secret to vault.",
		"Raksa Beginner Quick Guide",
		"Pro Workbench Commands (Hybrid L1-L7)",
	} {
		if !strings.Contains(txt, want) {
			t.Fatalf("expected %q in Simple/Guide/Pro TUI output:\n%s", want, txt)
		}
	}
}
