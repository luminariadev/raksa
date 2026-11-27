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
		"D3-NTA",
		"PIPE-001",
		"History Ledger",
		"Exiting raksa interactive workbench",
	} {
		if !strings.Contains(txt, want) {
			t.Fatalf("expected %q in TUI output:\n%s", want, txt)
		}
	}
}
