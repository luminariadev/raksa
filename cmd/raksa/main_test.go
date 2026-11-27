package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIScanFromReportsAndExitGates(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "testdata")
	hist := filepath.Join(t.TempDir(), "runs.ndjson")

	var out, errBuf bytes.Buffer
	code := run([]string{
		"scan",
		"--from-reports", filepath.Join(fixturesDir, "clean.json"),
		"--format", "json",
		"--fail-on", "low",
		"--history", hist,
	}, &out, &errBuf, strings.NewReader(""))
	if code != 0 {
		t.Fatalf("clean fixture failed with code %d: stderr=%s", code, errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"scan",
		"--from-reports", fixturesDir,
		"--format", "sarif",
		"--fail-on", "high",
		"--history", hist,
	}, &out, &errBuf, strings.NewReader(""))
	if code != 2 {
		t.Fatalf("expected exit code 2 on high findings, got %d: stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) {
		t.Fatalf("expected SARIF 2.1.0 output, got:\n%s", out.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"posture",
		"--history", hist,
		"--verify",
		"--format", "json",
	}, &out, &errBuf, strings.NewReader(""))
	if code != 0 {
		t.Fatalf("posture --verify failed: code=%d stderr=%s", code, errBuf.String())
	}
	var posturePayload struct {
		ChainEntries  int  `json:"chain_entries"`
		ChainVerified bool `json:"chain_verified"`
	}
	if err := json.Unmarshal(out.Bytes(), &posturePayload); err != nil {
		t.Fatal(err)
	}
	if !posturePayload.ChainVerified || posturePayload.ChainEntries != 2 {
		t.Fatalf("expected verified 2-entry chain, got %+v", posturePayload)
	}
}

func TestCLIInstallDryRunPlaybooksAndMCP(t *testing.T) {
	var out, errBuf bytes.Buffer

	if code := run([]string{"install", "--dry-run", "--layers", "netguard,pipeguard", "--format", "json"}, &out, &errBuf, strings.NewReader("")); code != 0 {
		t.Fatalf("install --dry-run failed: %s", errBuf.String())
	}
	if !strings.Contains(out.String(), "raksa-netguard") || !strings.Contains(out.String(), "SHA256SUMS.txt") {
		t.Fatalf("unexpected dry-run plan output: %s", out.String())
	}

	out.Reset()
	if code := run([]string{"playbooks", "list", "--format", "json"}, &out, &errBuf, strings.NewReader("")); code != 0 {
		t.Fatalf("playbooks list failed: %s", errBuf.String())
	}
	if !strings.Contains(out.String(), "ddos-readiness") {
		t.Fatalf("expected ddos-readiness playbook in output")
	}

	out.Reset()
	mcpInput := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n",
	)
	if code := run([]string{"mcp", "--history", filepath.Join(t.TempDir(), "runs.ndjson")}, &out, &errBuf, mcpInput); code != 0 {
		t.Fatalf("mcp failed: %s", errBuf.String())
	}
	if !strings.Contains(out.String(), "raksa_full_audit") || !strings.Contains(out.String(), "siem_verify_ledger") {
		t.Fatalf("expected federated tools in mcp output: %s", out.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"ui", "-h"}, &out, &errBuf, strings.NewReader("")); code != 0 {
		t.Fatalf("ui -h failed: code=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "-listen") || !strings.Contains(errBuf.String(), "-from-reports") {
		t.Fatalf("expected ui flags in help output, got: %s", errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	tuiInput := strings.NewReader("/matrix\n0\n")
	if code := run([]string{"tui", "--from-reports", filepath.Join("..", "..", "testdata", "clean.json"), "--history", filepath.Join(t.TempDir(), "runs.ndjson")}, &out, &errBuf, tuiInput); code != 0 {
		t.Fatalf("tui command failed: code=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Raksa Interactive Defense Workbench") || !strings.Contains(out.String(), "D3-NTA") {
		t.Fatalf("unexpected tui output: %s", out.String())
	}
}
