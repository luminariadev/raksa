// Package main implements the Layer 7 raksa CLI orchestrator and federated 61-tool MCP server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/luminariadev/raksa/internal/aggregator"
	"github.com/luminariadev/raksa/internal/bridge"
	"github.com/luminariadev/raksa/internal/ext"
	"github.com/luminariadev/raksa/internal/mcphub"
	"github.com/luminariadev/raksa/internal/playbook"
	"github.com/luminariadev/raksa/internal/policy"
	"github.com/luminariadev/raksa/internal/remediate"
	"github.com/luminariadev/raksa/internal/report"
	"github.com/luminariadev/raksa/internal/runner"
	"github.com/luminariadev/raksa/internal/schema"
	"github.com/luminariadev/raksa/internal/server"
	"github.com/luminariadev/raksa/internal/store"
	"github.com/luminariadev/raksa/internal/tui"
)

const (
	exitOK     = 0
	exitErr    = 1
	exitBreach = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin))
}

func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stdout)
		return exitOK
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "doctor":
		return runDoctor(rest, stdout, stderr)
	case "install":
		return runInstall(rest, stdout, stderr)
	case "scan":
		return runScan(rest, stdout, stderr)
	case "posture":
		return runPosture(rest, stdout, stderr)
	case "fix-preview":
		return runFixPreview(rest, stdout, stderr)
	case "playbooks":
		return runPlaybooks(rest, stdout, stderr)
	case "attack-matrix":
		return runAttackMatrix(rest, stdout, stderr)
	case "mcp":
		return runMCP(rest, stdout, stderr, stdin)
	case "ui", "serve":
		return runUI(rest, stdout, stderr)
	case "tui":
		return runTUI(rest, stdout, stderr, stdin)
	case "init":
		return runInit(rest, stdout, stderr)
	case "version", "-v", "--version":
		return runVersion(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n\n", cmd)
		printUsage(stderr)
		return exitErr
	}
}

func printUsage(w io.Writer) {
	rulesCount, mcpCount := schema.TotalCatalogCounts()
	fmt.Fprintf(w, `raksa v%s - Hybrid Blue Team Orchestrator & Unified Security Workbench (Layer 7)
Covers Layers 1-6 (%d built-in rules | %d L1-L6 + 8 L7 = %d federated MCP tools)

Usage:
  raksa <subcommand> [flags]

Subcommands:
  doctor         Inspect Layer 1-6 binary availability, versions, and SHA-256 digests
  install        Download and SHA-256 verify Layer 1-6 release binaries (--dry-run supported)
  scan           Run Hybrid L1-L6 audit or aggregate upstream reports (--from-reports)
  posture        Show historical posture runs and verify SHA-256 hash-chained run ledger
  fix-preview    Aggregate read-only unified remediation diffs from Layer 2-4 tools
  playbooks      List, verify, or execute curated defensive YAML playbooks
  attack-matrix  Print Attack-vs-Defense countermeasure coverage across Raksa layers
  ui             Launch embedded 3-panel Hybrid Web Workbench server (alias: serve)
  tui            Launch interactive terminal Blue Team workbench (SSH/headless friendly)
  mcp            Start unified stdio JSON-RPC 2.0 MCP hub (%d tools)
  init           Generate starter .raksa.yml governance config
  version        Print build, schema, and Open-Core edition metadata

Exit codes:
  0  Clean / within --fail-on gate
  1  Configuration, CLI usage, or runtime error
  2  Findings equal or exceed --fail-on threshold
`, schema.Version, rulesCount, mcpCount, mcpCount+8, mcpCount+8)
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	formatStr := fs.String("format", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	ed := ext.DefaultEdition()
	rulesCount, mcpCount := schema.TotalCatalogCounts()
	if strings.EqualFold(*formatStr, "json") {
		payload := map[string]any{
			"tool":           schema.ToolName,
			"version":        schema.Version,
			"commit":         schema.Commit,
			"build_date":     schema.BuildDate,
			"schema_version": schema.SchemaVersion,
			"layer":          schema.LayerName,
			"edition":        ed,
			"upstream_rules": rulesCount,
			"mcp_tools":      mcpCount + 8,
		}
		raw, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Fprintln(stdout, string(raw))
		return exitOK
	}
	fmt.Fprintf(stdout, "raksa v%s (schema=%s, layer=%s, edition=%s/%s, commit=%s)\n",
		schema.Version, schema.SchemaVersion, schema.LayerName, ed.Edition, ed.License, schema.Commit)
	return exitOK
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	binDir := fs.String("bin-dir", "", "Optional directory containing Raksa Layer 1-6 binaries")
	formatStr := fs.String("format", "table", "Output format: table or json")
	strict := fs.Bool("strict", false, "Exit with code 1 if any Layer 1-6 binary is missing")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	statuses := runner.Doctor(context.Background(), *binDir, nil, nil)
	if strings.EqualFold(*formatStr, "json") {
		raw, _ := json.MarshalIndent(map[string]any{
			"raksa_version": schema.Version,
			"tools":         statuses,
		}, "", "  ")
		fmt.Fprintln(stdout, string(raw))
	} else {
		fmt.Fprintf(stdout, "Raksa Toolchain Doctor (v%s)\n\n", schema.Version)
		for _, st := range statuses {
			ver := st.Version
			if ver == "" {
				ver = "-"
			}
			fmt.Fprintf(stdout, "L%d %-10s %-16s status=%-8s rules=%2d mcp=%2d ver=%s\n",
				st.Number, st.ID, st.Binary, st.Status, st.RuleCount, st.MCPCount, ver)
			if st.Path != "" {
				fmt.Fprintf(stdout, "   path: %s (sha256: %s)\n", st.Path, st.SHA256)
			} else if st.Hint != "" {
				fmt.Fprintf(stdout, "   hint: %s\n", st.Hint)
			}
		}
	}

	if *strict {
		for _, st := range statuses {
			if !st.Installed {
				return exitErr
			}
		}
	}
	return exitOK
}

func runInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	layersFlag := fs.String("layers", "", "Comma-separated layers to install (defaults to Go/Rust CLI binaries)")
	destDir := fs.String("dest", runner.DefaultBinDir(), "Destination directory for verified binaries")
	dryRun := fs.Bool("dry-run", false, "Resolve download URLs and checksums without downloading")
	formatStr := fs.String("format", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	var layerList []string
	if strings.TrimSpace(*layersFlag) != "" {
		layerList = strings.Split(*layersFlag, ",")
	}
	plan, err := runner.PlanInstall(layerList, *destDir, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	if *dryRun {
		if strings.EqualFold(*formatStr, "json") {
			raw, _ := json.MarshalIndent(map[string]any{"dry_run": true, "plan": plan}, "", "  ")
			fmt.Fprintln(stdout, string(raw))
			return exitOK
		}
		fmt.Fprintln(stdout, "Raksa Install Plan (dry-run):")
		for _, item := range plan {
			fmt.Fprintf(stdout, "  %-10s %s -> %s\n    archive:  %s\n    checksum: %s\n",
				item.Layer, item.Version, item.DestPath, item.ArchiveURL, item.ChecksumURL)
		}
		return exitOK
	}

	for _, item := range plan {
		fmt.Fprintf(stdout, "Installing %s %s -> %s ...\n", item.Binary, item.Version, item.DestPath)
		if err := runner.InstallBinaryArchive(context.Background(), item); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitErr
		}
		fmt.Fprintf(stdout, "Verified SHA-256 and installed %s\n", item.DestPath)
	}
	return exitOK
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("path", ".", "Workspace or host target path")
	profile := fs.String("profile", "", "Scan profile: full, repo, host, web, incident")
	layersFlag := fs.String("layers", "", "Comma-separated explicit layer IDs (Hybrid modular mode)")
	fromReports := fs.String("from-reports", "", "Aggregate existing Layer 1-6 JSON/NDJSON reports instead of invoking tools")
	netPolicy := fs.String("net-policy", "", "Optional Layer 1 netguard baseline YAML policy")
	netLog := fs.String("net-log", "", "Optional Layer 1 firewall/flow log file")
	webURL := fs.String("url", "", "Optional read-only HTTP/HTTPS URL for Layer 3 audit-headers")
	policyPath := fs.String("policy", "", "Path to .raksa.yml config (auto-discovers if omitted)")
	baselinePath := fs.String("baseline", "", "Suppress known findings recorded in baseline JSON")
	writeBaseline := fs.String("write-baseline", "", "Write active findings baseline JSON snapshot")
	formatFlag := fs.String("format", "table", "Output format: table, json, sarif, markdown, html")
	failOnFlag := fs.String("fail-on", "", "Severity gate for exit code 2 (critical, high, medium, low, info, none)")
	outputPath := fs.String("output", "", "Write formatted report to file instead of stdout")
	siemURL := fs.String("siem-url", "", "Optional Layer 6 raksa-siem HTTP endpoint for auto-ingest")
	historyPath := fs.String("history", store.DefaultHistoryPath(), "Path to SHA-256 hash-chained runs.ndjson")
	noHistory := fs.Bool("no-history", false, "Skip appending this run to local runs.ndjson")
	binDir := fs.String("bin-dir", "", "Optional extra directory to search for Layer 1-6 binaries")

	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	outFmt, err := report.ParseFormat(*formatFlag)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	cfg, _, err := policy.Discover(*target, *policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	failRaw := cfg.FailOn
	if strings.TrimSpace(*failOnFlag) != "" {
		failRaw = *failOnFlag
	}
	failOn, err := schema.ParseSeverity(failRaw)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	var basePtr *policy.Baseline
	if strings.TrimSpace(*baselinePath) != "" {
		loaded, loadErr := policy.LoadBaseline(*baselinePath)
		if loadErr != nil {
			fmt.Fprintf(stderr, "error: %v\n", loadErr)
			return exitErr
		}
		basePtr = &loaded
	}

	var ups []aggregator.UpstreamReport
	var execs []schema.LayerExecution
	usedProfile := *profile
	if usedProfile == "" {
		usedProfile = cfg.Profile
	}

	if strings.TrimSpace(*fromReports) != "" {
		ups, err = aggregator.LoadReportsFromPath(*fromReports)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitErr
		}
		if *profile == "" {
			usedProfile = "aggregated"
		}
	} else {
		var explicit []string
		if strings.TrimSpace(*layersFlag) != "" {
			explicit = []string{*layersFlag}
		}
		ups, execs, err = runner.RunSuite(context.Background(), runner.SuiteRequest{
			Profile:        usedProfile,
			ExplicitLayers: explicit,
			Target:         *target,
			NetPolicy:      *netPolicy,
			NetLog:         *netLog,
			WebURL:         *webURL,
			BinDir:         *binDir,
			Policy:         cfg,
		}, nil, nil)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitErr
		}
	}

	rep := aggregator.Merge(ups, execs, aggregator.MergeOptions{
		Profile:  usedProfile,
		Target:   *target,
		Policy:   cfg,
		Baseline: basePtr,
		Now:      time.Now().UTC(),
	})

	if strings.TrimSpace(*writeBaseline) != "" {
		snap := policy.BuildBaseline(rep.Findings, time.Now().UTC())
		if err := policy.SaveBaseline(*writeBaseline, snap); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitErr
		}
	}

	ingestTarget := strings.TrimSpace(*siemURL)
	if ingestTarget == "" && cfg.SIEM.AutoIngest {
		ingestTarget = cfg.SIEM.Endpoint
	}
	if ingestTarget != "" {
		token := ""
		if cfg.SIEM.TokenEnv != "" {
			token = os.Getenv(cfg.SIEM.TokenEnv)
		}
		client, clientErr := bridge.NewClient(ingestTarget, token, 10*time.Second)
		if clientErr != nil {
			fmt.Fprintf(stderr, "error: %v\n", clientErr)
			return exitErr
		}
		if _, ingestErr := client.IngestReport(context.Background(), rep); ingestErr != nil {
			fmt.Fprintf(stderr, "error: SIEM ingest failed: %v\n", ingestErr)
			return exitErr
		}
		rep.SIEMIngested = true
	}

	if !*noHistory && strings.TrimSpace(*historyPath) != "" {
		if _, histErr := store.Open(*historyPath).Append(rep); histErr != nil {
			fmt.Fprintf(stderr, "warning: could not record history: %v\n", histErr)
		}
	}

	rendered, err := report.Render(rep, outFmt)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	if err := writeOutput(rendered, *outputPath, stdout); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	if schema.MeetsThreshold(rep.Findings, failOn) {
		return exitBreach
	}
	return exitOK
}

func runPosture(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	historyPath := fs.String("history", store.DefaultHistoryPath(), "Path to SHA-256 hash-chained runs.ndjson")
	limit := fs.Int("limit", 10, "Maximum recent runs to display")
	verify := fs.Bool("verify", false, "Verify SHA-256 hash chain integrity across all records")
	formatStr := fs.String("format", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	st := store.Open(*historyPath)
	count, ok, reason, err := st.VerifyChain()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}
	runs, err := st.List(*limit)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}

	if strings.EqualFold(*formatStr, "json") {
		raw, _ := json.MarshalIndent(map[string]any{
			"history_path":   *historyPath,
			"chain_entries":  count,
			"chain_verified": ok,
			"chain_reason":   reason,
			"runs":           runs,
		}, "", "  ")
		fmt.Fprintln(stdout, string(raw))
	} else {
		fmt.Fprintf(stdout, "Raksa Posture History (%s) | chain: %d entries (%s)\n\n", *historyPath, count, reason)
		for _, r := range runs {
			fmt.Fprintf(stdout, "  #%d %s profile=%-10s score=%3d (%-2s) findings=%d target=%s\n",
				r.Seq, r.Timestamp, r.Profile, r.Posture.Score, r.Posture.Grade, r.Summary.Total, r.Target)
		}
		if len(runs) == 0 {
			fmt.Fprintln(stdout, "  No scan history recorded yet. Run 'raksa scan' first.")
		}
	}

	if *verify && !ok {
		return exitErr
	}
	return exitOK
}

func runFixPreview(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix-preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("path", ".", "File or workspace directory to generate read-only hardening patches for")
	formatStr := fs.String("format", "diff", "Output format: diff or json")
	outputPath := fs.String("output", "", "Write preview to file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	res := remediate.CollectFixPreviews(context.Background(), *target, nil)
	rendered, err := remediate.FormatDiff(res, *formatStr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}
	if err := writeOutput([]byte(rendered), *outputPath, stdout); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitErr
	}
	return exitOK
}

func runPlaybooks(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "list" {
		fs := flag.NewFlagSet("playbooks list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		formatStr := fs.String("format", "table", "Output format: table or json")
		rest := args
		if len(args) > 0 && args[0] == "list" {
			rest = args[1:]
		}
		if err := fs.Parse(rest); err != nil {
			return exitErr
		}
		pbs, err := playbook.ListBuiltins()
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitErr
		}
		if strings.EqualFold(*formatStr, "json") {
			raw, _ := json.MarshalIndent(map[string]any{"playbooks": pbs}, "", "  ")
			fmt.Fprintln(stdout, string(raw))
			return exitOK
		}
		fmt.Fprintln(stdout, "Curated Raksa Defensive Playbooks:")
		for _, pb := range pbs {
			fmt.Fprintf(stdout, "  %-22s layers=%-34s fail_on=%s\n    %s\n",
				pb.Name, strings.Join(pb.Layers, ","), pb.FailOn, pb.Description)
		}
		return exitOK
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "verify":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "error: playbooks verify requires a YAML file path")
			return exitErr
		}
		pb, err := playbook.LoadFile(rest[0])
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitErr
		}
		fmt.Fprintf(stdout, "Valid playbook %q (%d steps, layers: %s)\n", pb.Name, len(pb.Steps), strings.Join(pb.Layers, ", "))
		return exitOK
	case "run":
		fs := flag.NewFlagSet("playbooks run", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "Built-in playbook name")
		filePath := fs.String("file", "", "Custom playbook YAML file path")
		target := fs.String("path", ".", "Workspace target path")
		formatStr := fs.String("format", "table", "Output format: table, json, sarif, markdown, html")
		noHistory := fs.Bool("no-history", false, "Skip appending to local runs.ndjson")
		if err := fs.Parse(rest); err != nil {
			return exitErr
		}
		var pb playbook.Playbook
		var err error
		if strings.TrimSpace(*filePath) != "" {
			pb, err = playbook.LoadFile(*filePath)
		} else if strings.TrimSpace(*name) != "" {
			pb, err = playbook.ResolveBuiltin(*name)
		} else {
			fmt.Fprintln(stderr, "error: playbooks run requires --name or --file")
			return exitErr
		}
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitErr
		}
		scanArgs := []string{
			"--path", *target,
			"--layers", strings.Join(pb.Layers, ","),
			"--profile", pb.Name,
			"--fail-on", pb.FailOn,
			"--format", *formatStr,
		}
		if *noHistory {
			scanArgs = append(scanArgs, "--no-history")
		}
		return runScan(scanArgs, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown playbooks action %q (expected list, verify, run)\n", sub)
		return exitErr
	}
}

func runAttackMatrix(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attack-matrix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	statusFilter := fs.String("status", "", "Filter by coverage status: covered, partial, planned")
	formatStr := fs.String("format", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	rows := schema.AttackDefenseMatrix()
	if f := strings.ToLower(strings.TrimSpace(*statusFilter)); f != "" {
		filtered := make([]schema.AttackCoverageRow, 0, len(rows))
		for _, r := range rows {
			if r.Status == f {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}

	if strings.EqualFold(*formatStr, "json") {
		raw, _ := json.MarshalIndent(map[string]any{"matrix": rows}, "", "  ")
		fmt.Fprintln(stdout, string(raw))
		return exitOK
	}
	fmt.Fprintln(stdout, "Raksa Attack-vs-Defense Coverage Matrix:")
	for _, r := range rows {
		fmt.Fprintf(stdout, "  [%-7s] %-42s ATT&CK=%-14s D3FEND=%-8s layers=%s\n",
			r.Status, r.Category, r.MitreAttack, r.MitreD3FEND, strings.Join(r.Layers, ","))
	}
	return exitOK
}

func runMCP(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	binDir := fs.String("bin-dir", "", "Optional directory containing Raksa Layer 1-6 binaries")
	historyPath := fs.String("history", store.DefaultHistoryPath(), "Path to runs.ndjson")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	hub := mcphub.NewHub(*binDir, *historyPath)
	if err := hub.ServeStreams(stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "error: mcp server failed: %v\n", err)
		return exitErr
	}
	return exitOK
}

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPath := fs.String("out", policy.DefaultConfigFilename, "Destination .raksa.yml path")
	force := fs.Bool("force", false, "Overwrite existing configuration file")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if !*force {
		if _, err := os.Stat(*outPath); err == nil {
			fmt.Fprintf(stderr, "error: %s already exists (pass --force to overwrite)\n", *outPath)
			return exitErr
		}
	}
	starter := `# Raksa Layer 7 Hybrid Suite Configuration
profile: full
fail_on: high
per_layer_timeout_sec: 120
max_concurrency: 4

enabled_layers: []
disabled_layers: []

siem:
  endpoint: http://127.0.0.1:8484
  token_env: RAKSA_SIEM_TOKEN
  auto_ingest: false

waivers: []
`
	if err := os.WriteFile(*outPath, []byte(starter), 0o600); err != nil {
		fmt.Fprintf(stderr, "error: write %s: %v\n", *outPath, err)
		return exitErr
	}
	fmt.Fprintf(stdout, "Wrote starter %s\n", *outPath)
	return exitOK
}

func runUI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listenAddr := fs.String("listen", "127.0.0.1:8787", "HTTP bind address for Raksa Web Workbench")
	workspace := fs.String("path", ".", "Workspace directory path")
	fromReports := fs.String("from-reports", "", "Optional initial upstream reports file/directory")
	binDir := fs.String("bin-dir", "", "Optional directory containing Layer 1-6 binaries")
	historyPath := fs.String("history", store.DefaultHistoryPath(), "Path to SHA-256 hash-chained runs.ndjson")
	siemURL := fs.String("siem-url", "", "Optional raksa-siem HTTP endpoint")
	tokenEnv := fs.String("token-env", "", "Optional environment variable supplying UI auth token")
	noAuth := fs.Bool("no-auth", false, "Disable token/cookie auth (intended only for isolated local CI checks)")
	noOpen := fs.Bool("no-open", false, "Do not auto-open the system browser")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitErr
	}

	var initToken string
	if strings.TrimSpace(*tokenEnv) != "" {
		initToken = strings.TrimSpace(os.Getenv(*tokenEnv))
	}

	srv, err := server.New(server.Config{
		ListenAddr:  *listenAddr,
		Workspace:   *workspace,
		FromReports: *fromReports,
		BinDir:      *binDir,
		HistoryPath: *historyPath,
		SIEMURL:     *siemURL,
		Token:       initToken,
		NoAuth:      *noAuth,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: initialize UI server: %v\n", err)
		return exitErr
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		fmt.Fprintf(stderr, "error: listen on %s: %v\n", *listenAddr, err)
		return exitErr
	}

	baseURL := "http://" + ln.Addr().String()
	launchURL := baseURL
	if !*noAuth && srv.Token() != "" {
		launchURL = baseURL + "/?token=" + srv.Token()
	}

	fmt.Fprintf(stdout, "Raksa Hybrid Web Workbench v%s listening on %s\n", schema.Version, baseURL)
	if !*noAuth && srv.Token() != "" {
		fmt.Fprintf(stdout, "Open: %s\n", launchURL)
	}
	if !*noOpen {
		openBrowserURL(launchURL)
	}

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if serveErr := httpSrv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			fmt.Fprintf(stderr, "error: HTTP server failed: %v\n", serveErr)
			return exitErr
		}
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = httpSrv.Shutdown(shCtx)
		cancel()
	}
	return exitOK
}

func openBrowserURL(targetURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	case "darwin":
		cmd = exec.Command("open", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	_ = cmd.Start()
}

func runTUI(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	workspace := fs.String("path", ".", "Workspace directory path")
	fromReports := fs.String("from-reports", "", "Optional initial upstream reports file/directory")
	binDir := fs.String("bin-dir", "", "Optional directory containing Layer 1-6 binaries")
	historyPath := fs.String("history", store.DefaultHistoryPath(), "Path to SHA-256 hash-chained runs.ndjson")
	siemURL := fs.String("siem-url", "", "Optional raksa-siem HTTP endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitErr
	}

	if err := tui.Run(context.Background(), tui.Options{
		Workspace:   *workspace,
		FromReports: *fromReports,
		BinDir:      *binDir,
		HistoryPath: *historyPath,
		SIEMURL:     *siemURL,
	}, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "error: tui failed: %v\n", err)
		return exitErr
	}
	return exitOK
}

func writeOutput(data []byte, outputPath string, stdout io.Writer) error {
	if strings.TrimSpace(outputPath) != "" {
		if parent := filepath.Dir(outputPath); parent != "." && parent != "" {
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}
		}
		return os.WriteFile(outputPath, data, 0o600)
	}
	_, err := stdout.Write(data)
	return err
}
