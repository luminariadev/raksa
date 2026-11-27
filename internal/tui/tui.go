// Package tui implements the interactive zero-dependency terminal Blue Team workbench (raksa tui).
package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luminariadev/raksa/internal/aggregator"
	"github.com/luminariadev/raksa/internal/assistant"
	"github.com/luminariadev/raksa/internal/playbook"
	"github.com/luminariadev/raksa/internal/policy"
	"github.com/luminariadev/raksa/internal/remediate"
	"github.com/luminariadev/raksa/internal/report"
	"github.com/luminariadev/raksa/internal/runner"
	"github.com/luminariadev/raksa/internal/schema"
	"github.com/luminariadev/raksa/internal/store"
)

// Options configures the interactive terminal workbench session.
type Options struct {
	Workspace   string
	FromReports string
	BinDir      string
	HistoryPath string
	SIEMURL     string
	Resolver    runner.BinaryResolver
	Exec        runner.CommandRunner
	Remediate   remediate.Executor
}

// Run launches an interactive menu and slash-command workbench loop on stdin/stdout.
func Run(ctx context.Context, opts Options, stdin io.Reader, stdout io.Writer) error {
	if strings.TrimSpace(opts.Workspace) == "" {
		opts.Workspace = "."
	}
	if strings.TrimSpace(opts.HistoryPath) == "" {
		opts.HistoryPath = store.DefaultHistoryPath()
	}

	active, err := loadInitialReport(opts)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 0, 16*1024), 256*1024)

	printBanner(stdout, active, opts.Workspace)
	printMenu(stdout)

	for {
		fmt.Fprintf(stdout, "\nraksa [%d/100 %s]> ", active.Posture.Score, active.Posture.Grade)
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		cmd, arg := splitCommand(line)
		switch cmd {
		case "0", "/quit", "/exit", "quit", "exit":
			fmt.Fprintln(stdout, "Exiting raksa interactive workbench.")
			return nil
		case "help", "/help", "?":
			printMenu(stdout)
		case "1", "/scan":
			profile := arg
			if profile == "" {
				profile = "full"
			}
			active = runAuditAction(ctx, opts, profile, nil, stdout)
		case "2", "/layers":
			if arg == "" {
				fmt.Fprint(stdout, "Enter layers (e.g. netguard,hostguard,pipeguard): ")
				if !scanner.Scan() {
					return nil
				}
				arg = strings.TrimSpace(scanner.Text())
			}
			if arg == "" {
				fmt.Fprintln(stdout, "Skipped: no layers entered.")
				continue
			}
			active = runAuditAction(ctx, opts, "hybrid-layers", strings.Split(arg, ","), stdout)
		case "3", "/playbooks", "/playbook":
			pbs, err := playbook.ListBuiltins()
			if err != nil {
				fmt.Fprintf(stdout, "error: %v\n", err)
				continue
			}
			if arg == "" {
				fmt.Fprintln(stdout, "Available Playbooks:")
				for _, pb := range pbs {
					fmt.Fprintf(stdout, "  - %-22s layers=%s\n", pb.Name, strings.Join(pb.Layers, ","))
				}
				fmt.Fprint(stdout, "Run playbook name (blank to cancel): ")
				if !scanner.Scan() {
					return nil
				}
				arg = strings.TrimSpace(scanner.Text())
			}
			if arg == "" {
				continue
			}
			pb, err := playbook.ResolveBuiltin(arg)
			if err != nil {
				fmt.Fprintf(stdout, "error: %v\n", err)
				continue
			}
			active = runAuditAction(ctx, opts, pb.Name, pb.Layers, stdout)
		case "4", "/doctor":
			statuses := runner.Doctor(ctx, opts.BinDir, opts.Resolver, opts.Exec)
			for _, st := range statuses {
				fmt.Fprintf(stdout, "  L%d %-10s status=%-8s rules=%2d mcp=%2d %s\n",
					st.Number, st.ID, st.Status, st.RuleCount, st.MCPCount, st.Hint)
			}
		case "5", "/matrix":
			rows := schema.AttackDefenseMatrix()
			for _, r := range rows {
				fmt.Fprintf(stdout, "  [%-7s] %-40s D3FEND=%-8s layers=%s\n",
					r.Status, r.Category, r.MitreD3FEND, strings.Join(r.Layers, ","))
			}
		case "6", "/fix":
			res := remediate.CollectFixPreviews(ctx, opts.Workspace, opts.Remediate)
			rendered, _ := remediate.FormatDiff(res, "diff")
			fmt.Fprint(stdout, rendered)
		case "7", "/verify":
			count, ok, reason, err := store.Open(opts.HistoryPath).VerifyChain()
			if err != nil {
				fmt.Fprintf(stdout, "error: %v\n", err)
				continue
			}
			fmt.Fprintf(stdout, "History Ledger (%s): entries=%d verified=%v (%s)\n",
				opts.HistoryPath, count, ok, reason)
		case "8", "/ask":
			if arg == "" {
				fmt.Fprint(stdout, "Ask Defense Assistant: ")
				if !scanner.Scan() {
					return nil
				}
				arg = strings.TrimSpace(scanner.Text())
			}
			if arg == "" {
				continue
			}
			res, err := assistant.Chat(ctx, assistant.InputContext{
				Report:      active,
				Workspace:   opts.Workspace,
				BinDir:      opts.BinDir,
				HistoryPath: opts.HistoryPath,
				Resolver:    opts.Resolver,
				Exec:        opts.Exec,
				Remediate:   opts.Remediate,
			}, assistant.ChatRequest{Mode: "local", Prompt: arg})
			if err != nil {
				fmt.Fprintf(stdout, "assistant error: %v\n", err)
				continue
			}
			fmt.Fprintln(stdout, res.Reply)
		case "9", "/ui":
			fmt.Fprintf(stdout, "Launch browser workbench with:\n  raksa ui --path %s\n", opts.Workspace)
		default:
			fmt.Fprintf(stdout, "Unknown selection %q (type 'help' or '0' to quit).\n", line)
		}
	}
	return scanner.Err()
}

func loadInitialReport(opts Options) (schema.SuiteReport, error) {
	cfg, _, err := policy.Discover(opts.Workspace, "")
	if err != nil {
		cfg = policy.DefaultConfig()
	}
	if strings.TrimSpace(opts.FromReports) != "" {
		ups, err := aggregator.LoadReportsFromPath(opts.FromReports)
		if err != nil {
			return schema.SuiteReport{}, err
		}
		return aggregator.Merge(ups, nil, aggregator.MergeOptions{
			Profile: "aggregated",
			Target:  opts.FromReports,
			Policy:  cfg,
			Now:     time.Now().UTC(),
		}), nil
	}
	return aggregator.Merge(nil, nil, aggregator.MergeOptions{
		Profile: cfg.Profile,
		Target:  opts.Workspace,
		Policy:  cfg,
		Now:     time.Now().UTC(),
	}), nil
}

func runAuditAction(ctx context.Context, opts Options, profile string, layers []string, stdout io.Writer) schema.SuiteReport {
	cfg, _, _ := policy.Discover(opts.Workspace, "")
	ups, execs, err := runner.RunSuite(ctx, runner.SuiteRequest{
		Profile:        profile,
		ExplicitLayers: layers,
		Target:         opts.Workspace,
		BinDir:         opts.BinDir,
		Policy:         cfg,
	}, opts.Resolver, opts.Exec)
	if err != nil {
		fmt.Fprintf(stdout, "scan error: %v\n", err)
		return aggregator.Merge(nil, nil, aggregator.MergeOptions{Profile: profile, Target: opts.Workspace, Policy: cfg})
	}
	rep := aggregator.Merge(ups, execs, aggregator.MergeOptions{
		Profile: profile,
		Target:  opts.Workspace,
		Policy:  cfg,
		Now:     time.Now().UTC(),
	})
	_, _ = store.Open(opts.HistoryPath).Append(rep)
	rendered, _ := report.Render(rep, report.FormatTable)
	fmt.Fprint(stdout, string(rendered))
	return rep
}

func splitCommand(line string) (string, string) {
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToLower(strings.TrimSpace(parts[0]))
	arg := ""
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}
	return cmd, arg
}

func printBanner(w io.Writer, rep schema.SuiteReport, target string) {
	fmt.Fprintf(w, "Raksa Interactive Defense Workbench v%s | target=%s | posture=%d/100 (%s) | findings=%d\n",
		schema.Version, target, rep.Posture.Score, rep.Posture.Grade, rep.Summary.Total)
}

func printMenu(w io.Writer) {
	fmt.Fprintln(w, `Menu / Slash Commands:
  [1] /scan [profile]   Run Hybrid audit (full, repo, host, web, incident)
  [2] /layers <list>    Selective scan (e.g. pipeguard,hostguard)
  [3] /playbook <name>  List or execute curated YAML playbook
  [4] /doctor           Inspect installed Layer 1-6 tools
  [5] /matrix           Display Attack-vs-Defense coverage matrix
  [6] /fix              Generate read-only hardening fix previews
  [7] /verify           Verify SHA-256 hash-chained runs.ndjson ledger
  [8] /ask <question>   Query offline Defense Assistant
  [9] /ui               Show command to launch embedded Web Workbench
  [0] /quit             Exit interactive session`)
}
