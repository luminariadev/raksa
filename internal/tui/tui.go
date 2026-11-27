// Package tui implements the interactive zero-dependency terminal Blue Team workbench (raksa tui).
package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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

const tuiBoxInnerWidth = 76

// Options configures the interactive terminal workbench session.
type Options struct {
	Workspace   string
	FromReports string
	BinDir      string
	HistoryPath string
	SIEMURL     string
	NoColor     bool
	ForceColor  bool
	Resolver    runner.BinaryResolver
	Exec        runner.CommandRunner
	Remediate   remediate.Executor
}

type ansiTheme struct {
	enabled bool
}

func resolveTheme(opts Options, w io.Writer) ansiTheme {
	if opts.NoColor || os.Getenv("NO_COLOR") != "" {
		return ansiTheme{enabled: false}
	}
	if opts.ForceColor {
		return ansiTheme{enabled: true}
	}
	return ansiTheme{enabled: isTerminalWriter(w)}
}

func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (t ansiTheme) paint(code, s string) string {
	if !t.enabled || s == "" {
		return s
	}
	return code + s + "\x1b[0m"
}

func (t ansiTheme) blue(s string) string   { return t.paint("\x1b[38;2;10;132;255m", s) }
func (t ansiTheme) cyan(s string) string   { return t.paint("\x1b[38;2;100;210;255m", s) }
func (t ansiTheme) green(s string) string  { return t.paint("\x1b[38;2;48;209;88m", s) }
func (t ansiTheme) yellow(s string) string { return t.paint("\x1b[38;2;255;214;10m", s) }
func (t ansiTheme) orange(s string) string { return t.paint("\x1b[38;2;255;159;10m", s) }
func (t ansiTheme) red(s string) string    { return t.paint("\x1b[38;2;255;69;58m", s) }
func (t ansiTheme) muted(s string) string  { return t.paint("\x1b[38;2;142;142;147m", s) }
func (t ansiTheme) border(s string) string { return t.paint("\x1b[38;2;99;99;102m", s) }
func (t ansiTheme) bright(s string) string { return t.paint("\x1b[1;38;2;245;245;247m", s) }

func (t ansiTheme) dotRed() string    { return t.paint("\x1b[38;2;255;95;87m", "●") }
func (t ansiTheme) dotYellow() string { return t.paint("\x1b[38;2;254;188;46m", "●") }
func (t ansiTheme) dotGreen() string  { return t.paint("\x1b[38;2;40;200;64m", "●") }

func (t ansiTheme) scoreColor(score int, s string) string {
	switch {
	case score >= 90:
		return t.green(s)
	case score >= 70:
		return t.orange(s)
	default:
		return t.red(s)
	}
}

// Run launches an interactive menu and slash-command workbench loop on stdin/stdout.
func Run(ctx context.Context, opts Options, stdin io.Reader, stdout io.Writer) error {
	if strings.TrimSpace(opts.Workspace) == "" {
		opts.Workspace = "."
	}
	if strings.TrimSpace(opts.HistoryPath) == "" {
		opts.HistoryPath = store.DefaultHistoryPath()
	}

	th := resolveTheme(opts, stdout)
	proMode := false

	active, err := loadInitialReport(opts)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 0, 16*1024), 256*1024)

	printBanner(stdout, th, active, opts.Workspace, proMode)
	printSimpleMenu(stdout, th)

	for {
		modeTag := "simple"
		if proMode {
			modeTag = "pro"
		}
		promptScore := th.scoreColor(active.Posture.Score, fmt.Sprintf("[%d/100 %s]", active.Posture.Score, active.Posture.Grade))
		fmt.Fprintf(stdout, "\n%s %s %s %s ", th.blue("raksa"), th.muted("("+modeTag+")"), promptScore, th.cyan("❯"))
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		cmd, arg := splitCommand(line)
		cmd = resolveNumberShortcut(cmd, proMode)

		switch cmd {
		case "0", "/quit", "/exit", "quit", "exit":
			fmt.Fprintln(stdout, th.muted("Exiting raksa interactive workbench."))
			return nil
		case "help", "/help", "?":
			if proMode {
				printProMenu(stdout, th)
			} else {
				printSimpleMenu(stdout, th)
			}
		case "/simple", "s":
			proMode = false
			printSimpleMenu(stdout, th)
		case "/pro":
			proMode = true
			printProMenu(stdout, th)
		case "/issues":
			printSimpleIssues(stdout, th, active)
		case "/guide":
			printQuickGuide(stdout, th)
		case "/scan":
			profile := arg
			if profile == "" {
				profile = "full"
			}
			active = runAuditAction(ctx, opts, th, profile, nil, stdout)
		case "/layers":
			if arg == "" {
				fmt.Fprint(stdout, th.cyan("Enter layers (e.g. netguard,hostguard,pipeguard): "))
				if !scanner.Scan() {
					return nil
				}
				arg = strings.TrimSpace(scanner.Text())
			}
			if arg == "" {
				fmt.Fprintln(stdout, th.muted("Skipped: no layers entered."))
				continue
			}
			active = runAuditAction(ctx, opts, th, "hybrid-layers", strings.Split(arg, ","), stdout)
		case "/playbooks", "/playbook":
			pbs, err := playbook.ListBuiltins()
			if err != nil {
				fmt.Fprintf(stdout, "%s %v\n", th.red("error:"), err)
				continue
			}
			if arg == "" {
				printSectionHeader(stdout, th, "Curated YAML Playbooks", tuiBoxInnerWidth)
				for _, pb := range pbs {
					name := fmt.Sprintf("%-22s", pb.Name)
					fmt.Fprintf(stdout, "  %s %s %s\n", th.cyan(name), th.muted("layers="), th.bright(strings.Join(pb.Layers, ",")))
				}
				printSectionFooter(stdout, th, tuiBoxInnerWidth)
				fmt.Fprint(stdout, th.cyan("Run playbook name (blank to cancel): "))
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
				fmt.Fprintf(stdout, "%s %v\n", th.red("error:"), err)
				continue
			}
			active = runAuditAction(ctx, opts, th, pb.Name, pb.Layers, stdout)
		case "/doctor":
			statuses := runner.Doctor(ctx, opts.BinDir, opts.Resolver, opts.Exec)
			printSectionHeader(stdout, th, "Layer 1-6 Doctor Status", tuiBoxInnerWidth)
			for _, st := range statuses {
				badgeText := fmt.Sprintf("[%-7s]", st.Status)
				badgeStyled := th.orange(badgeText)
				if st.Installed {
					badgeStyled = th.green(badgeText)
				}
				idCell := fmt.Sprintf("L%d %-10s", st.Number, st.ID)
				fmt.Fprintf(stdout, "  %s %s  rules=%2d  mcp=%2d  %s\n",
					th.bright(idCell), badgeStyled, st.RuleCount, st.MCPCount, th.muted(st.Hint))
			}
			printSectionFooter(stdout, th, tuiBoxInnerWidth)
		case "/matrix":
			rows := schema.AttackDefenseMatrix()
			printSectionHeader(stdout, th, "Attack-vs-Defense Coverage Matrix", tuiBoxInnerWidth)
			for _, r := range rows {
				stRaw := fmt.Sprintf("[%-7s]", r.Status)
				stStyled := th.muted(stRaw)
				switch r.Status {
				case "covered":
					stStyled = th.green(stRaw)
				case "partial":
					stStyled = th.orange(stRaw)
				}
				fmt.Fprintf(stdout, "  %s %-40s D3FEND=%s  layers=%s\n",
					stStyled, r.Category, th.cyan(fmt.Sprintf("%-8s", r.MitreD3FEND)), th.muted(strings.Join(r.Layers, ",")))
			}
			printSectionFooter(stdout, th, tuiBoxInnerWidth)
		case "/fix":
			res := remediate.CollectFixPreviews(ctx, opts.Workspace, opts.Remediate)
			rendered, _ := remediate.FormatDiff(res, "diff")
			printSectionHeader(stdout, th, "Read-Only Hardening Fix Previews", tuiBoxInnerWidth)
			fmt.Fprint(stdout, rendered)
			if !strings.HasSuffix(rendered, "\n") {
				fmt.Fprintln(stdout)
			}
			printSectionFooter(stdout, th, tuiBoxInnerWidth)
		case "/verify":
			count, ok, reason, err := store.Open(opts.HistoryPath).VerifyChain()
			if err != nil {
				fmt.Fprintf(stdout, "%s %v\n", th.red("error:"), err)
				continue
			}
			statusText := fmt.Sprintf("entries=%d verified=%v (%s)", count, ok, reason)
			summaryBody := fmt.Sprintf("History Ledger: %s\nPath: %s", statusText, opts.HistoryPath)
			printWrappedBox(stdout, th, "SHA-256 Hash-Chained Ledger", summaryBody, tuiBoxInnerWidth)
		case "/ask":
			if arg == "" {
				fmt.Fprint(stdout, th.cyan("Ask Raksa Assistant: "))
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
				fmt.Fprintf(stdout, "%s %v\n", th.red("assistant error:"), err)
				continue
			}
			printWrappedBox(stdout, th, "Raksa Assistant (Read-Only)", res.Reply, tuiBoxInnerWidth)
		case "/ui":
			printSectionHeader(stdout, th, "Embedded Glassmorphism Web Workbench", tuiBoxInnerWidth)
			fmt.Fprintf(stdout, "  Launch browser workbench with:\n    %s\n",
				th.cyan(fmt.Sprintf("raksa ui --path %s", opts.Workspace)))
			printSectionFooter(stdout, th, tuiBoxInnerWidth)
		default:
			fmt.Fprintf(stdout, "%s %q %s\n", th.orange("Unknown selection"), line, th.muted("(type 'help', '/guide', or '0' to quit)."))
		}
	}
	return scanner.Err()
}

func resolveNumberShortcut(cmd string, proMode bool) string {
	if !proMode {
		switch cmd {
		case "1":
			return "/scan"
		case "2":
			return "/issues"
		case "3":
			return "/ask"
		case "4":
			return "/guide"
		case "5":
			return "/pro"
		}
		return cmd
	}
	switch cmd {
	case "1":
		return "/scan"
	case "2":
		return "/layers"
	case "3":
		return "/playbook"
	case "4":
		return "/doctor"
	case "5":
		return "/matrix"
	case "6":
		return "/fix"
	case "7":
		return "/verify"
	case "8":
		return "/ask"
	case "9":
		return "/ui"
	}
	return cmd
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

func runAuditAction(ctx context.Context, opts Options, th ansiTheme, profile string, layers []string, stdout io.Writer) schema.SuiteReport {
	cfg, _, _ := policy.Discover(opts.Workspace, "")
	ups, execs, err := runner.RunSuite(ctx, runner.SuiteRequest{
		Profile:        profile,
		ExplicitLayers: layers,
		Target:         opts.Workspace,
		BinDir:         opts.BinDir,
		Policy:         cfg,
	}, opts.Resolver, opts.Exec)
	if err != nil {
		fmt.Fprintf(stdout, "%s %v\n", th.red("scan error:"), err)
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
	printSectionHeader(stdout, th, fmt.Sprintf("Audit Result (%s)", profile), tuiBoxInnerWidth)
	fmt.Fprint(stdout, string(rendered))
	printSectionFooter(stdout, th, tuiBoxInnerWidth)
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

func postureBar(score, width int) (string, string) {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	filled := (score * width) / 100
	return strings.Repeat("█", filled), strings.Repeat("░", width-filled)
}

func truncateRunes(s string, max int) string {
	if max <= 3 || utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return "..." + string(runes[len(runes)-(max-3):])
}

func printBoxLine(w io.Writer, th ansiTheme, innerWidth, visibleLen int, styled string) {
	pad := innerWidth - 2 - visibleLen
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(w, "%s %s%s %s\n", th.border("│"), styled, strings.Repeat(" ", pad), th.border("│"))
}

func printSectionHeader(w io.Writer, th ansiTheme, title string, width int) {
	prefix := "╭─ " + title + " "
	rem := width - utf8.RuneCountInString(prefix) + 1
	if rem < 2 {
		rem = 2
	}
	fmt.Fprintf(w, "%s%s%s\n",
		th.border("╭─ "),
		th.bright(title),
		th.border(" "+strings.Repeat("─", rem)+"╮"))
}

func printSectionFooter(w io.Writer, th ansiTheme, width int) {
	fmt.Fprintln(w, th.border("╰"+strings.Repeat("─", width)+"╯"))
}

func healthStatusLabel(rep schema.SuiteReport) string {
	switch {
	case rep.Summary.Total == 0:
		return "All Clear"
	case rep.Summary.Critical > 0:
		return "Action Needed"
	case rep.Summary.High > 0:
		return "Needs Attention"
	default:
		return "Fairly Good"
	}
}

func printBanner(w io.Writer, th ansiTheme, rep schema.SuiteReport, target string, proMode bool) {
	fmt.Fprintln(w, th.border("╭"+strings.Repeat("─", tuiBoxInnerWidth)+"╮"))

	modeStr := "Simple Mode"
	if proMode {
		modeStr = "Pro Mode"
	}
	titlePlain := fmt.Sprintf("● ● ●  Raksa Interactive Defense Workbench v%s (%s)", schema.Version, modeStr)
	titleStyled := fmt.Sprintf("%s %s %s  %s %s %s",
		th.dotRed(), th.dotYellow(), th.dotGreen(),
		th.bright("Raksa Interactive Defense Workbench"),
		th.cyan("v"+schema.Version),
		th.muted("("+modeStr+")"))
	printBoxLine(w, th, tuiBoxInnerWidth, utf8.RuneCountInString(titlePlain), titleStyled)

	fmt.Fprintln(w, th.border("├"+strings.Repeat("─", tuiBoxInnerWidth)+"┤"))

	safeTarget := truncateRunes(target, 32)
	statusText := healthStatusLabel(rep)
	tPlain := fmt.Sprintf("Project  : %-32s   Status: %s", safeTarget, statusText)
	tStyled := fmt.Sprintf("%s%s   %s%s",
		th.muted("Project  : "), th.bright(fmt.Sprintf("%-32s", safeTarget)),
		th.muted("Status: "), th.scoreColor(rep.Posture.Score, statusText))
	printBoxLine(w, th, tuiBoxInnerWidth, utf8.RuneCountInString(tPlain), tStyled)

	filled, empty := postureBar(rep.Posture.Score, 16)
	scoreStr := fmt.Sprintf("%d/100 [%s]", rep.Posture.Score, rep.Posture.Grade)
	findStr := fmt.Sprintf("Issues: %d", rep.Summary.Total)
	pPlain := fmt.Sprintf("Health   : %s%s %s   %s", filled, empty, scoreStr, findStr)
	pStyled := fmt.Sprintf("%s%s%s %s   %s",
		th.muted("Health   : "),
		th.scoreColor(rep.Posture.Score, filled),
		th.border(empty),
		th.scoreColor(rep.Posture.Score, scoreStr),
		th.bright(findStr))
	printBoxLine(w, th, tuiBoxInnerWidth, utf8.RuneCountInString(pPlain), pStyled)

	s := rep.Summary
	sPlain := fmt.Sprintf("Priority : Urgent %d  Important %d  Moderate %d  Low %d",
		s.Critical, s.High, s.Medium, s.Low+s.Info)
	sStyled := fmt.Sprintf("%s%s  %s  %s  %s",
		th.muted("Priority : "),
		th.red(fmt.Sprintf("Urgent %d", s.Critical)),
		th.orange(fmt.Sprintf("Important %d", s.High)),
		th.yellow(fmt.Sprintf("Moderate %d", s.Medium)),
		th.blue(fmt.Sprintf("Low %d", s.Low+s.Info)))
	printBoxLine(w, th, tuiBoxInnerWidth, utf8.RuneCountInString(sPlain), sStyled)

	printSectionFooter(w, th, tuiBoxInnerWidth)
}

func printSimpleMenu(w io.Writer, th ansiTheme) {
	items := []struct {
		key   string
		label string
		desc  string
	}{
		{"[1]", "Scan Project Now", "Run a safe read-only security check"},
		{"[2]", "Issues & Fixes", "View top problems and recommended fixes"},
		{"[3]", "Ask Assistant", "Ask Raksa what to fix in plain language"},
		{"[4]", "Quick Guide", "3-step guide for beginners"},
		{"[5]", "Pro Mode (L1-L6)", "Unlock layers, playbooks, matrix & SIEM"},
		{"[0]", "Quit", "Exit interactive session"},
	}

	printSectionHeader(w, th, "Simple Quick Menu", tuiBoxInnerWidth)
	for _, it := range items {
		labelPadded := fmt.Sprintf("%-18s", it.label)
		plain := fmt.Sprintf(" %s %s  %s", it.key, labelPadded, it.desc)
		styled := fmt.Sprintf(" %s %s  %s", th.blue(it.key), th.cyan(labelPadded), it.desc)
		printBoxLine(w, th, tuiBoxInnerWidth, utf8.RuneCountInString(plain), styled)
	}
	printSectionFooter(w, th, tuiBoxInnerWidth)
}

func printProMenu(w io.Writer, th ansiTheme) {
	items := []struct {
		key  string
		cmd  string
		desc string
	}{
		{"[1]", "/scan [profile]", "Run Hybrid audit (full, repo, host, web, incident)"},
		{"[2]", "/layers <list>", "Selective scan (e.g. pipeguard,hostguard)"},
		{"[3]", "/playbook <name>", "List or execute curated YAML playbook"},
		{"[4]", "/doctor", "Inspect installed Layer 1-6 tools"},
		{"[5]", "/matrix", "Display Attack-vs-Defense coverage matrix"},
		{"[6]", "/fix", "Generate read-only hardening fix previews"},
		{"[7]", "/verify", "Verify SHA-256 hash-chained runs.ndjson ledger"},
		{"[8]", "/ask <question>", "Query offline Defense Assistant"},
		{"[9]", "/ui", "Show command to launch embedded Web Workbench"},
		{"[s]", "/simple", "Switch back to beginner Simple Mode"},
		{"[0]", "/quit", "Exit interactive session"},
	}

	printSectionHeader(w, th, "Pro Workbench Commands (Hybrid L1-L7)", tuiBoxInnerWidth)
	for _, it := range items {
		cmdPadded := fmt.Sprintf("%-16s", it.cmd)
		plain := fmt.Sprintf(" %s %s  %s", it.key, cmdPadded, it.desc)
		styled := fmt.Sprintf(" %s %s  %s", th.blue(it.key), th.cyan(cmdPadded), it.desc)
		printBoxLine(w, th, tuiBoxInnerWidth, utf8.RuneCountInString(plain), styled)
	}
	printSectionFooter(w, th, tuiBoxInnerWidth)
}

func urgencyTag(sev schema.Severity) (string, int) {
	switch strings.ToLower(string(sev)) {
	case "critical":
		return "URGENT", 4
	case "high":
		return "IMPORTANT", 3
	case "medium":
		return "MODERATE", 2
	default:
		return "LOW", 1
	}
}

func printSimpleIssues(w io.Writer, th ansiTheme, rep schema.SuiteReport) {
	if len(rep.Findings) == 0 {
		printWrappedBox(w, th, "Issues & Recommended Fixes",
			"No active issues found! Your project looks clear right now.\nRun '1' (/scan) anytime to re-check.", tuiBoxInnerWidth)
		return
	}

	sorted := make([]schema.Finding, len(rep.Findings))
	copy(sorted, rep.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		_, ri := urgencyTag(sorted[i].Severity)
		_, rj := urgencyTag(sorted[j].Severity)
		return ri > rj
	})

	var b strings.Builder
	limit := len(sorted)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		f := sorted[i]
		tag, _ := urgencyTag(f.Severity)
		fix := strings.TrimSpace(f.Remediation)
		if fix == "" {
			fix = strings.TrimSpace(f.Description)
		}
		if fix == "" {
			fix = "Review configuration and apply least-privilege defaults."
		}
		fmt.Fprintf(&b, "%d. [%s] %s\nWhere: %s\nFix:   %s\n", i+1, tag, f.Title, f.Target, fix)
		if i < limit-1 {
			b.WriteByte('\n')
		}
	}
	if len(sorted) > limit {
		fmt.Fprintf(&b, "\nShowing top %d of %d issues. Type '3' to ask Assistant for full plan.", limit, len(sorted))
	}
	printWrappedBox(w, th, "Issues & Recommended Fixes", b.String(), tuiBoxInnerWidth)
}

func printQuickGuide(w io.Writer, th ansiTheme) {
	guide := `Quick Start in 3 Simple Steps:
1. Run '1' (Scan Project Now) to safely inspect your project read-only.
2. Run '2' (Issues & Fixes) to see problems sorted by Urgency + clear fixes.
3. Run '3' (Ask Assistant) for plain-language help prioritizing fixes.

Modes & Safety:
- Simple Mode (default): clean 6-item menu without heavy security jargon.
- Pro Mode (press '5' or /pro): unlocks L1-L6 layers, YAML playbooks,
  Attack Matrix, unified diffs, and SHA-256 audit verification.
- Raksa never modifies your project files automatically.`
	printWrappedBox(w, th, "Raksa Beginner Quick Guide", guide, tuiBoxInnerWidth)
}

func printWrappedBox(w io.Writer, th ansiTheme, title, body string, width int) {
	printSectionHeader(w, th, title, width)
	maxContent := width - 2
	for _, rawLine := range strings.Split(body, "\n") {
		wrapped := wrapPlainLine(rawLine, maxContent)
		for _, ln := range wrapped {
			printBoxLine(w, th, width, utf8.RuneCountInString(ln), ln)
		}
	}
	printSectionFooter(w, th, width)
}

func wrapPlainLine(line string, maxWidth int) []string {
	trimmed := strings.TrimRight(line, "\r")
	if utf8.RuneCountInString(trimmed) <= maxWidth {
		return []string{trimmed}
	}
	var out []string
	var cur strings.Builder
	curLen := 0
	for _, word := range strings.Fields(trimmed) {
		wLen := utf8.RuneCountInString(word)
		if curLen > 0 && curLen+1+wLen > maxWidth {
			out = append(out, cur.String())
			cur.Reset()
			curLen = 0
		}
		if curLen > 0 {
			cur.WriteByte(' ')
			curLen++
		}
		cur.WriteString(word)
		curLen += wLen
	}
	if cur.Len() > 0 || len(out) == 0 {
		out = append(out, cur.String())
	}
	return out
}
