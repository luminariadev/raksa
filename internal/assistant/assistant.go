// Package assistant implements the read-only BYOK AI Defense Assistant for Layer 7
// supporting Offline Deterministic mode, Local Ollama, and external chat API adapters.
package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa/internal/playbook"
	"github.com/luminariadev/raksa/internal/remediate"
	"github.com/luminariadev/raksa/internal/runner"
	"github.com/luminariadev/raksa/internal/schema"
	"github.com/luminariadev/raksa/internal/store"
)

const (
	DefaultOllamaURL   = "http://localhost:11434"
	DefaultOllamaModel = "llama3.2"
	EnvOllamaURL       = "RAKSA_OLLAMA_URL"
	EnvAIEndpoint      = "RAKSA_AI_ENDPOINT"
	EnvAIAPIKey        = "RAKSA_AI_API_KEY"
	EnvAIModel         = "RAKSA_AI_MODEL"
)

// ToolCallCard records a transparent read-only MCP/orchestrator inspection performed for a reply.
type ToolCallCard struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok, skipped, warning
	Summary string `json:"summary"`
}

// ConfigStatus exposes safe non-secret assistant capability metadata.
type ConfigStatus struct {
	DefaultMode    string   `json:"default_mode"`
	Modes          []string `json:"modes"`
	OllamaURL      string   `json:"ollama_url"`
	DefaultModel   string   `json:"default_model"`
	BYOKConfigured bool     `json:"byok_configured"`
	ReadOnly       bool     `json:"read_only"`
}

// ChatRequest carries an operator prompt and provider mode selection.
type ChatRequest struct {
	Prompt   string `json:"prompt"`
	Mode     string `json:"mode"`     // local, ollama, byok
	Model    string `json:"model"`    // optional override
	Endpoint string `json:"endpoint"` // optional http/https URL override
}

// ChatResponse contains the assistant reply plus read-only tool provenance and citations.
type ChatResponse struct {
	Mode        string         `json:"mode"`
	Model       string         `json:"model,omitempty"`
	Reply       string         `json:"reply"`
	ToolCalls   []ToolCallCard `json:"tool_calls"`
	Citations   []string       `json:"citations"`
	ReadOnly    bool           `json:"read_only"`
	GeneratedAt string         `json:"generated_at"`
}

// InputContext supplies live Layer 7 state for read-only grounding.
type InputContext struct {
	Report      schema.SuiteReport
	Workspace   string
	BinDir      string
	HistoryPath string
	Resolver    runner.BinaryResolver
	Exec        runner.CommandRunner
	Remediate   remediate.Executor
}

// GetConfigStatus returns non-secret environment readiness for local, Ollama, and BYOK modes.
func GetConfigStatus() ConfigStatus {
	ollamaURL := strings.TrimSpace(os.Getenv(EnvOllamaURL))
	if ollamaURL == "" {
		ollamaURL = DefaultOllamaURL
	}
	model := strings.TrimSpace(os.Getenv(EnvAIModel))
	if model == "" {
		model = DefaultOllamaModel
	}
	byokReady := strings.TrimSpace(os.Getenv(EnvAIEndpoint)) != "" && strings.TrimSpace(os.Getenv(EnvAIAPIKey)) != ""
	return ConfigStatus{
		DefaultMode:    "local",
		Modes:          []string{"local", "ollama", "byok"},
		OllamaURL:      ollamaURL,
		DefaultModel:   model,
		BYOKConfigured: byokReady,
		ReadOnly:       true,
	}
}

// Chat grounds the user's question in read-only Layer 7 checks and answers via local/ollama/byok.
func Chat(ctx context.Context, in InputContext, req ChatRequest) (ChatResponse, error) {
	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" {
		return ChatResponse{}, fmt.Errorf("prompt cannot be empty")
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "local"
	}

	cards, citations, grounded := gatherGroundedTools(ctx, in, prompt)
	now := time.Now().UTC().Format(time.RFC3339)

	switch mode {
	case "local", "deterministic", "offline":
		return ChatResponse{
			Mode:        "local",
			Model:       "raksa-deterministic-v0.3",
			Reply:       composeDeterministicReply(prompt, in.Report, cards, grounded),
			ToolCalls:   cards,
			Citations:   citations,
			ReadOnly:    true,
			GeneratedAt: now,
		}, nil
	case "ollama":
		endpoint := strings.TrimSpace(req.Endpoint)
		if endpoint == "" {
			endpoint = strings.TrimSpace(os.Getenv(EnvOllamaURL))
		}
		if endpoint == "" {
			endpoint = DefaultOllamaURL
		}
		if err := validateHTTPURL(endpoint); err != nil {
			return ChatResponse{}, err
		}
		model := strings.TrimSpace(req.Model)
		if model == "" {
			model = strings.TrimSpace(os.Getenv(EnvAIModel))
		}
		if model == "" {
			model = DefaultOllamaModel
		}
		reply, err := callOllamaChat(ctx, endpoint, model, grounded, prompt)
		if err != nil {
			return ChatResponse{}, err
		}
		return ChatResponse{
			Mode:        "ollama",
			Model:       model,
			Reply:       reply,
			ToolCalls:   cards,
			Citations:   citations,
			ReadOnly:    true,
			GeneratedAt: now,
		}, nil
	case "byok":
		endpoint := strings.TrimSpace(req.Endpoint)
		if endpoint == "" {
			endpoint = strings.TrimSpace(os.Getenv(EnvAIEndpoint))
		}
		if err := validateHTTPURL(endpoint); err != nil {
			return ChatResponse{}, fmt.Errorf("BYOK mode requires valid %s (or endpoint): %w", EnvAIEndpoint, err)
		}
		apiKey := strings.TrimSpace(os.Getenv(EnvAIAPIKey))
		if apiKey == "" {
			return ChatResponse{}, fmt.Errorf("BYOK mode requires %s environment variable", EnvAIAPIKey)
		}
		model := strings.TrimSpace(req.Model)
		if model == "" {
			model = strings.TrimSpace(os.Getenv(EnvAIModel))
		}
		if model == "" {
			return ChatResponse{}, fmt.Errorf("BYOK mode requires model name or %s", EnvAIModel)
		}
		reply, err := callBYOKChat(ctx, endpoint, apiKey, model, grounded, prompt)
		if err != nil {
			return ChatResponse{}, err
		}
		return ChatResponse{
			Mode:        "byok",
			Model:       model,
			Reply:       reply,
			ToolCalls:   cards,
			Citations:   citations,
			ReadOnly:    true,
			GeneratedAt: now,
		}, nil
	default:
		return ChatResponse{}, fmt.Errorf("unsupported assistant mode %q (expected local, ollama, byok)", req.Mode)
	}
}

type groundedBundle struct {
	TopFindings    []schema.Finding
	MatrixGaps     []schema.AttackCoverageRow
	DoctorTools    []schema.ToolDoctorStatus
	FixQueue       *remediate.QueueResult
	Playbooks      []playbook.Playbook
	LedgerCount    int
	LedgerVerified bool
	LedgerReason   string
}

func gatherGroundedTools(ctx context.Context, in InputContext, prompt string) ([]ToolCallCard, []string, groundedBundle) {
	low := strings.ToLower(prompt)
	var cards []ToolCallCard
	citeSet := make(map[string]struct{})
	var bundle groundedBundle

	// Always inspect active suite posture & top findings
	findings := make([]schema.Finding, len(in.Report.Findings))
	copy(findings, in.Report.Findings)
	schema.SortFindings(findings)
	limit := 5
	if len(findings) < limit {
		limit = len(findings)
	}
	bundle.TopFindings = findings[:limit]
	for _, f := range bundle.TopFindings {
		citeSet[fmt.Sprintf("%s@%s", f.RuleID, f.Target)] = struct{}{}
	}
	cards = append(cards, ToolCallCard{
		Name:   "raksa_posture_summary",
		Status: "ok",
		Summary: fmt.Sprintf("Posture %d/100 (%s), total=%d (critical=%d, high=%d, medium=%d)",
			in.Report.Posture.Score, in.Report.Posture.Grade, in.Report.Summary.Total, in.Report.Summary.Critical, in.Report.Summary.High, in.Report.Summary.Medium),
	})

	wantsMatrix := containsAny(low, "gap", "matrix", "attack", "ddos", "phishing", "cover", "strix", "hacking")
	wantsLedger := containsAny(low, "ledger", "verify", "chain", "history", "tamper", "audit trail", "sha")
	wantsFix := containsAny(low, "fix", "patch", "remediat", "harden", "diff", "mitigat")
	wantsDoctor := containsAny(low, "doctor", "tool", "install", "layer", "missing", "status")
	wantsPlaybook := containsAny(low, "playbook", "workflow", "checklist", "gate")

	if wantsMatrix {
		rows := schema.AttackDefenseMatrix()
		for _, r := range rows {
			if r.Status != "covered" {
				bundle.MatrixGaps = append(bundle.MatrixGaps, r)
				citeSet[fmt.Sprintf("%s (%s)", r.MitreD3FEND, r.Status)] = struct{}{}
			}
		}
		cards = append(cards, ToolCallCard{
			Name:    "raksa_defense_coverage",
			Status:  "ok",
			Summary: fmt.Sprintf("Evaluated %d attack categories (%d partial/planned gaps)", len(rows), len(bundle.MatrixGaps)),
		})
	}

	if wantsLedger || in.HistoryPath != "" {
		histPath := in.HistoryPath
		if strings.TrimSpace(histPath) == "" {
			histPath = store.DefaultHistoryPath()
		}
		count, ok, reason, err := store.Open(histPath).VerifyChain()
		if err != nil {
			cards = append(cards, ToolCallCard{Name: "raksa_verify_history", Status: "warning", Summary: err.Error()})
		} else {
			bundle.LedgerCount = count
			bundle.LedgerVerified = ok
			bundle.LedgerReason = reason
			citeSet["ledger:runs.ndjson"] = struct{}{}
			st := "ok"
			if !ok {
				st = "warning"
			}
			cards = append(cards, ToolCallCard{
				Name:    "raksa_verify_history",
				Status:  st,
				Summary: fmt.Sprintf("%d entries, verified=%v (%s)", count, ok, reason),
			})
		}
	}

	if wantsFix {
		target := in.Workspace
		if strings.TrimSpace(target) == "" {
			target = in.Report.Target
		}
		if strings.TrimSpace(target) == "" {
			target = "."
		}
		res := remediate.CollectFixPreviews(ctx, target, in.Remediate)
		bundle.FixQueue = &res
		cards = append(cards, ToolCallCard{
			Name:    "raksa_plan_remediation",
			Status:  "ok",
			Summary: fmt.Sprintf("Collected %d read-only patch preview(s) (%d skipped)", len(res.Items), len(res.Skipped)),
		})
	}

	if wantsDoctor {
		docs := runner.Doctor(ctx, in.BinDir, in.Resolver, in.Exec)
		bundle.DoctorTools = docs
		ready := 0
		for _, d := range docs {
			if d.Installed {
				ready++
			}
		}
		cards = append(cards, ToolCallCard{
			Name:    "raksa_doctor",
			Status:  "ok",
			Summary: fmt.Sprintf("%d/%d Layer 1-6 tools installed on host", ready, len(docs)),
		})
	}

	if wantsPlaybook {
		pbs, err := playbook.ListBuiltins()
		if err == nil {
			bundle.Playbooks = pbs
			cards = append(cards, ToolCallCard{
				Name:    "raksa_list_playbooks",
				Status:  "ok",
				Summary: fmt.Sprintf("Listed %d built-in YAML defensive playbooks", len(pbs)),
			})
		}
	}

	citations := make([]string, 0, len(citeSet))
	for c := range citeSet {
		citations = append(citations, c)
	}
	sort.Strings(citations)
	return cards, citations, bundle
}

func composeDeterministicReply(prompt string, rep schema.SuiteReport, cards []ToolCallCard, g groundedBundle) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Defense Assessment (%d/100 Grade %s, %d active findings):\n\n",
		rep.Posture.Score, rep.Posture.Grade, rep.Summary.Total)

	if len(g.TopFindings) > 0 {
		b.WriteString("Top Prioritized Findings:\n")
		for idx, f := range g.TopFindings {
			rem := f.Remediation
			if rem == "" {
				rem = f.Description
			}
			fmt.Fprintf(&b, "%d. [%s] %s (%s) on %s -> %s\n",
				idx+1, strings.ToUpper(string(f.Severity)), f.RuleID, f.Title, f.Target, rem)
		}
		b.WriteByte('\n')
	} else {
		b.WriteString("No active findings exceed current posture thresholds.\n\n")
	}

	if len(g.MatrixGaps) > 0 {
		b.WriteString("Attack-vs-Defense Matrix Gaps (partial/planned):\n")
		for _, r := range g.MatrixGaps {
			fmt.Fprintf(&b, "- [%s] %s (%s): %s\n", r.Status, r.Category, r.MitreD3FEND, r.DefensiveAim)
		}
		b.WriteByte('\n')
	}

	if g.LedgerCount > 0 || containsAny(strings.ToLower(prompt), "ledger", "verify", "chain") {
		fmt.Fprintf(&b, "Audit Ledger Verification: entries=%d verified=%v (%s).\n\n",
			g.LedgerCount, g.LedgerVerified, g.LedgerReason)
	}

	if g.FixQueue != nil {
		fmt.Fprintf(&b, "Read-Only Fix Previews (%s): %d patch(es) ready for human review; run 'raksa fix-preview --path %s' to inspect diffs.\n\n",
			g.FixQueue.Target, len(g.FixQueue.Items), g.FixQueue.Target)
	}

	if len(g.DoctorTools) > 0 {
		var missing []string
		for _, d := range g.DoctorTools {
			if !d.Installed {
				missing = append(missing, d.ID)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(&b, "Missing Layer Tools: %s (install via 'raksa install --layers %s').\n\n",
				strings.Join(missing, ", "), strings.Join(missing, ","))
		} else {
			b.WriteString("Toolchain Doctor: all 6 defensive layers are installed.\n\n")
		}
	}

	if len(g.Playbooks) > 0 {
		var names []string
		for _, pb := range g.Playbooks {
			names = append(names, pb.Name)
		}
		fmt.Fprintf(&b, "Recommended Playbooks: %s.\n\n", strings.Join(names, ", "))
	}

	fmt.Fprintf(&b, "Read-Only Guardrail: %d deterministic tool check(s) inspected; no files were modified.", len(cards))
	return strings.TrimSpace(b.String())
}

func callOllamaChat(ctx context.Context, baseURL, model string, g groundedBundle, prompt string) (string, error) {
	sysMsg := buildSystemContextPrompt(g)
	payload := map[string]any{
		"model":  model,
		"stream": false,
		"messages": []map[string]string{
			{"role": "system", "content": sysMsg},
			{"role": "user", "content": prompt},
		},
	}
	target := strings.TrimRight(baseURL, "/") + "/api/chat"
	raw, err := postJSON(ctx, target, "", payload)
	if err != nil {
		return "", err
	}
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("decode Ollama response: %w", err)
	}
	if out.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", out.Error)
	}
	if strings.TrimSpace(out.Message.Content) == "" {
		return "", fmt.Errorf("empty response from Ollama")
	}
	return strings.TrimSpace(out.Message.Content), nil
}

func callBYOKChat(ctx context.Context, endpoint, apiKey, model string, g groundedBundle, prompt string) (string, error) {
	sysMsg := buildSystemContextPrompt(g)
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": sysMsg},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.2,
	}
	target := strings.TrimRight(endpoint, "/")
	if !strings.HasSuffix(target, "/chat/completions") {
		target += "/v1/chat/completions"
	}
	raw, err := postJSON(ctx, target, apiKey, payload)
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("decode BYOK response: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("BYOK endpoint error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("empty choices in BYOK chat response")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

func buildSystemContextPrompt(g groundedBundle) string {
	var b strings.Builder
	b.WriteString("You are Raksa Defense Assistant (strictly read-only Blue Team advisor). Rely only on verified Raksa telemetry below:\n")
	for _, f := range g.TopFindings {
		fmt.Fprintf(&b, "- [%s] %s %s target=%s remediation=%s\n", f.Severity, f.RuleID, f.Title, f.Target, f.Remediation)
	}
	if len(g.MatrixGaps) > 0 {
		b.WriteString("Coverage gaps:\n")
		for _, r := range g.MatrixGaps {
			fmt.Fprintf(&b, "- [%s] %s (%s)\n", r.Status, r.Category, r.MitreD3FEND)
		}
	}
	if g.LedgerReason != "" {
		fmt.Fprintf(&b, "History ledger: entries=%d verified=%v (%s)\n", g.LedgerCount, g.LedgerVerified, g.LedgerReason)
	}
	return b.String()
}

func postJSON(ctx context.Context, rawURL, bearer string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build assistant request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("assistant request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read assistant response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("assistant endpoint returned HTTP %d", resp.StatusCode)
	}
	return raw, nil
}

func validateHTTPURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q (expected http or https)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL %q missing host", raw)
	}
	return nil
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}
