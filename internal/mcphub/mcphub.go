// Package mcphub provides a federated 61-tool JSON-RPC 2.0 MCP server unifying
// 8 Raksa Layer 7 orchestrator meta-tools with all 53 Layer 1-6 defensive MCP tools.
package mcphub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/luminariadev/raksa/internal/aggregator"
	"github.com/luminariadev/raksa/internal/playbook"
	"github.com/luminariadev/raksa/internal/policy"
	"github.com/luminariadev/raksa/internal/remediate"
	"github.com/luminariadev/raksa/internal/runner"
	"github.com/luminariadev/raksa/internal/schema"
	"github.com/luminariadev/raksa/internal/store"
)

const supportedProtocolVersion = "2024-11-05"

// ToolSpec defines a federated MCP tool registration and its upstream layer target.
type ToolSpec struct {
	Layer       string
	Binary      string
	Name        string
	Description string
	InputSchema map[string]any
}

// UpstreamDispatcher proxies a JSON-RPC tools/call request to a Layer 1-6 `<bin> mcp` process.
type UpstreamDispatcher func(ctx context.Context, binary, toolName string, arguments json.RawMessage) (string, bool, error)

// Hub hosts the federated 61-tool stdio MCP server.
type Hub struct {
	BinDir     string
	History    *store.Store
	Resolver   runner.BinaryResolver
	Exec       runner.CommandRunner
	Remediate  remediate.Executor
	UpstreamFn UpstreamDispatcher
}

// NewHub initializes a Hub wired to local defaults.
func NewHub(binDir, historyPath string) *Hub {
	if strings.TrimSpace(historyPath) == "" {
		historyPath = store.DefaultHistoryPath()
	}
	return &Hub{
		BinDir:     binDir,
		History:    store.Open(historyPath),
		Resolver:   runner.ResolveBinary,
		UpstreamFn: nil,
	}
}

// Catalog returns all 61 MCP tools (8 orchestrator meta-tools + 53 upstream L1-L6 tools).
func Catalog() []ToolSpec {
	specs := []ToolSpec{
		// L7 Orchestrator Meta-Tools (8)
		localTool("raksa_doctor", "Inspect availability, versions, and SHA-256 digests of Raksa Layers 1-6", objSchema(prop("bin_dir", "Optional extra directory to search for binaries"))),
		localTool("raksa_full_audit", "Run Hybrid parallel security audit across L1-L6 on a workspace or host target", objSchema(prop("target", "Workspace path (default '.')"), prop("profile", "full|repo|host|web|incident"), prop("layers", "Comma-separated explicit layer IDs"))),
		localTool("raksa_posture_summary", "Compute aggregate 0-100 posture score and per-layer breakdown from target or saved reports", objSchema(prop("from_reports", "Path to Schema v1 JSON/NDJSON file or directory"))),
		localTool("raksa_correlate_all", "Merge upstream L1-L5 Finding Schema v1 reports and correlate attack chains via L6 SIEM", objSchema(prop("from_reports", "Path to report file or directory"))),
		localTool("raksa_defense_coverage", "Return the Attack-vs-Defense coverage matrix mapping threat classes to Raksa layers and rules", objSchema(prop("status", "Optional status filter: covered|partial|planned"))),
		localTool("raksa_plan_remediation", "Aggregate read-only unified hardening diffs across Layer 2-4 tools", objSchema(prop("target", "Target path to generate unified diffs for"))),
		localTool("raksa_list_playbooks", "List curated YAML defensive playbooks bundled in Layer 7", objSchema()),
		localTool("raksa_verify_history", "Verify SHA-256 hash-chain integrity of local Layer 7 scan run history", objSchema()),
	}

	// L1 raksa-netguard (5)
	specs = append(specs,
		upstreamTool("netguard", "raksa-netguard", "netguard_audit_host", "Audit local listening sockets against a YAML baseline policy"),
		upstreamTool("netguard", "raksa-netguard", "netguard_analyze_logs", "Analyze firewall or flow logs for port scans and bursts"),
		upstreamTool("netguard", "raksa-netguard", "netguard_check_policy", "Validate a netguard YAML baseline policy for permissive exposures"),
		upstreamTool("netguard", "raksa-netguard", "netguard_generate_baseline", "Generate a starter baseline policy from current listeners"),
		upstreamTool("netguard", "raksa-netguard", "netguard_list_rules", "List all 10 NET-* defensive rules"),
	)

	// L2 raksa-hostguard (9)
	specs = append(specs,
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_audit_ssh", "Audit OpenSSH sshd_config against CIS rules (HOST-101..106)"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_audit_docker", "Audit Dockerfile, Compose, daemon.json, or Podman configs"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_audit_host", "Audit Linux sysctl, sudoers, permissions, persistence, PAM, and kernel rules"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_audit_systemd", "Audit systemd units and .service.d drop-in sandboxing (HOST-305)"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_audit_workspace", "Recursively audit host and container configs in a workspace"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_fim_snapshot", "Create an optionally HMAC-signed SHA-256 FIM baseline snapshot"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_fim_check", "Verify filesystem integrity against a saved FIM snapshot"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_suggest_fix", "Generate read-only hardening unified diff patches for host/container configs"),
		upstreamTool("hostguard", "raksa-hostguard", "hostguard_list_rules", "List all 29 HOST-* CIS hardening rules"),
	)

	// L3 raksa-webshield (8)
	specs = append(specs,
		upstreamTool("webshield", "raksa-webshield", "webshield_audit_headers", "Audit HTTP security headers from a dump or SSRF-safe URL"),
		upstreamTool("webshield", "raksa-webshield", "webshield_audit_csp", "Audit Content-Security-Policy directives and JSONP/CDN bypasses"),
		upstreamTool("webshield", "raksa-webshield", "webshield_audit_config", "Audit Nginx, Caddy, Vercel, or Kubernetes Ingress reverse-proxy configs"),
		upstreamTool("webshield", "raksa-webshield", "webshield_inspect_payload", "Inspect HTTP payloads across 10 WAF classes and semantic tokenizers"),
		upstreamTool("webshield", "raksa-webshield", "webshield_audit_workspace", "Recursively audit web security configs and header dumps in a workspace"),
		upstreamTool("webshield", "raksa-webshield", "webshield_generate_remediation", "Generate hardened Nginx, Caddy, Next.js, or HTTP header snippets"),
		upstreamTool("webshield", "raksa-webshield", "webshield_validate_custom_rules", "Validate custom enterprise YAML WAF rule files"),
		upstreamTool("webshield", "raksa-webshield", "webshield_list_rules", "List all 30 WEB-* application security rules"),
	)

	// L4 raksa-pipeguard (9)
	specs = append(specs,
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_scan_secrets", "Scan repository files, git diffs, or history for exposed secrets"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_scan_deps", "Audit dependency lockfiles against OSV, CISA KEV, FIRST EPSS, and SPDX licenses"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_generate_sbom", "Generate CycloneDX 1.5 or SPDX 2.3 JSON SBOMs"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_scan_iac", "Audit Dockerfile, Kubernetes YAML, and multi-cloud Terraform HCL"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_scan_image", "Inspect Docker/OCI tarballs daemonlessly for OS CVEs and runtime risks"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_scan_ci_workflow", "Audit GitHub Actions and GitLab CI pipeline files"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_scan_repo", "Run complete Layer 4 DevSecOps gate across a repository"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_suggest_fix", "Generate read-only DevSecOps unified patch suggestions"),
		upstreamTool("pipeguard", "raksa-pipeguard", "pipeguard_list_rules", "List all 33 PIPE-* DevSecOps rules"),
	)

	// L5 raksa-iocscan (10)
	specs = append(specs,
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_scan_path", "Run streaming hash, YARA, binary, document, and archive malware triage"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_scan_yara", "Evaluate built-in or custom YARA signatures against files/directories"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_verify_yara", "Validate YARA syntax and compile-time prefilters"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_check_hash", "Check SHA-256/SHA-1/MD5/Imphash against IoC databases or providers"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_inspect_binary", "Inspect PE/ELF/Mach-O headers, entropy, packers, and Authenticode DER signatures"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_inspect_document", "Perform static OOXML/OLE2/PDF/LNK/HTA/SVG triage"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_decode_payload", "Run bounded static multi-stage Base64/UTF-16LE/zlib/hex deobfuscation"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_extract_iocs", "Extract and defang IP, domain, URL, and hash IoCs from logs or text"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_diff_allowlist", "Detect hash/size drift against a trusted allowlist manifest"),
		upstreamTool("iocscan", "raksa-iocscan", "iocscan_list_rules", "List all 27 IOC-* malware and forensic rules"),
	)

	// L6 raksa-siem (12)
	specs = append(specs,
		upstreamTool("siem", "raksa-siem", "siem_analyze_logs", "Normalize multi-format logs and correlate SIEM security alerts"),
		upstreamTool("siem", "raksa-siem", "siem_correlate_reports", "Correlate upstream Raksa Layer 1-5 Schema v1 findings in SIEM"),
		upstreamTool("siem", "raksa-siem", "siem_normalize_events", "Normalize raw logs into unified Raksa telemetry schema"),
		upstreamTool("siem", "raksa-siem", "siem_build_timeline", "Build chronological incident timeline across alerts"),
		upstreamTool("siem", "raksa-siem", "siem_query_incidents", "Query active SIEM incidents and severity counts"),
		upstreamTool("siem", "raksa-siem", "siem_triage_case", "Transition or annotate SIEM incident case status"),
		upstreamTool("siem", "raksa-siem", "siem_verify_ledger", "Verify SHA-256 hash-chained SIEM audit ledger segments"),
		upstreamTool("siem", "raksa-siem", "siem_verify_rules", "Validate .raksa-siem.yml custom, sequence, and alert sink rules"),
		upstreamTool("siem", "raksa-siem", "siem_verify_sigma", "Compile and validate native Sigma YAML detection rules"),
		upstreamTool("siem", "raksa-siem", "siem_match_threat_intel", "Match observables against STIX 2.1/CIDR threat intelligence indicators"),
		upstreamTool("siem", "raksa-siem", "siem_check_suppression", "Evaluate suppression/waiver matches cleanly"),
		upstreamTool("siem", "raksa-siem", "siem_list_rules", "List all 23 SIEM-001..502 correlation rules"),
	)

	return specs
}

func localTool(name, desc string, schemaMap map[string]any) ToolSpec {
	return ToolSpec{
		Layer:       schema.LayerName,
		Binary:      schema.ToolName,
		Name:        name,
		Description: desc,
		InputSchema: schemaMap,
	}
}

func upstreamTool(layer, binary, name, desc string) ToolSpec {
	return ToolSpec{
		Layer:       layer,
		Binary:      binary,
		Name:        name,
		Description: fmt.Sprintf("[%s] %s (proxied to %s mcp)", layer, desc, binary),
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": true,
		},
	}
}

type schemaProp struct {
	name string
	desc string
}

func prop(name, desc string) schemaProp {
	return schemaProp{name: name, desc: desc}
}

func objSchema(props ...schemaProp) map[string]any {
	propMap := make(map[string]any, len(props))
	for _, p := range props {
		propMap[p.name] = map[string]any{"type": "string", "description": p.desc}
	}
	return map[string]any{
		"type":                 "object",
		"properties":           propMap,
		"additionalProperties": false,
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeStreams runs the newline-delimited JSON-RPC 2.0 MCP server on stdin/stdout.
func (h *Hub) ServeStreams(stdin io.Reader, stdout io.Writer) error {
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(stdout)

	catalog := Catalog()
	toolIndex := make(map[string]ToolSpec, len(catalog))
	for _, spec := range catalog {
		toolIndex[spec.Name] = spec
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: -32700, Message: "parse error"},
			})
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			// Notification (e.g. notifications/initialized): no response emitted.
			continue
		}
		resp := h.handleRequest(req, catalog, toolIndex)
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("encode mcp response: %w", err)
		}
	}
	return scanner.Err()
}

func (h *Hub) handleRequest(req rpcRequest, catalog []ToolSpec, toolIndex map[string]ToolSpec) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": supportedProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{
					"name":    schema.ToolName,
					"version": schema.Version,
				},
			},
		}
	case "ping":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "tools/list":
		listed := make([]map[string]any, 0, len(catalog))
		for _, spec := range catalog {
			listed = append(listed, map[string]any{
				"name":        spec.Name,
				"description": spec.Description,
				"inputSchema": spec.InputSchema,
			})
		}
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": listed}}
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: "invalid tools/call params"},
			}
		}
		spec, ok := toolIndex[params.Name]
		if !ok {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: fmt.Sprintf("unknown tool %q", params.Name)},
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		text, isErr := h.dispatchTool(ctx, spec, params.Arguments)
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"isError": isErr,
				"content": []map[string]any{
					{"type": "text", "text": text},
				},
			},
		}
	default:
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}

func (h *Hub) dispatchTool(ctx context.Context, spec ToolSpec, rawArgs json.RawMessage) (string, bool) {
	if spec.Layer != schema.LayerName {
		disp := h.UpstreamFn
		if disp == nil {
			disp = h.defaultUpstreamDispatch
		}
		text, isErr, err := disp(ctx, spec.Binary, spec.Name, rawArgs)
		if err != nil {
			return err.Error(), true
		}
		return text, isErr
	}

	args := make(map[string]string)
	if len(bytes.TrimSpace(rawArgs)) > 0 {
		_ = json.Unmarshal(rawArgs, &args)
	}

	switch spec.Name {
	case "raksa_doctor":
		binDir := h.BinDir
		if args["bin_dir"] != "" {
			binDir = args["bin_dir"]
		}
		res := runner.Doctor(ctx, binDir, h.Resolver, h.Exec)
		return mustJSON(res), false
	case "raksa_defense_coverage":
		rows := schema.AttackDefenseMatrix()
		if filter := strings.ToLower(strings.TrimSpace(args["status"])); filter != "" {
			filtered := make([]schema.AttackCoverageRow, 0, len(rows))
			for _, row := range rows {
				if row.Status == filter {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
		}
		return mustJSON(rows), false
	case "raksa_list_playbooks":
		pbs, err := playbook.ListBuiltins()
		if err != nil {
			return err.Error(), true
		}
		return mustJSON(pbs), false
	case "raksa_verify_history":
		if h.History == nil {
			return "history store unavailable", true
		}
		count, ok, reason, err := h.History.VerifyChain()
		if err != nil {
			return err.Error(), true
		}
		return mustJSON(map[string]any{"entries": count, "verified": ok, "reason": reason}), !ok
	case "raksa_plan_remediation":
		target := args["target"]
		if target == "" {
			target = "."
		}
		res := remediate.CollectFixPreviews(ctx, target, h.Remediate)
		return mustJSON(res), false
	case "raksa_posture_summary", "raksa_correlate_all":
		fromPath := strings.TrimSpace(args["from_reports"])
		if fromPath == "" {
			if h.History != nil {
				recs, err := h.History.List(10)
				if err == nil {
					return mustJSON(map[string]any{"recent_runs": recs}), false
				}
			}
			return "from_reports path required when no scan history exists", true
		}
		ups, err := aggregator.LoadReportsFromPath(fromPath)
		if err != nil {
			return err.Error(), true
		}
		merged := aggregator.Merge(ups, nil, aggregator.MergeOptions{
			Profile: "aggregated",
			Target:  fromPath,
			Policy:  policy.DefaultConfig(),
			Now:     time.Now().UTC(),
		})
		return mustJSON(merged), false
	case "raksa_full_audit":
		target := args["target"]
		if target == "" {
			target = "."
		}
		profile := args["profile"]
		if profile == "" {
			profile = "full"
		}
		var explicit []string
		if args["layers"] != "" {
			explicit = []string{args["layers"]}
		}
		cfg, _, _ := policy.Discover(target, "")
		ups, execs, err := runner.RunSuite(ctx, runner.SuiteRequest{
			Profile:        profile,
			ExplicitLayers: explicit,
			Target:         target,
			BinDir:         h.BinDir,
			Policy:         cfg,
		}, h.Resolver, h.Exec)
		if err != nil {
			return err.Error(), true
		}
		merged := aggregator.Merge(ups, execs, aggregator.MergeOptions{
			Profile: profile,
			Target:  target,
			Policy:  cfg,
			Now:     time.Now().UTC(),
		})
		return mustJSON(merged), false
	default:
		return fmt.Sprintf("unhandled local tool %s", spec.Name), true
	}
}

func (h *Hub) defaultUpstreamDispatch(ctx context.Context, binary, toolName string, rawArgs json.RawMessage) (string, bool, error) {
	resolver := h.Resolver
	if resolver == nil {
		resolver = runner.ResolveBinary
	}
	binPath, found := resolver(binary, h.BinDir)
	if !found {
		return "", true, fmt.Errorf("%s is not installed (run 'raksa install --layers %s')", binary, strings.TrimPrefix(binary, "raksa-"))
	}
	if len(bytes.TrimSpace(rawArgs)) == 0 {
		rawArgs = json.RawMessage("{}")
	}

	req1, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]any{"protocolVersion": supportedProtocolVersion},
	})
	reqNotify, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	reqCall, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": json.RawMessage(rawArgs),
		},
	})
	var stdinBuf bytes.Buffer
	stdinBuf.Write(req1)
	stdinBuf.WriteByte('\n')
	stdinBuf.Write(reqNotify)
	stdinBuf.WriteByte('\n')
	stdinBuf.Write(reqCall)
	stdinBuf.WriteByte('\n')

	cmd := exec.CommandContext(ctx, binPath, "mcp")
	cmd.Stdin = &stdinBuf
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return "", true, fmt.Errorf("%s mcp failed: %w (%s)", binary, err, strings.TrimSpace(stderr.String()))
	}

	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var resp struct {
			ID     json.RawMessage `json:"id"`
			Error  *rpcError       `json:"error"`
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			continue
		}
		if strings.TrimSpace(string(resp.ID)) != "2" {
			continue
		}
		if resp.Error != nil {
			return resp.Error.Message, true, nil
		}
		if len(resp.Result.Content) > 0 {
			return resp.Result.Content[0].Text, resp.Result.IsError, nil
		}
		return "{}", resp.Result.IsError, nil
	}
	return "", true, fmt.Errorf("no tools/call response from %s mcp", binary)
}

func mustJSON(v any) string {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(raw)
}
