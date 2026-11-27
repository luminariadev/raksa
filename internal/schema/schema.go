// Package schema defines Raksa Layer 7 Finding Schema v1 models, layer metadata,
// posture scoring, severity thresholds, and the Attack-vs-Defense matrix.
package schema

import (
	"fmt"
	"sort"
	"strings"
)

var (
	// Version is the semantic version of raksa; overridden at release build time via ldflags.
	Version = "0.1.0"
	// Commit is injected via ldflags when built in CI/release pipelines.
	Commit = "dev"
	// BuildDate is injected via ldflags when built in CI/release pipelines.
	BuildDate = "unknown"
)

const (
	// SchemaVersion identifies the Raksa Unified Finding Schema contract version.
	SchemaVersion = "1.0"
	// ToolName is the canonical CLI and MCP server identifier for Layer 7.
	ToolName = "raksa"
	// LayerName is the Layer 7 orchestrator slug.
	LayerName = "orchestrator"
)

// Severity represents normalized Raksa finding severity levels and threshold filters.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityNone     Severity = "none"
)

// Finding conforms to Raksa Finding Schema v1 emitted by Layers 1-7.
type Finding struct {
	ID          string         `json:"id" yaml:"id"`
	RuleID      string         `json:"rule_id" yaml:"rule_id"`
	Module      string         `json:"module,omitempty" yaml:"module,omitempty"`
	Layer       string         `json:"layer" yaml:"layer"`
	Tool        string         `json:"tool,omitempty" yaml:"tool,omitempty"`
	Severity    Severity       `json:"severity" yaml:"severity"`
	Title       string         `json:"title" yaml:"title"`
	Description string         `json:"description" yaml:"description"`
	Target      string         `json:"target" yaml:"target"`
	Evidence    map[string]any `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	MitreD3FEND string         `json:"mitre_d3fend,omitempty" yaml:"mitre_d3fend,omitempty"`
	Compliance  []string       `json:"compliance,omitempty" yaml:"compliance,omitempty"`
	Timestamp   string         `json:"timestamp" yaml:"timestamp"`
}

// Summary counts findings per severity bucket.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// PostureScore quantifies overall defensive posture on a 0-100 (A+..F) scale.
type PostureScore struct {
	Score int    `json:"score"`
	Grade string `json:"grade"`
}

// LayerSpec captures static catalog metadata for each Raksa L1-L6 module.
type LayerSpec struct {
	Number      int    `json:"number"`
	ID          string `json:"id"`
	LayerSlug   string `json:"layer_slug"`
	Binary      string `json:"binary"`
	Repository  string `json:"repository"`
	Language    string `json:"language"`
	Version     string `json:"version"`
	RuleCount   int    `json:"rule_count"`
	MCPCount    int    `json:"mcp_count"`
	RulePrefix  string `json:"rule_prefix"`
	Description string `json:"description"`
}

// LayerExecution summarizes execution status and posture for one layer in a scan run.
type LayerExecution struct {
	Layer         string       `json:"layer"`
	Binary        string       `json:"binary"`
	Version       string       `json:"version,omitempty"`
	Status        string       `json:"status"` // ok, findings, not_installed, skipped, error
	ExitCode      int          `json:"exit_code"`
	DurationMs    int64        `json:"duration_ms"`
	FindingsCount int          `json:"findings_count"`
	Posture       PostureScore `json:"posture"`
	Message       string       `json:"message,omitempty"`
}

// ToolDoctorStatus reports installation and integrity probe details for one tool binary.
type ToolDoctorStatus struct {
	Number     int    `json:"number"`
	ID         string `json:"id"`
	Binary     string `json:"binary"`
	Repository string `json:"repository"`
	Installed  bool   `json:"installed"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	RuleCount  int    `json:"rule_count"`
	MCPCount   int    `json:"mcp_count"`
	Status     string `json:"status"` // ready, missing, error
	Hint       string `json:"hint,omitempty"`
}

// SuiteReport is the unified Layer 7 Finding Schema v1 envelope.
type SuiteReport struct {
	SchemaVersion      string            `json:"schema_version"`
	Tool               string            `json:"tool"`
	Version            string            `json:"version"`
	Layer              string            `json:"layer"`
	Edition            string            `json:"edition,omitempty"`
	Profile            string            `json:"profile"`
	Target             string            `json:"target"`
	GeneratedAt        string            `json:"generated_at"`
	Posture            PostureScore      `json:"posture"`
	Summary            Summary           `json:"summary"`
	SuppressedCount    int               `json:"suppressed_count"`
	BaselinedCount     int               `json:"baselined_count"`
	DeduplicatedCount  int               `json:"deduplicated_count"`
	Layers             []LayerExecution  `json:"layers"`
	Findings           []Finding         `json:"findings"`
	ComplianceCoverage map[string]int    `json:"compliance_coverage,omitempty"`
	SIEMIngested       bool              `json:"siem_ingested,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// AttackCoverageRow maps an offensive threat domain to Raksa defensive controls.
type AttackCoverageRow struct {
	Category     string   `json:"category"`
	MitreAttack  string   `json:"mitre_attack"`
	MitreD3FEND  string   `json:"mitre_d3fend"`
	Layers       []string `json:"layers"`
	RuleRanges   string   `json:"rule_ranges"`
	Status       string   `json:"status"` // covered, partial, planned
	Command      string   `json:"command"`
	DefensiveAim string   `json:"defensive_aim"`
}

// FixPreviewItem stores a read-only unified remediation patch from an upstream tool.
type FixPreviewItem struct {
	Layer          string   `json:"layer"`
	Tool           string   `json:"tool"`
	Target         string   `json:"target"`
	RulesAddressed []string `json:"rules_addressed,omitempty"`
	Format         string   `json:"format"`
	Diff           string   `json:"diff"`
}

// ParseSeverity validates and normalizes a severity or threshold string.
func ParseSeverity(raw string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "info":
		return SeverityInfo, nil
	case "none", "":
		return SeverityNone, nil
	default:
		return "", fmt.Errorf("invalid severity %q (expected critical, high, medium, low, info, none)", raw)
	}
}

// SeverityRank maps severities to comparable numeric ranks.
func SeverityRank(s Severity) int {
	switch strings.ToLower(string(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// MeetsThreshold checks whether any finding meets or exceeds failOn threshold.
func MeetsThreshold(findings []Finding, failOn Severity) bool {
	if failOn == "" || failOn == SeverityNone {
		return false
	}
	minRank := SeverityRank(failOn)
	if minRank == 0 {
		return false
	}
	for _, f := range findings {
		if SeverityRank(f.Severity) >= minRank {
			return true
		}
	}
	return false
}

// BuildSummary tallies findings by severity.
func BuildSummary(findings []Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		case "info":
			s.Info++
		}
	}
	return s
}

// ComputePosture calculates the suite-wide 0-100 posture score and A+..F letter grade.
func ComputePosture(findings []Finding) PostureScore {
	score := 100
	for _, f := range findings {
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			score -= 25
		case "high":
			score -= 15
		case "medium":
			score -= 7
		case "low":
			score -= 3
		}
	}
	if score < 0 {
		score = 0
	}
	return PostureScore{
		Score: score,
		Grade: gradeForScore(score),
	}
}

func gradeForScore(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// SortFindings sorts findings deterministically from highest severity to lowest.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri := SeverityRank(findings[i].Severity)
		rj := SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].Layer != findings[j].Layer {
			return findings[i].Layer < findings[j].Layer
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		return findings[i].ID < findings[j].ID
	})
}

// LayerCatalog returns metadata for all six shipped defensive layers (L1-L6).
func LayerCatalog() []LayerSpec {
	return []LayerSpec{
		{
			Number:      1,
			ID:          "netguard",
			LayerSlug:   "network-defense",
			Binary:      "raksa-netguard",
			Repository:  "luminariadev/raksa-netguard",
			Language:    "Go",
			Version:     "0.3.0",
			RuleCount:   10,
			MCPCount:    5,
			RulePrefix:  "NET-",
			Description: "Local listener baseline auditor and sliding-window port-scan/burst detector",
		},
		{
			Number:      2,
			ID:          "hostguard",
			LayerSlug:   "host-hardening",
			Binary:      "raksa-hostguard",
			Repository:  "luminariadev/raksa-hostguard",
			Language:    "Rust",
			Version:     "0.3.0",
			RuleCount:   29,
			MCPCount:    9,
			RulePrefix:  "HOST-",
			Description: "HMAC-signed event-driven FIM and Linux/SSH/Docker/systemd CIS hardening auditor",
		},
		{
			Number:      3,
			ID:          "webshield",
			LayerSlug:   "web-defense",
			Binary:      "raksa-webshield",
			Repository:  "luminariadev/raksa-webshield",
			Language:    "Go + TypeScript",
			Version:     "0.3.0",
			RuleCount:   30,
			MCPCount:    8,
			RulePrefix:  "WEB-",
			Description: "HTTP header/CSP/CORS/TLS auditor, reverse-proxy config linter, and WAF sidecar",
		},
		{
			Number:      4,
			ID:          "pipeguard",
			LayerSlug:   "devsecops",
			Binary:      "raksa-pipeguard",
			Repository:  "luminariadev/raksa-pipeguard",
			Language:    "Go",
			Version:     "0.3.0",
			RuleCount:   33,
			MCPCount:    9,
			RulePrefix:  "PIPE-",
			Description: "Secrets, CycloneDX/SPDX SBOM, OSV/KEV/EPSS CVEs, OCI image, and IaC/CI gate",
		},
		{
			Number:      5,
			ID:          "iocscan",
			LayerSlug:   "ioc-defense",
			Binary:      "raksa-iocscan",
			Repository:  "luminariadev/raksa-iocscan",
			Language:    "Python",
			Version:     "0.3.0",
			RuleCount:   27,
			MCPCount:    10,
			RulePrefix:  "IOC-",
			Description: "Pure-Python YARA engine, Imphash/FastCDC, PE/ELF/Mach-O/archive malware triage",
		},
		{
			Number:      6,
			ID:          "siem",
			LayerSlug:   "observability-siem",
			Binary:      "raksa-siem",
			Repository:  "luminariadev/raksa-siem",
			Language:    "Go + Python",
			Version:     "0.3.0",
			RuleCount:   23,
			MCPCount:    12,
			RulePrefix:  "SIEM-",
			Description: "13-format normalizer, Sigma/EQL correlator, attack graph, and hash-chained audit ledger",
		},
	}
}

// ParseLayerAlias normalizes user-supplied layer names (e.g. "l1", "raksa-netguard", "netguard").
func ParseLayerAlias(raw string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	switch norm {
	case "1", "l1", "netguard", "raksa-netguard", "network-defense":
		return "netguard", true
	case "2", "l2", "hostguard", "raksa-hostguard", "host-hardening":
		return "hostguard", true
	case "3", "l3", "webshield", "raksa-webshield", "web-defense":
		return "webshield", true
	case "4", "l4", "pipeguard", "raksa-pipeguard", "devsecops":
		return "pipeguard", true
	case "5", "l5", "iocscan", "raksa-iocscan", "ioc-defense":
		return "iocscan", true
	case "6", "l6", "siem", "raksa-siem", "observability-siem":
		return "siem", true
	default:
		return "", false
	}
}

// TotalCatalogCounts returns total shipped rule count (152) and L1-L6 MCP tool count (53).
func TotalCatalogCounts() (rules int, mcpTools int) {
	for _, spec := range LayerCatalog() {
		rules += spec.RuleCount
		mcpTools += spec.MCPCount
	}
	return rules, mcpTools
}

// AttackDefenseMatrix returns the defensive countermeasure coverage map against common attack classes.
func AttackDefenseMatrix() []AttackCoverageRow {
	return []AttackCoverageRow{
		{
			Category:     "Reconnaissance & Port Scanning",
			MitreAttack:  "T1046",
			MitreD3FEND:  "D3-NTA",
			Layers:       []string{"netguard", "siem"},
			RuleRanges:   "NET-001..104, SIEM-101..104",
			Status:       "covered",
			Command:      "raksa scan --layers netguard,siem",
			DefensiveAim: "Detect open listener drift, vertical/horizontal/distributed scans, and anomalous bursts",
		},
		{
			Category:     "SQL Injection & Command Injection",
			MitreAttack:  "T1190 / T1059",
			MitreD3FEND:  "D3-ITF",
			Layers:       []string{"webshield", "siem"},
			RuleRanges:   "WEB-301, WEB-308, SIEM-103",
			Status:       "covered",
			Command:      "raksa-webshield inspect-request --payload \"...\"",
			DefensiveAim: "Zero-CGO semantic SQLi/XSS tokenizer, WAF sidecar blocking, and SIEM alert correlation",
		},
		{
			Category:     "XSS, CSRF, Clickjacking & Session Theft",
			MitreAttack:  "T1059.007 / T1185",
			MitreD3FEND:  "D3-SRA",
			Layers:       []string{"webshield"},
			RuleRanges:   "WEB-001..104, WEB-302",
			Status:       "covered",
			Command:      "raksa scan --profile web --path .",
			DefensiveAim: "Strict CSP nonce, HttpOnly/SameSite cookies, COOP/CORP/CORS, and DOM sanitizer",
		},
		{
			Category:     "SSH Brute Force & Credential Stuffing",
			MitreAttack:  "T1110",
			MitreD3FEND:  "D3-LAM",
			Layers:       []string{"hostguard", "siem"},
			RuleRanges:   "HOST-101..106, HOST-307, SIEM-101",
			Status:       "covered",
			Command:      "raksa scan --profile host",
			DefensiveAim: "Disable root/password SSH login, enforce PAM lockout, correlate auth brute force bursts",
		},
		{
			Category:     "Privilege Escalation & Persistence Hooks",
			MitreAttack:  "T1543 / T1053 / T1548",
			MitreD3FEND:  "D3-FIM",
			Layers:       []string{"hostguard", "iocscan"},
			RuleRanges:   "HOST-001..005, HOST-301..308, IOC-201..210",
			Status:       "covered",
			Command:      "raksa scan --profile host --path /etc",
			DefensiveAim: "Audit sudoers/SUID/systemd/cron/PAM/auditd and detect HMAC baseline drift",
		},
		{
			Category:     "Malware Payloads, RATs & Obfuscated Loaders",
			MitreAttack:  "T1204 / T1027",
			MitreD3FEND:  "D3-FA",
			Layers:       []string{"iocscan", "siem"},
			RuleRanges:   "IOC-001..211, SIEM-206",
			Status:       "covered",
			Command:      "raksa scan --layers iocscan,siem --path .",
			DefensiveAim: "YARA matching, Imphash/FastCDC fuzzy matching, Authenticode/PE/ELF inspection, deobfuscation",
		},
		{
			Category:     "Malicious Documents & Archive Bombs",
			MitreAttack:  "T1566.001 / T1204.002",
			MitreD3FEND:  "D3-DA",
			Layers:       []string{"iocscan"},
			RuleRanges:   "IOC-207..209, IOC-401..404",
			Status:       "covered",
			Command:      "raksa-iocscan scan --path ./uploads",
			DefensiveAim: "Static OOXML/OLE2/PDF/LNK/HTA/SVG triage and bounded ZIP/TAR/7z/RAR inspection",
		},
		{
			Category:     "Secret Leaks & Supply-Chain CVEs (KEV/EPSS)",
			MitreAttack:  "T1552 / T1195",
			MitreD3FEND:  "D3-SYSV",
			Layers:       []string{"pipeguard"},
			RuleRanges:   "PIPE-001..106",
			Status:       "covered",
			Command:      "raksa scan --profile repo --path .",
			DefensiveAim: "Secret entropy scanning, SBOM CycloneDX/SPDX, OSV/KEV/EPSS CVEs, license compliance",
		},
		{
			Category:     "Container Breakout & CI/CD Pipeline Poisoning",
			MitreAttack:  "T1611 / T1525",
			MitreD3FEND:  "D3-CISC",
			Layers:       []string{"hostguard", "pipeguard"},
			RuleRanges:   "HOST-201..210, PIPE-201..408",
			Status:       "covered",
			Command:      "raksa scan --profile repo --path .",
			DefensiveAim: "Docker/Compose/daemon.json CIS audits, OCI tarball scan, GHA/GitLab CI/Terraform checks",
		},
		{
			Category:     "Multi-Stage Attack Chains & Audit Log Tampering",
			MitreAttack:  "T1070 / T1078",
			MitreD3FEND:  "D3-AL",
			Layers:       []string{"siem", "hostguard"},
			RuleRanges:   "SIEM-001..502, HOST-005",
			Status:       "covered",
			Command:      "raksa scan --profile incident --path .",
			DefensiveAim: "EQL/Sigma sequence correlation, STIX threat intel, and SHA-256 hash-chained audit ledger",
		},
		{
			Category:     "Web/L7 DoS & SYN/Slowloris Flood Readiness",
			MitreAttack:  "T1498 / T1499",
			MitreD3FEND:  "D3-ITF",
			Layers:       []string{"netguard", "hostguard", "webshield"},
			RuleRanges:   "NET-103, HOST-301, WEB-312",
			Status:       "partial",
			Command:      "raksa playbooks run --name ddos-readiness --path .",
			DefensiveAim: "Verify tcp_syncookies, proxy bounded LRU rate limiting, and connection burst detection",
		},
		{
			Category:     "C2 Beaconing & DNS Tunneling Egress",
			MitreAttack:  "T1071.004 / T1573",
			MitreD3FEND:  "D3-DNSAL",
			Layers:       []string{"netguard", "siem"},
			RuleRanges:   "NET-105..107 (v0.4.0), SIEM-502",
			Status:       "partial",
			Command:      "raksa-siem analyze <logs> --format html",
			DefensiveAim: "Currently catches STIX/CIDR IOCs in SIEM; periodic jitter and NXDOMAIN burst planned for v0.4.0",
		},
		{
			Category:     "Phishing Infrastructure & DNS/Email Spoofing",
			MitreAttack:  "T1566 / T1583",
			MitreD3FEND:  "D3-DNSDL",
			Layers:       []string{"orchestrator", "webshield"},
			RuleRanges:   "WEB-001..010, Planned DNS Posture",
			Status:       "planned",
			Command:      "raksa attack-matrix --format table",
			DefensiveAim: "Planned v0.4.0 read-only SPF/DKIM/DMARC/DNSSEC domain posture validation",
		},
		{
			Category:     "Active Directory & Windows/macOS Host Drift",
			MitreAttack:  "T1087 / T1558",
			MitreD3FEND:  "D3-HDA",
			Layers:       []string{"hostguard", "netguard"},
			RuleRanges:   "HOST-4xx (v0.4.0)",
			Status:       "planned",
			Command:      "raksa scan --profile host",
			DefensiveAim: "Planned v0.4.0 read-only RDP/WinRM/Defender/FileVault/SIP auditors and Ed25519 FIM",
		},
		{
			Category:     "OpenAPI / GraphQL & Request Smuggling Evasion",
			MitreAttack:  "T1190",
			MitreD3FEND:  "D3-SVA",
			Layers:       []string{"webshield"},
			RuleRanges:   "WEB-401..404, WEB-313..314 (v0.4.0)",
			Status:       "planned",
			Command:      "raksa scan --profile web",
			DefensiveAim: "Planned v0.4.0 schema introspection, depth bombs, JWT alg:none, and CL.TE smuggling checks",
		},
		{
			Category:     "Evaluated Terraform Plans & Cosign Provenance",
			MitreAttack:  "T1195.002",
			MitreD3FEND:  "D3-SYSV",
			Layers:       []string{"pipeguard"},
			RuleRanges:   "PIPE-107, PIPE-409..410 (v0.4.0)",
			Status:       "planned",
			Command:      "raksa scan --profile repo --path .",
			DefensiveAim: "Planned v0.4.0 terraform show -json, OpenVEX filtering, and Cosign SLSA verification",
		},
	}
}
