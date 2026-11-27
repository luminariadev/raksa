// Package ext defines clean Open-Core extension boundaries allowing private
// enterprise builds (via Go build tags) without forking the Apache-2.0 core.
package ext

import (
	"context"
	"strings"

	"github.com/luminariadev/raksa/internal/schema"
)

// EditionMetadata describes the runtime distribution tier and license.
type EditionMetadata struct {
	Edition       string   `json:"edition"`
	License       string   `json:"license"`
	Capabilities  []string `json:"capabilities"`
	EnterpriseURL string   `json:"enterprise_url,omitempty"`
}

// AuthProvider abstracts operator identity verification for Web UI and API tiers.
type AuthProvider interface {
	Name() string
	ValidateToken(ctx context.Context, token string) (subject string, role string, ok bool)
}

// ComplianceMapper enriches findings with framework control IDs (CIS, OWASP, MITRE).
type ComplianceMapper interface {
	Name() string
	ControlsFor(f schema.Finding) []string
}

// LocalAuthProvider is the single-operator open-source default authenticator.
type LocalAuthProvider struct {
	ExpectedToken string
}

// Name returns the OSS authenticator identifier.
func (LocalAuthProvider) Name() string { return "local-token" }

// ValidateToken verifies a local operator token in single-user mode.
func (p LocalAuthProvider) ValidateToken(_ context.Context, token string) (string, string, bool) {
	if p.ExpectedToken == "" {
		return "local-operator", "admin", true
	}
	if token == p.ExpectedToken {
		return "local-operator", "admin", true
	}
	return "", "", false
}

// OSSComplianceMapper provides deterministic MITRE D3FEND, CIS, and OWASP mappings.
type OSSComplianceMapper struct{}

// Name returns the OSS compliance mapper identifier.
func (OSSComplianceMapper) Name() string { return "oss-baseline-mapper" }

// ControlsFor returns standardized defensive control references for a finding.
func (OSSComplianceMapper) ControlsFor(f schema.Finding) []string {
	controls := make([]string, 0, 3)
	if f.MitreD3FEND != "" {
		controls = append(controls, "MITRE:"+strings.ToUpper(strings.TrimSpace(f.MitreD3FEND)))
	}
	rule := strings.ToUpper(strings.TrimSpace(f.RuleID))
	switch {
	case strings.HasPrefix(rule, "NET-"):
		controls = append(controls, "CIS-Network-Baseline")
	case strings.HasPrefix(rule, "HOST-2"):
		controls = append(controls, "CIS-Docker-Benchmark")
	case strings.HasPrefix(rule, "HOST-"):
		controls = append(controls, "CIS-Linux-Benchmark")
	case strings.HasPrefix(rule, "WEB-"):
		controls = append(controls, "OWASP-ASVS-4.0")
	case strings.HasPrefix(rule, "PIPE-"):
		controls = append(controls, "SLSA-DevSecOps-Gate")
	case strings.HasPrefix(rule, "IOC-"):
		controls = append(controls, "NIST-800-83-Malware")
	case strings.HasPrefix(rule, "SIEM-"):
		controls = append(controls, "NIST-AU-Audit-Correlation")
	}
	return controls
}

// DefaultEdition reports the Apache-2.0 Open-Source core edition metadata.
func DefaultEdition() EditionMetadata {
	return EditionMetadata{
		Edition: "oss",
		License: "Apache-2.0",
		Capabilities: []string{
			"hybrid-orchestrator",
			"unified-mcp-hub",
			"hash-chained-history",
			"sarif-markdown-html-export",
			"read-only-fix-preview",
		},
		EnterpriseURL: "https://github.com/luminariadev/raksa/blob/main/docs/OPEN_CORE_MODEL.md",
	}
}
