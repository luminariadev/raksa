// Package policy implements .raksa.yml configuration governance, fail-closed waivers,
// and deterministic SHA-256 finding baseline suppression.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa/internal/schema"
	"gopkg.in/yaml.v3"
)

const DefaultConfigFilename = ".raksa.yml"

// SIEMConfig configures optional Layer 6 raksa-siem connectivity.
type SIEMConfig struct {
	Endpoint   string `yaml:"endpoint" json:"endpoint"`
	TokenEnv   string `yaml:"token_env" json:"token_env"`
	AutoIngest bool   `yaml:"auto_ingest" json:"auto_ingest"`
}

// Waiver defines an audited, time-bounded finding suppression entry.
type Waiver struct {
	RuleID         string `yaml:"rule_id" json:"rule_id"`
	Layer          string `yaml:"layer,omitempty" json:"layer,omitempty"`
	TargetContains string `yaml:"target_contains,omitempty" json:"target_contains,omitempty"`
	Reason         string `yaml:"reason" json:"reason"`
	ExpiresOn      string `yaml:"expires_on" json:"expires_on"`
}

// Config captures declarative Raksa Layer 7 suite governance settings.
type Config struct {
	Profile            string     `yaml:"profile" json:"profile"`
	FailOn             string     `yaml:"fail_on" json:"fail_on"`
	PerLayerTimeoutSec int        `yaml:"per_layer_timeout_sec" json:"per_layer_timeout_sec"`
	MaxConcurrency     int        `yaml:"max_concurrency" json:"max_concurrency"`
	EnabledLayers      []string   `yaml:"enabled_layers,omitempty" json:"enabled_layers,omitempty"`
	DisabledLayers     []string   `yaml:"disabled_layers,omitempty" json:"disabled_layers,omitempty"`
	SIEM               SIEMConfig `yaml:"siem" json:"siem"`
	Waivers            []Waiver   `yaml:"waivers,omitempty" json:"waivers,omitempty"`
}

// Baseline stores deterministic finding fingerprints for regression gating.
type Baseline struct {
	SchemaVersion string   `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Fingerprints  []string `json:"fingerprints"`
}

// DefaultConfig returns baseline suite governance defaults.
func DefaultConfig() Config {
	return Config{
		Profile:            "full",
		FailOn:             "high",
		PerLayerTimeoutSec: 120,
		MaxConcurrency:     4,
		SIEM: SIEMConfig{
			Endpoint: "http://127.0.0.1:8484",
			TokenEnv: "RAKSA_SIEM_TOKEN",
		},
	}
}

// Discover loads explicit configPath if given, or auto-discovers .raksa.yml in dir.
func Discover(dir, configPath string) (Config, string, error) {
	cfg := DefaultConfig()
	if configPath != "" {
		loaded, err := LoadConfig(configPath)
		return loaded, configPath, err
	}
	for _, candidateName := range []string{".raksa.yml", ".raksa.yaml"} {
		candidate := filepath.Join(dir, candidateName)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			loaded, err := LoadConfig(candidate)
			return loaded, candidate, err
		}
	}
	return cfg, "", nil
}

// LoadConfig reads, parses, and validates a .raksa.yml file.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := DefaultConfig()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate enforces fail-closed constraints on config fields and waivers.
func (c *Config) Validate() error {
	if c.FailOn != "" {
		if _, err := schema.ParseSeverity(c.FailOn); err != nil {
			return err
		}
	}
	if c.PerLayerTimeoutSec <= 0 {
		c.PerLayerTimeoutSec = 120
	}
	if c.MaxConcurrency <= 0 {
		c.MaxConcurrency = 4
	}
	for _, raw := range c.EnabledLayers {
		if _, ok := schema.ParseLayerAlias(raw); !ok {
			return fmt.Errorf("unknown enabled layer %q", raw)
		}
	}
	for _, raw := range c.DisabledLayers {
		if _, ok := schema.ParseLayerAlias(raw); !ok {
			return fmt.Errorf("unknown disabled layer %q", raw)
		}
	}
	for idx, w := range c.Waivers {
		if strings.TrimSpace(w.RuleID) == "" && strings.TrimSpace(w.Layer) == "" {
			return fmt.Errorf("waiver[%d] requires rule_id or layer", idx)
		}
		if strings.TrimSpace(w.Reason) == "" {
			return fmt.Errorf("waiver[%d] requires non-empty audit reason", idx)
		}
		if _, err := time.Parse("2006-01-02", strings.TrimSpace(w.ExpiresOn)); err != nil {
			return fmt.Errorf("waiver[%d] expires_on %q must match YYYY-MM-DD: %w", idx, w.ExpiresOn, err)
		}
	}
	return nil
}

// ApplyWaivers filters active, non-expired waivers in fail-closed fashion.
func ApplyWaivers(findings []schema.Finding, waivers []Waiver, now time.Time) ([]schema.Finding, int) {
	if len(waivers) == 0 || len(findings) == 0 {
		return findings, 0
	}
	today := now.UTC().Format("2006-01-02")
	active := make([]Waiver, 0, len(waivers))
	for _, w := range waivers {
		if strings.TrimSpace(w.Reason) == "" {
			continue
		}
		exp := strings.TrimSpace(w.ExpiresOn)
		if _, err := time.Parse("2006-01-02", exp); err != nil {
			continue
		}
		if exp < today {
			continue
		}
		active = append(active, w)
	}
	if len(active) == 0 {
		return findings, 0
	}

	remaining := make([]schema.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if matchesAnyWaiver(f, active) {
			suppressed++
			continue
		}
		remaining = append(remaining, f)
	}
	return remaining, suppressed
}

func matchesAnyWaiver(f schema.Finding, waivers []Waiver) bool {
	for _, w := range waivers {
		if w.RuleID != "" && !strings.EqualFold(strings.TrimSpace(w.RuleID), strings.TrimSpace(f.RuleID)) {
			continue
		}
		if w.Layer != "" {
			wantLayer, ok := schema.ParseLayerAlias(w.Layer)
			gotLayer, ok2 := schema.ParseLayerAlias(f.Layer)
			if !ok || !ok2 || wantLayer != gotLayer {
				continue
			}
		}
		if w.TargetContains != "" && !strings.Contains(f.Target, w.TargetContains) {
			continue
		}
		return true
	}
	return false
}

// Fingerprint computes a stable SHA-256 identity key for baseline comparison.
func Fingerprint(f schema.Finding) string {
	canonical := strings.Join([]string{
		strings.ToLower(strings.TrimSpace(f.Layer)),
		strings.ToUpper(strings.TrimSpace(f.RuleID)),
		strings.TrimSpace(f.Target),
		strings.TrimSpace(f.Title),
	}, "\x00")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// BuildBaseline constructs a sorted, deduplicated baseline snapshot from findings.
func BuildBaseline(findings []schema.Finding, now time.Time) Baseline {
	seen := make(map[string]struct{}, len(findings))
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		fp := Fingerprint(f)
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	return Baseline{
		SchemaVersion: schema.SchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Fingerprints:  fps,
	}
}

// SaveBaseline writes a baseline snapshot as formatted JSON.
func SaveBaseline(path string, b Baseline) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create baseline directory: %w", err)
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

// LoadBaseline reads a saved baseline snapshot from disk.
func LoadBaseline(path string) (Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return b, nil
}

// ApplyBaseline removes findings whose SHA-256 fingerprint appears in baseline.
func ApplyBaseline(findings []schema.Finding, b Baseline) ([]schema.Finding, int) {
	if len(b.Fingerprints) == 0 || len(findings) == 0 {
		return findings, 0
	}
	known := make(map[string]struct{}, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		known[fp] = struct{}{}
	}
	remaining := make([]schema.Finding, 0, len(findings))
	baselined := 0
	for _, f := range findings {
		if _, ok := known[Fingerprint(f)]; ok {
			baselined++
			continue
		}
		remaining = append(remaining, f)
	}
	return remaining, baselined
}
