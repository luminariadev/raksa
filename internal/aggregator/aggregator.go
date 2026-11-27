// Package aggregator parses, deduplicates, and merges Finding Schema v1 outputs
// emitted by Raksa Layers 1-6 into unified SuiteReports.
package aggregator

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa/internal/ext"
	"github.com/luminariadev/raksa/internal/policy"
	"github.com/luminariadev/raksa/internal/schema"
)

// UpstreamReport represents a parsed Finding Schema v1 envelope from a single tool/layer.
type UpstreamReport struct {
	Source        string           `json:"source,omitempty"`
	SchemaVersion string           `json:"schema_version"`
	Tool          string           `json:"tool"`
	Version       string           `json:"version,omitempty"`
	Layer         string           `json:"layer"`
	GeneratedAt   string           `json:"generated_at"`
	Findings      []schema.Finding `json:"findings"`
}

// MergeOptions configures deduplication, compliance enrichment, waivers, and baselines.
type MergeOptions struct {
	Profile    string
	Target     string
	Policy     policy.Config
	Baseline   *policy.Baseline
	Compliance ext.ComplianceMapper
	Now        time.Time
}

// ParseReportBytes parses either a Schema v1 JSON report object or NDJSON finding lines.
func ParseReportBytes(raw []byte, source string) (UpstreamReport, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return UpstreamReport{}, fmt.Errorf("empty report payload from %s", source)
	}

	if trimmed[0] == '{' && json.Valid(trimmed) {
		var single schema.Finding
		if err := json.Unmarshal(trimmed, &single); err == nil && single.RuleID != "" {
			env := UpstreamReport{
				Source:        source,
				SchemaVersion: schema.SchemaVersion,
				Tool:          single.Tool,
				Layer:         single.Layer,
				Findings:      []schema.Finding{single},
			}
			normalizeUpstreamFindings(&env, source)
			return env, nil
		}
		var env UpstreamReport
		if err := json.Unmarshal(trimmed, &env); err == nil && (env.Findings != nil || env.SchemaVersion != "" || env.Tool != "") {
			normalizeUpstreamFindings(&env, source)
			return env, nil
		}
	}

	// Fallback: NDJSON stream of Finding objects (used by --siem-out and ndjson outputs).
	var findings []schema.Finding
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var f schema.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			return UpstreamReport{}, fmt.Errorf("parse NDJSON finding from %s: %w", source, err)
		}
		if f.RuleID == "" && f.Title == "" {
			continue
		}
		findings = append(findings, f)
	}
	if err := scanner.Err(); err != nil {
		return UpstreamReport{}, fmt.Errorf("scan NDJSON from %s: %w", source, err)
	}
	if len(findings) == 0 {
		return UpstreamReport{}, fmt.Errorf("no valid Schema v1 findings decoded from %s", source)
	}
	env := UpstreamReport{
		Source:        source,
		SchemaVersion: schema.SchemaVersion,
		Tool:          findings[0].Tool,
		Layer:         findings[0].Layer,
		Findings:      findings,
	}
	normalizeUpstreamFindings(&env, source)
	return env, nil
}

func normalizeUpstreamFindings(env *UpstreamReport, source string) {
	env.Source = source
	if env.SchemaVersion == "" {
		env.SchemaVersion = schema.SchemaVersion
	}
	for i := range env.Findings {
		f := &env.Findings[i]
		if f.Layer == "" {
			f.Layer = env.Layer
		}
		if f.Tool == "" {
			f.Tool = env.Tool
		}
		if f.Severity == "" {
			f.Severity = schema.SeverityInfo
		} else {
			f.Severity = schema.Severity(strings.ToLower(string(f.Severity)))
		}
	}
}

// LoadReportsFromPath reads one report file or recursively collects *.json / *.ndjson in a dir.
func LoadReportsFromPath(path string) ([]UpstreamReport, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat report path %s: %w", path, err)
	}
	if !info.IsDir() {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read report %s: %w", path, err)
		}
		rep, err := ParseReportBytes(raw, path)
		if err != nil {
			return nil, err
		}
		return []UpstreamReport{rep}, nil
	}

	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		extName := strings.ToLower(filepath.Ext(d.Name()))
		if extName == ".json" || extName == ".ndjson" || extName == ".jsonl" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk reports dir %s: %w", path, err)
	}
	sort.Strings(files)

	reports := make([]UpstreamReport, 0, len(files))
	for _, file := range files {
		raw, readErr := os.ReadFile(file)
		if readErr != nil {
			return nil, fmt.Errorf("read report %s: %w", file, readErr)
		}
		rep, parseErr := ParseReportBytes(raw, file)
		if parseErr != nil {
			return nil, parseErr
		}
		reports = append(reports, rep)
	}
	if len(reports) == 0 {
		return nil, fmt.Errorf("no Schema v1 report files found in %s", path)
	}
	return reports, nil
}

// Merge combines upstream reports and execution metadata into a deduplicated SuiteReport.
func Merge(reports []UpstreamReport, executions []schema.LayerExecution, opts MergeOptions) schema.SuiteReport {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	mapper := opts.Compliance
	if mapper == nil {
		mapper = ext.OSSComplianceMapper{}
	}

	rawFindings := make([]schema.Finding, 0)
	for _, r := range reports {
		rawFindings = append(rawFindings, r.Findings...)
	}

	deduped, dedupCount := deduplicateFindings(rawFindings)
	afterWaiver, suppressedCount := policy.ApplyWaivers(deduped, opts.Policy.Waivers, now)

	finalFindings := afterWaiver
	baselinedCount := 0
	if opts.Baseline != nil {
		finalFindings, baselinedCount = policy.ApplyBaseline(afterWaiver, *opts.Baseline)
	}

	complianceTotals := make(map[string]int)
	for i := range finalFindings {
		if len(finalFindings[i].Compliance) == 0 {
			finalFindings[i].Compliance = mapper.ControlsFor(finalFindings[i])
		}
		for _, ctrl := range finalFindings[i].Compliance {
			complianceTotals[ctrl]++
		}
	}

	schema.SortFindings(finalFindings)

	execOut := buildLayerSummaries(executions, reports, finalFindings)
	profile := strings.TrimSpace(opts.Profile)
	if profile == "" {
		profile = "full"
	}
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		target = "."
	}

	return schema.SuiteReport{
		SchemaVersion:      schema.SchemaVersion,
		Tool:               schema.ToolName,
		Version:            schema.Version,
		Layer:              schema.LayerName,
		Edition:            ext.DefaultEdition().Edition,
		Profile:            profile,
		Target:             target,
		GeneratedAt:        now.UTC().Format(time.RFC3339),
		Posture:            schema.ComputePosture(finalFindings),
		Summary:            schema.BuildSummary(finalFindings),
		SuppressedCount:    suppressedCount,
		BaselinedCount:     baselinedCount,
		DeduplicatedCount:  dedupCount,
		Layers:             execOut,
		Findings:           finalFindings,
		ComplianceCoverage: complianceTotals,
	}
}

func deduplicateFindings(in []schema.Finding) ([]schema.Finding, int) {
	if len(in) == 0 {
		return []schema.Finding{}, 0
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]schema.Finding, 0, len(in))
	dropped := 0
	for _, f := range in {
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(f.Layer)),
			strings.ToUpper(strings.TrimSpace(f.RuleID)),
			strings.TrimSpace(f.Target),
			strings.TrimSpace(f.Title),
		}, "\x00")
		if _, exists := seen[key]; exists {
			dropped++
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out, dropped
}

func buildLayerSummaries(executions []schema.LayerExecution, reports []UpstreamReport, activeFindings []schema.Finding) []schema.LayerExecution {
	byLayerFindings := make(map[string][]schema.Finding)
	for _, f := range activeFindings {
		id, ok := schema.ParseLayerAlias(f.Layer)
		if !ok {
			id = strings.ToLower(strings.TrimSpace(f.Layer))
		}
		byLayerFindings[id] = append(byLayerFindings[id], f)
	}

	if len(executions) > 0 {
		out := make([]schema.LayerExecution, 0, len(executions))
		for _, ex := range executions {
			lf := byLayerFindings[ex.Layer]
			ex.FindingsCount = len(lf)
			ex.Posture = schema.ComputePosture(lf)
			if ex.Status == "ok" && len(lf) > 0 {
				ex.Status = "findings"
			}
			out = append(out, ex)
		}
		return out
	}

	presentLayers := make(map[string]string)
	for _, r := range reports {
		id, ok := schema.ParseLayerAlias(r.Layer)
		if ok {
			presentLayers[id] = r.Tool
		}
	}
	catalog := schema.LayerCatalog()
	out := make([]schema.LayerExecution, 0, len(catalog))
	for _, spec := range catalog {
		lf := byLayerFindings[spec.ID]
		status := "not_run"
		if _, ok := presentLayers[spec.ID]; ok {
			status = "ok"
			if len(lf) > 0 {
				status = "findings"
			}
		}
		out = append(out, schema.LayerExecution{
			Layer:         spec.ID,
			Binary:        spec.Binary,
			Status:        status,
			FindingsCount: len(lf),
			Posture:       schema.ComputePosture(lf),
		})
	}
	return out
}

// ToNDJSON encodes findings as newline-delimited JSON suitable for raksa-siem correlate.
func ToNDJSON(findings []schema.Finding) ([]byte, error) {
	var buf bytes.Buffer
	for _, f := range findings {
		line, err := json.Marshal(f)
		if err != nil {
			return nil, fmt.Errorf("marshal finding %s: %w", f.ID, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}
