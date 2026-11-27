// Package report renders SuiteReports into table, JSON, SARIF 2.1.0, Markdown, and offline HTML.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"unicode"

	"github.com/luminariadev/raksa/internal/schema"
)

// Format identifies a supported Layer 7 output renderer.
type Format string

const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// ParseFormat validates user-supplied report format flags.
func ParseFormat(raw string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "table":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	case "md", "markdown":
		return FormatMarkdown, nil
	case "html":
		return FormatHTML, nil
	default:
		return "", fmt.Errorf("invalid format %q (expected table, json, sarif, markdown, html)", raw)
	}
}

// Render converts a SuiteReport into the requested output format bytes.
func Render(rep schema.SuiteReport, format Format) ([]byte, error) {
	switch format {
	case FormatTable:
		return []byte(renderTable(rep)), nil
	case FormatJSON:
		raw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode json report: %w", err)
		}
		return append(raw, '\n'), nil
	case FormatSARIF:
		return renderSARIF(rep)
	case FormatMarkdown:
		return []byte(renderMarkdown(rep)), nil
	case FormatHTML:
		return renderHTML(rep)
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}

func renderTable(rep schema.SuiteReport) string {
	var b strings.Builder
	fmt.Fprintf(
		&b,
		"raksa v%s | layer: %s | profile: %s | score: %d/100 (%s) | total: %d (critical: %d, high: %d, medium: %d, low: %d, info: %d)\n",
		sanitizeText(rep.Version),
		sanitizeText(rep.Layer),
		sanitizeText(rep.Profile),
		rep.Posture.Score,
		sanitizeText(rep.Posture.Grade),
		rep.Summary.Total,
		rep.Summary.Critical,
		rep.Summary.High,
		rep.Summary.Medium,
		rep.Summary.Low,
		rep.Summary.Info,
	)

	if len(rep.Layers) > 0 {
		b.WriteString("\nLayers:\n")
		for _, l := range rep.Layers {
			fmt.Fprintf(
				&b,
				"  %-10s status=%-13s score=%3d (%-2s) findings=%d %s\n",
				sanitizeText(l.Layer),
				sanitizeText(l.Status),
				l.Posture.Score,
				sanitizeText(l.Posture.Grade),
				l.FindingsCount,
				sanitizeText(l.Message),
			)
		}
	}

	if len(rep.Findings) == 0 {
		b.WriteString("\nNo security findings detected.\n")
		return b.String()
	}

	b.WriteString("\nFindings:\n")
	for _, f := range rep.Findings {
		fmt.Fprintf(
			&b,
			"  [%-8s] %-10s %-14s %s -> %s\n",
			strings.ToUpper(sanitizeText(string(f.Severity))),
			sanitizeText(f.RuleID),
			sanitizeText(f.Layer),
			sanitizeText(f.Title),
			sanitizeText(f.Target),
		)
	}
	return b.String()
}

func renderMarkdown(rep schema.SuiteReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Raksa Security Suite Report (`v%s`)\n\n", sanitizeText(rep.Version))
	fmt.Fprintf(
		&b,
		"- **Profile**: `%s` | **Target**: `%s`\n- **Posture Score**: **%d/100 (%s)**\n- **Summary**: `total=%d` (critical: %d, high: %d, medium: %d, low: %d, info: %d)\n",
		sanitizeText(rep.Profile),
		sanitizeText(rep.Target),
		rep.Posture.Score,
		sanitizeText(rep.Posture.Grade),
		rep.Summary.Total,
		rep.Summary.Critical,
		rep.Summary.High,
		rep.Summary.Medium,
		rep.Summary.Low,
		rep.Summary.Info,
	)
	if rep.SuppressedCount > 0 || rep.BaselinedCount > 0 || rep.DeduplicatedCount > 0 {
		fmt.Fprintf(&b, "- **Filtered**: deduplicated=%d, waived=%d, baselined=%d\n", rep.DeduplicatedCount, rep.SuppressedCount, rep.BaselinedCount)
	}

	if len(rep.Layers) > 0 {
		b.WriteString("\n### Layer Breakdown (Hybrid Mode)\n\n| Layer | Status | Findings | Score | Notes |\n| :--- | :--- | ---: | ---: | :--- |\n")
		for _, l := range rep.Layers {
			fmt.Fprintf(
				&b,
				"| `%s` | %s | %d | %d (%s) | %s |\n",
				sanitizeText(l.Layer),
				sanitizeText(l.Status),
				l.FindingsCount,
				l.Posture.Score,
				sanitizeText(l.Posture.Grade),
				escapeMD(sanitizeText(l.Message)),
			)
		}
	}

	if len(rep.Findings) > 0 {
		b.WriteString("\n### Active Findings\n\n| Severity | Rule | Layer | Title | Target | Remediation |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for _, f := range rep.Findings {
			fmt.Fprintf(
				&b,
				"| **%s** | `%s` | `%s` | %s | `%s` | %s |\n",
				strings.ToUpper(sanitizeText(string(f.Severity))),
				sanitizeText(f.RuleID),
				sanitizeText(f.Layer),
				escapeMD(sanitizeText(f.Title)),
				escapeMD(sanitizeText(f.Target)),
				escapeMD(sanitizeText(f.Remediation)),
			)
		}
	} else {
		b.WriteString("\nNo active findings above suppression gates.\n")
	}
	return b.String()
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func renderSARIF(rep schema.SuiteReport) ([]byte, error) {
	ruleMap := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(rep.Findings))

	for _, f := range rep.Findings {
		if _, exists := ruleMap[f.RuleID]; !exists {
			props := map[string]string{"layer": f.Layer}
			if f.MitreD3FEND != "" {
				props["mitre_d3fend"] = f.MitreD3FEND
			}
			ruleMap[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				Properties:       props,
			}
		}

		msg := f.Description
		if f.Remediation != "" {
			msg = fmt.Sprintf("%s Remediation: %s", msg, f.Remediation)
		}
		uri := sanitizeSARIFURI(f.Target)
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: uri},
						Region:           &sarifRegion{StartLine: 1},
					},
				},
			},
		})
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "raksa",
						Version:        rep.Version,
						InformationURI: "https://github.com/luminariadev/raksa",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode sarif: %w", err)
	}
	return append(raw, '\n'), nil
}

func sarifLevel(s schema.Severity) string {
	switch strings.ToLower(string(s)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sanitizeSARIFURI(target string) string {
	uri := strings.TrimSpace(target)
	uri = strings.TrimPrefix(uri, "file://")
	uri = strings.ReplaceAll(uri, `\`, "/")
	if uri == "" {
		return "workspace"
	}
	return uri
}

const htmlTemplateSrc = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Raksa Security Suite Report</title>
<style>
:root { --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --good:#3fb950; --warn:#d29922; --bad:#f85149; --accent:#58a6ff; }
* { box-sizing: border-box; }
body { margin:0; padding:24px; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:var(--bg); color:var(--text); }
.wrap { max-width:1180px; margin:0 auto; }
.header { display:flex; justify-content:space-between; align-items:center; gap:16px; background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px; margin-bottom:20px; }
.title h1 { margin:0 0 6px 0; font-size:22px; }
.meta { color:var(--muted); font-size:13px; }
.score { text-align:center; min-width:120px; }
.grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr)); gap:12px; margin-bottom:20px; }
.card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px; }
.card h3 { margin:0 0 6px 0; font-size:13px; color:var(--accent); text-transform:uppercase; }
.big { font-size:22px; font-weight:700; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-bottom:20px; }
th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-size:13px; vertical-align:top; }
th { background:#1c2128; color:var(--muted); font-weight:600; }
.sev { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; text-transform:uppercase; }
.sev-critical { background:#5c1a1b; color:#ff7b72; }
.sev-high { background:#4c2b14; color:#ffa657; }
.sev-medium { background:#3d3011; color:#e3b341; }
.sev-low { background:#132f4c; color:#79c0ff; }
.sev-info { background:#21262d; color:#8b949e; }
code { background:#0d1117; padding:2px 5px; border-radius:4px; font-size:12px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="title">
      <h1>Raksa Flagship Suite Report (v{{.Report.Version}})</h1>
      <div class="meta">Profile: <code>{{.Report.Profile}}</code> | Target: <code>{{.Report.Target}}</code> | Generated: {{.Report.GeneratedAt}}</div>
      <div class="meta">Summary: Total {{.Report.Summary.Total}} (Critical {{.Report.Summary.Critical}}, High {{.Report.Summary.High}}, Medium {{.Report.Summary.Medium}}, Low {{.Report.Summary.Low}}, Info {{.Report.Summary.Info}})</div>
    </div>
    <div class="score">
      <svg width="96" height="96" viewBox="0 0 96 96" aria-label="Posture gauge">
        <circle cx="48" cy="48" r="40" fill="none" stroke="#30363d" stroke-width="8"/>
        <circle cx="48" cy="48" r="40" fill="none" stroke="{{.GaugeColor}}" stroke-width="8" stroke-dasharray="{{.DashLen}} 251" transform="rotate(-90 48 48)"/>
        <text x="48" y="47" text-anchor="middle" fill="#e6edf3" font-size="20" font-weight="700">{{.Report.Posture.Score}}</text>
        <text x="48" y="64" text-anchor="middle" fill="#8b949e" font-size="12">Grade {{.Report.Posture.Grade}}</text>
      </svg>
    </div>
  </div>

  <div class="grid">
    {{range .Report.Layers}}
    <div class="card">
      <h3>{{.Layer}}</h3>
      <div class="big">{{.Posture.Score}} / 100 ({{.Posture.Grade}})</div>
      <div class="meta">Status: {{.Status}} | Findings: {{.FindingsCount}}</div>
    </div>
    {{end}}
  </div>

  {{if .Report.Findings}}
  <table>
    <thead>
      <tr><th>Severity</th><th>Rule</th><th>Layer</th><th>Finding</th><th>Target</th><th>Remediation</th></tr>
    </thead>
    <tbody>
      {{range .Report.Findings}}
      <tr>
        <td><span class="sev sev-{{.Severity}}">{{.Severity}}</span></td>
        <td><code>{{.RuleID}}</code></td>
        <td><code>{{.Layer}}</code></td>
        <td><strong>{{.Title}}</strong><br><span class="meta">{{.Description}}</span></td>
        <td><code>{{.Target}}</code></td>
        <td>{{.Remediation}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="card">No active security findings above suppression gates.</div>
  {{end}}
</div>
</body>
</html>
`

func renderHTML(rep schema.SuiteReport) ([]byte, error) {
	tmpl, err := template.New("suite-html").Parse(htmlTemplateSrc)
	if err != nil {
		return nil, fmt.Errorf("parse html template: %w", err)
	}
	gaugeColor := "#3fb950"
	if rep.Posture.Score < 70 {
		gaugeColor = "#f85149"
	} else if rep.Posture.Score < 90 {
		gaugeColor = "#d29922"
	}
	dashLen := (rep.Posture.Score * 251) / 100
	data := struct {
		Report     schema.SuiteReport
		GaugeColor string
		DashLen    int
	}{
		Report:     rep,
		GaugeColor: gaugeColor,
		DashLen:    dashLen,
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render html report: %w", err)
	}
	return buf.Bytes(), nil
}

func sanitizeText(in string) string {
	cleaned := strings.ReplaceAll(in, "\x1b", "")
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, cleaned)
}

func escapeMD(in string) string {
	return strings.ReplaceAll(strings.ReplaceAll(in, "|", "\\|"), "\n", " ")
}
