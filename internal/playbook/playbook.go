// Package playbook loads, validates, and resolves declarative YAML defensive playbooks.
package playbook

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/luminariadev/raksa/internal/schema"
	"github.com/luminariadev/raksa/playbooks"
	"gopkg.in/yaml.v3"
)

// PlaybookStep documents one defensive execution stage inside a playbook.
type PlaybookStep struct {
	Layer   string `yaml:"layer" json:"layer"`
	Summary string `yaml:"summary" json:"summary"`
}

// Playbook declares an ordered multi-layer defensive workflow.
type Playbook struct {
	Name        string         `yaml:"name" json:"name"`
	Title       string         `yaml:"title" json:"title"`
	Description string         `yaml:"description" json:"description"`
	Profile     string         `yaml:"profile" json:"profile"`
	Layers      []string       `yaml:"layers" json:"layers"`
	FailOn      string         `yaml:"fail_on" json:"fail_on"`
	MitreD3FEND []string       `yaml:"mitre_d3fend,omitempty" json:"mitre_d3fend,omitempty"`
	Steps       []PlaybookStep `yaml:"steps" json:"steps"`
}

// ListBuiltins parses and returns all curated embedded playbooks sorted by name.
func ListBuiltins() ([]Playbook, error) {
	entries, err := fs.ReadDir(playbooks.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded playbooks: %w", err)
	}
	out := make([]Playbook, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		raw, err := fs.ReadFile(playbooks.FS, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded playbook %s: %w", entry.Name(), err)
		}
		pb, err := ParseBytes(raw, entry.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, pb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ResolveBuiltin finds an embedded playbook by name or returns an error.
func ResolveBuiltin(name string) (Playbook, error) {
	all, err := ListBuiltins()
	if err != nil {
		return Playbook{}, err
	}
	needle := strings.ToLower(strings.TrimSpace(name))
	for _, pb := range all {
		if strings.ToLower(pb.Name) == needle {
			return pb, nil
		}
	}
	return Playbook{}, fmt.Errorf("playbook %q not found", name)
}

// LoadFile reads and validates a custom playbook YAML file from disk.
func LoadFile(path string) (Playbook, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Playbook{}, fmt.Errorf("read playbook %s: %w", path, err)
	}
	return ParseBytes(raw, path)
}

// ParseBytes unmarshals and validates a Playbook YAML document.
func ParseBytes(raw []byte, source string) (Playbook, error) {
	var pb Playbook
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&pb); err != nil {
		return Playbook{}, fmt.Errorf("parse playbook %s: %w", source, err)
	}
	if err := pb.Validate(); err != nil {
		return Playbook{}, fmt.Errorf("invalid playbook %s: %w", source, err)
	}
	return pb, nil
}

// Validate verifies required metadata, valid fail_on threshold, and canonical layer IDs.
func (p *Playbook) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("playbook requires name")
	}
	if strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("playbook %q requires title", p.Name)
	}
	if len(p.Layers) == 0 {
		return fmt.Errorf("playbook %q requires at least one layer", p.Name)
	}
	normLayers := make([]string, 0, len(p.Layers))
	for _, raw := range p.Layers {
		id, ok := schema.ParseLayerAlias(raw)
		if !ok {
			return fmt.Errorf("playbook %q references unknown layer %q", p.Name, raw)
		}
		normLayers = append(normLayers, id)
	}
	p.Layers = normLayers

	for i, step := range p.Steps {
		id, ok := schema.ParseLayerAlias(step.Layer)
		if !ok {
			return fmt.Errorf("playbook %q step[%d] unknown layer %q", p.Name, i, step.Layer)
		}
		p.Steps[i].Layer = id
		if strings.TrimSpace(step.Summary) == "" {
			return fmt.Errorf("playbook %q step[%d] requires summary", p.Name, i)
		}
	}

	if p.FailOn != "" {
		if _, err := schema.ParseSeverity(p.FailOn); err != nil {
			return fmt.Errorf("playbook %q invalid fail_on: %w", p.Name, err)
		}
	}
	return nil
}
