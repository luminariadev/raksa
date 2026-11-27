// Package playbooks exposes curated built-in Raksa defensive playbook YAML templates.
package playbooks

import "embed"

// FS embeds all curated YAML playbooks shipped in the root playbooks/ directory.
//
//go:embed *.yml
var FS embed.FS
