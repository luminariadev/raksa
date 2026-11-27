// Package remediate aggregates read-only unified patch previews from Layer 2-4 tools.
package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/luminariadev/raksa/internal/schema"
)

// Executor abstracts subprocess execution for deterministic remediation unit tests.
type Executor func(ctx context.Context, binary string, args ...string) ([]byte, error)

// QueueResult captures aggregated read-only remediation patches plus any skipped layers.
type QueueResult struct {
	Target  string                  `json:"target"`
	Items   []schema.FixPreviewItem `json:"items"`
	Skipped []string                `json:"skipped,omitempty"`
}

func defaultExecutor(ctx context.Context, binary string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runErr := cmd.Run(); runErr != nil {
		return stdout.Bytes(), fmt.Errorf("%s failed: %w (%s)", binary, runErr, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// CollectFixPreviews invokes hostguard fix-preview, pipeguard fix-preview, and webshield generate-policy in read-only mode.
func CollectFixPreviews(ctx context.Context, target string, execFn Executor) QueueResult {
	if execFn == nil {
		execFn = defaultExecutor
	}
	if strings.TrimSpace(target) == "" {
		target = "."
	}

	res := QueueResult{Target: target}

	collectUnifiedDiff := func(layer, binary string, args ...string) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		out, err := execFn(cctx, binary, args...)
		if err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%s not installed)", layer, binary))
				return
			}
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%v)", layer, err))
			return
		}
		trimmed := strings.TrimSpace(string(out))
		if trimmed == "" || strings.Contains(strings.ToLower(trimmed), "no hardening changes needed") || strings.Contains(strings.ToLower(trimmed), "no remediation diffs") {
			return
		}
		res.Items = append(res.Items, schema.FixPreviewItem{
			Layer:  layer,
			Tool:   binary,
			Target: target,
			Format: "diff",
			Diff:   trimmed,
		})
	}

	collectUnifiedDiff("hostguard", "raksa-hostguard", "fix-preview", "--path", target, "--format", "diff")
	collectUnifiedDiff("pipeguard", "raksa-pipeguard", "fix-preview", "--path", target, "--format", "diff")
	collectUnifiedDiff("webshield", "raksa-webshield", "generate-policy", "--target", "nginx", "--profile", "strict")

	return res
}

// FormatDiff renders QueueResult as human-readable unified diff or JSON.
func FormatDiff(res QueueResult, format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "diff":
		if len(res.Items) == 0 {
			return fmt.Sprintf("No unified remediation patches emitted for %s.\n", res.Target), nil
		}
		var b strings.Builder
		for _, item := range res.Items {
			fmt.Fprintf(&b, "=== [%s] %s (%s) ===\n%s\n\n", item.Layer, item.Tool, item.Target, item.Diff)
		}
		return b.String(), nil
	case "json":
		raw, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return "", fmt.Errorf("encode fix-preview json: %w", err)
		}
		return string(raw) + "\n", nil
	default:
		return "", fmt.Errorf("invalid format %q (expected diff or json)", format)
	}
}
