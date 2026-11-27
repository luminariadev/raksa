package remediate

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestCollectFixPreviewsGracefulAndAggregated(t *testing.T) {
	mock := func(_ context.Context, binary string, _ ...string) ([]byte, error) {
		switch binary {
		case "raksa-hostguard":
			return []byte("--- a/sshd_config\n+++ b/sshd_config\n+PermitRootLogin no"), nil
		case "raksa-pipeguard":
			return nil, exec.ErrNotFound
		case "raksa-webshield":
			return []byte("add_header X-Frame-Options \"DENY\" always;"), nil
		default:
			return nil, exec.ErrNotFound
		}
	}

	res := CollectFixPreviews(context.Background(), "./app", mock)
	if len(res.Items) != 2 {
		t.Fatalf("expected 2 remediation items, got %d (%+v)", len(res.Items), res)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "pipeguard") {
		t.Fatalf("expected pipeguard skipped gracefully, got %v", res.Skipped)
	}

	diffText, err := FormatDiff(res, "diff")
	if err != nil || !strings.Contains(diffText, "+PermitRootLogin no") {
		t.Fatalf("unexpected diff output: %q err=%v", diffText, err)
	}
	jsonText, err := FormatDiff(res, "json")
	if err != nil || !strings.Contains(jsonText, `"hostguard"`) {
		t.Fatalf("unexpected json output: %q err=%v", jsonText, err)
	}
}
