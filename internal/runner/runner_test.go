package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/luminariadev/raksa/internal/policy"
)

func TestHybridRunSuiteGracefulDegradationAndCorrelate(t *testing.T) {
	resolver := func(binary, _ string) (string, bool) {
		switch binary {
		case "raksa-pipeguard", "raksa-siem":
			return "/usr/local/bin/" + binary, true
		default:
			return "", false
		}
	}

	execFn := func(_ context.Context, binary string, args ...string) ExecResult {
		if strings.HasSuffix(binary, "raksa-pipeguard") {
			return ExecResult{
				ExitCode: 2,
				Stdout: []byte(`{
					"schema_version": "1.0",
					"tool": "raksa-pipeguard",
					"layer": "devsecops",
					"findings": [{"id":"p1","rule_id":"PIPE-001","layer":"devsecops","severity":"high","title":"Secret","description":"leak","target":"file://.env"}]
				}`),
			}
		}
		if strings.HasSuffix(binary, "raksa-siem") && len(args) > 0 && args[0] == "correlate" {
			return ExecResult{
				ExitCode: 1,
				Stdout: []byte(`{
					"schema_version": "1.0",
					"tool": "raksa-siem",
					"layer": "siem",
					"findings": [{"id":"s1","rule_id":"SIEM-401","layer":"siem","severity":"high","title":"Correlated alert","description":"siem alert","target":"siem://chain"}]
				}`),
			}
		}
		return ExecResult{ExitCode: 0}
	}

	reports, execs, err := RunSuite(context.Background(), SuiteRequest{
		Profile: "repo",
		Target:  ".",
		Policy:  policy.DefaultConfig(),
	}, resolver, execFn)
	if err != nil {
		t.Fatalf("RunSuite: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 upstream+siem reports, got %d", len(reports))
	}
	statusByLayer := make(map[string]string)
	for _, ex := range execs {
		statusByLayer[ex.Layer] = ex.Status
	}
	if statusByLayer["pipeguard"] != "findings" || statusByLayer["siem"] != "findings" {
		t.Fatalf("unexpected active layer statuses: %+v", statusByLayer)
	}
	if statusByLayer["hostguard"] != "not_installed" || statusByLayer["iocscan"] != "not_installed" {
		t.Fatalf("expected graceful not_installed degradation, got %+v", statusByLayer)
	}
}

func TestDoctorAndInstallPlanner(t *testing.T) {
	statuses := Doctor(context.Background(), "", func(binary, _ string) (string, bool) {
		if binary == "raksa-pipeguard" {
			return "/bin/raksa-pipeguard", true
		}
		return "", false
	}, func(_ context.Context, _ string, _ ...string) ExecResult {
		return ExecResult{ExitCode: 0, Stdout: []byte("raksa-pipeguard v0.3.0")}
	})
	if len(statuses) != 6 {
		t.Fatalf("expected 6 doctor entries, got %d", len(statuses))
	}

	plan, err := PlanInstall([]string{"netguard", "hostguard", "siem"}, "/tmp/raksa-bin", "linux", "amd64")
	if err != nil {
		t.Fatalf("PlanInstall: %v", err)
	}
	if len(plan) != 3 || !strings.Contains(plan[1].ArchiveURL, "x86_64-unknown-linux-musl") {
		t.Fatalf("unexpected install plan: %+v", plan)
	}
}
