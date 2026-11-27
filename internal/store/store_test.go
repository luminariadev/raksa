package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa/internal/schema"
)

func TestStoreHashChainAppendAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runs.ndjson")
	st := Open(path)

	for i, score := range []int{92, 85, 100} {
		rep := schema.SuiteReport{
			GeneratedAt: "2026-11-27T12:00:00Z",
			Profile:     "full",
			Target:      ".",
			Posture:     schema.PostureScore{Score: score, Grade: "A"},
			Summary:     schema.Summary{Total: i},
			Layers: []schema.LayerExecution{
				{Layer: "pipeguard", Status: "ok"},
				{Layer: "netguard", Status: "not_installed"},
			},
		}
		if _, err := st.Append(rep); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	count, ok, reason, err := st.VerifyChain()
	if err != nil || !ok || count != 3 {
		t.Fatalf("expected valid 3-entry chain, got count=%d ok=%v reason=%q err=%v", count, ok, reason, err)
	}

	recent, err := st.List(2)
	if err != nil || len(recent) != 2 || recent[0].Seq != 3 || recent[1].Seq != 2 {
		t.Fatalf("unexpected List(2): %+v err=%v", recent, err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"score":85`, `"score":99`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ok, reason, err = st.VerifyChain()
	if err != nil || ok {
		t.Fatalf("expected tamper failure, got ok=%v reason=%q err=%v", ok, reason, err)
	}
}
