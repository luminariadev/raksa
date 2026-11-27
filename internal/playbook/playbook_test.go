package playbook

import "testing"

func TestListAndValidateBuiltins(t *testing.T) {
	all, err := ListBuiltins()
	if err != nil {
		t.Fatalf("ListBuiltins: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 built-in playbooks, got %d", len(all))
	}

	pb, err := ResolveBuiltin("pre-release-gate")
	if err != nil {
		t.Fatalf("ResolveBuiltin: %v", err)
	}
	if pb.Profile != "repo" || len(pb.Layers) < 4 {
		t.Fatalf("unexpected pre-release-gate playbook: %+v", pb)
	}

	if _, err := ParseBytes([]byte("name: bad\ntitle: Bad\nlayers: [unknown]\n"), "bad.yml"); err == nil {
		t.Fatal("expected unknown layer error")
	}
}
