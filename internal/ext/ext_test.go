package ext

import (
	"context"
	"slices"
	"testing"

	"github.com/luminariadev/raksa/internal/schema"
)

func TestOSSDefaults(t *testing.T) {
	ed := DefaultEdition()
	if ed.Edition != "oss" || ed.License != "Apache-2.0" {
		t.Fatalf("unexpected edition metadata: %+v", ed)
	}

	auth := LocalAuthProvider{ExpectedToken: "secret-dev-token"}
	if _, _, ok := auth.ValidateToken(context.Background(), "wrong"); ok {
		t.Fatal("expected invalid token rejection")
	}
	subj, role, ok := auth.ValidateToken(context.Background(), "secret-dev-token")
	if !ok || subj == "" || role != "admin" {
		t.Fatalf("expected valid token approval, got %q %q %v", subj, role, ok)
	}

	mapper := OSSComplianceMapper{}
	controls := mapper.ControlsFor(schema.Finding{
		RuleID:      "HOST-201",
		MitreD3FEND: "D3-CISC",
	})
	if !slices.Contains(controls, "MITRE:D3-CISC") || !slices.Contains(controls, "CIS-Docker-Benchmark") {
		t.Fatalf("unexpected compliance controls: %v", controls)
	}
}
