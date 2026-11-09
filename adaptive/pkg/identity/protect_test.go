package identity_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/identity"
)

func TestPseudonymDeterministicInScope(t *testing.T) {
	p := identity.NewProtector([]byte("master-key-for-tests-32bytes!!"))
	a := p.Protect(identity.ModePseudonym, "alice", "paper1", "REVIEW", "DOUBLE_BLIND", "AUTHOR")
	b := p.Protect(identity.ModePseudonym, "alice", "paper1", "REVIEW", "DOUBLE_BLIND", "AUTHOR")
	if a.Value != b.Value {
		t.Fatalf("expected same pseudonym, got %s vs %s", a.Value, b.Value)
	}
	c := p.Protect(identity.ModePseudonym, "alice", "paper1", "PUBLICATION", "", "AUTHOR")
	if a.Value == c.Value {
		t.Fatal("cross-phase pseudonyms must differ")
	}
}

func TestAnonymousUnlinkable(t *testing.T) {
	p := identity.NewProtector([]byte("master-key-for-tests-32bytes!!"))
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		h := p.Protect(identity.ModeAnonymous, "alice", "s", "REVIEW", "DOUBLE_BLIND", "AUTHOR")
		if seen[h.Value] {
			t.Fatal("anonymous collision")
		}
		seen[h.Value] = true
		if h.Mode != identity.ModeAnonymous {
			t.Fatalf("mode %s", h.Mode)
		}
	}
}
