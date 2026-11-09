package uc_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/uc"
)

func TestFNymCandidatesShareOneIdeal(t *testing.T) {
	F := uc.NewFNym()
	master := []byte("nym-master-key-32-bytes-please!!")
	scope := "REVIEW|DOUBLE_BLIND|AUTHOR"

	pseudo := uc.NewNymCandidate(uc.NymPseudo, master)
	h1 := F.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymPseudo, Scope: scope})
	h2 := F.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymPseudo, Scope: scope})
	if h1.Value != h2.Value {
		t.Fatal("F_nym must be deterministic in-scope for pseudonyms")
	}
	r1 := pseudo.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymPseudo, Scope: scope})
	r2 := pseudo.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymPseudo, Scope: scope})
	if r1.Value != r2.Value {
		t.Fatal("π_pseudo must match F_nym in-scope linkability")
	}

	anon := uc.NewNymCandidate(uc.NymAnonymous, master)
	a1 := F.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymAnonymous})
	a2 := F.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymAnonymous})
	if a1.Value == a2.Value {
		t.Fatal("F_nym anonymous must be unlinkable")
	}
	b1 := anon.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymAnonymous})
	b2 := anon.Issue(uc.NymRequest{UID: "u", SA: "p1", Kind: uc.NymAnonymous})
	if b1.Value == b2.Value || b1.Mode != identity.ModeAnonymous {
		t.Fatal("π_anon must realise F_nym unlinkability")
	}
}

func TestFSCCandidatesShareOneIdeal(t *testing.T) {
	msg := []byte("manuscript")
	F := uc.NewFSC()
	scheme := crypto.Scheme{Token: "ECDH", Algorithms: []string{"ECDH"}, ComposeMode: crypto.ComposeSingle}
	ct, err := F.Seal(scheme, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := F.Open(scheme, ct)
	if err != nil || string(pt) != string(msg) {
		t.Fatalf("F_SC open: %v %q", err, pt)
	}

	for _, c := range uc.DefaultSCCandidates() {
		sch := crypto.Scheme{Token: c.Name(), Algorithms: []string{c.Name()}, ComposeMode: crypto.ComposeSingle}
		if sc, ok := c.(*uc.SCCandidate); ok {
			sch = crypto.Scheme{Token: sc.Algorithm(), Algorithms: []string{sc.Algorithm()}, ComposeMode: crypto.ComposeSingle}
		}
		ct, err := c.Seal(sch, msg)
		if err != nil {
			t.Fatalf("%s seal: %v", c.Name(), err)
		}
		pt, err := c.Open(sch, ct)
		if err != nil || string(pt) != string(msg) {
			t.Fatalf("%s (primitive %s) must realise F_SC: %v %q", c.Name(), c.Primitive(), err, pt)
		}
	}
}

func TestRhoAppDoesNotNeedPerPairFunctionality(t *testing.T) {
	if !uc.IndependentKeys() {
		t.Fatal("identity/data share state: would need JUC/GUC, not this layout")
	}
	rep, err := uc.CheckComposition()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pairs != 3*4 {
		t.Fatalf("want 3 nym × 4 sc = 12 pairs, got %d", rep.Pairs)
	}
	if rep.TraceOK != rep.Pairs {
		t.Fatalf("public traces must match hybrid ρ_app for every pair: %d/%d", rep.TraceOK, rep.Pairs)
	}
	if rep.DecryptOK != rep.Pairs {
		t.Fatalf("each SC candidate must decrypt: %d/%d", rep.DecryptOK, rep.Pairs)
	}
	if rep.UnlinkOK != rep.Pairs {
		t.Fatalf("F_nym unlinkability must hold under every SC plug-in: %d/%d", rep.UnlinkOK, rep.Pairs)
	}
}

func TestRhoAppHybridFailClosed(t *testing.T) {
	ρ, err := uc.NewHybridRhoApp()
	if err != nil {
		t.Fatal(err)
	}
	req := uc.AdaptiveRequest{
		SID:    "sid-abort",
		UserID: "alice",
		Input: context.ContextInput{
			Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "OPEN",
			DataType: "MANUSCRIPT", SecurityLevel: 1,
			AuthenticatedPhase: "SUBMISSION", RegisteredRole: "AUTHOR",
		},
		Plaintext: []byte("no"),
	}
	resp, err := ρ.Invoke(req)
	if err == nil || resp == nil || !resp.Trace.FallbackUsed {
		t.Fatalf("hybrid ρ_app must fail-closed: err=%v resp=%v", err, resp)
	}
}
