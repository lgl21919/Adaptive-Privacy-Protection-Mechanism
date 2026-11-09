package uc_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/uc"
)

func TestLiftModeConfigIsMonotone(t *testing.T) {
	cfg := context.ModeConfig{MinSecurityLevel: 1}
	got := uc.LiftModeConfig(cfg, true)
	if !got.ForceAnonymous || got.MinSecurityLevel != 3 || !got.AllowComposition || !got.RequireSTE {
		t.Fatalf("lift: %+v", got)
	}
	same := uc.LiftModeConfig(got, false)
	if same != got {
		t.Fatal("consistent path must not change cfg")
	}
}

func TestCompareRealIdealConsistentOnHonestRequest(t *testing.T) {
	π, err := uc.NewDefaultProtocol()
	if err != nil {
		t.Fatal(err)
	}
	F, err := uc.NewDefaultFAdaptive()
	if err != nil {
		t.Fatal(err)
	}
	S := uc.NewSimulator(F)
	req := uc.AdaptiveRequest{
		SID:    "paper-gov",
		UserID: "alice",
		Input: context.ContextInput{
			Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
			DataType: "MANUSCRIPT", SecurityLevel: 1,
			RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		},
		Plaintext: []byte("m"),
	}
	rec, err := uc.CompareRealIdeal(π, S, req)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Consistent {
		t.Fatalf("expected consistent traces: real=%+v ideal=%+v", rec.RealTrace, rec.IdealTrace)
	}
	payload := rec.OnChainPayload()
	if payload.SID != "paper-gov" || !payload.Consistent {
		t.Fatalf("payload %+v", payload)
	}
}

func TestGovernorJournalLiftAfterStreak(t *testing.T) {
	g := uc.NewGovernor(2)
	j := context.ModeConfig{MinSecurityLevel: 1}
	s := context.ModeConfig{}
	mismatch := uc.OnChainConsistencyPayload{SID: "x", Consistent: false, Reason: "public_trace_mismatch"}
	j, s, lifted := g.ApplyIngestedRecord(j, s, mismatch)
	if lifted || s.MinSecurityLevel != 3 {
		t.Fatalf("first mismatch should lift session only, lifted=%v sess=%+v", lifted, s)
	}
	j, s, lifted = g.ApplyIngestedRecord(j, s, mismatch)
	if !lifted || j.MinSecurityLevel != 3 || !j.ForceAnonymous {
		t.Fatalf("second mismatch should lift journal, lifted=%v journal=%+v", lifted, j)
	}
}
