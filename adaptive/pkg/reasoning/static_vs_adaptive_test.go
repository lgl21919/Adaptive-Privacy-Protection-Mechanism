package reasoning_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
)

func TestStaticVsAdaptiveGoldFitness(t *testing.T) {
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	cases := reasoning.DefaultFitnessCases()
	var b1, b2, b2s, ad reasoning.FitnessReport
	for _, c := range cases {
		i, d := reasoning.StaticB1()
		reasoning.Accumulate(&b1, reasoning.Judge(c, reasoning.SchemePick{"B1", i, d}))
		i, d = reasoning.StaticB2(c.Phase, c.DataType)
		reasoning.Accumulate(&b2, reasoning.Judge(c, reasoning.SchemePick{"B2", i, d}))
		i, d = reasoning.StaticB2SSS()
		reasoning.Accumulate(&b2s, reasoning.Judge(c, reasoning.SchemePick{"B2-SSS", i, d}))
		pick, err := reasoning.AdaptivePick(coord, c)
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		reasoning.Accumulate(&ad, reasoning.Judge(c, pick))
	}
	t.Logf("N=%d", ad.N)
	t.Logf("under-ID     B1=%.3f B2=%.3f B2-SSS=%.3f Adaptive=%.3f",
		b1.Rate(b1.UnderID), b2.Rate(b2.UnderID), b2s.Rate(b2s.UnderID), ad.Rate(ad.UnderID))
	t.Logf("under-data   B1=%.3f B2=%.3f B2-SSS=%.3f Adaptive=%.3f  (B2-SSS %d/%d)",
		b1.Rate(b1.UnderData), b2.Rate(b2.UnderData), b2s.Rate(b2s.UnderData), ad.Rate(ad.UnderData),
		b2s.UnderData, b2s.N)
	t.Logf("no-threshold B1=%d B2=%d B2-SSS=%d Adaptive=%d",
		b1.NoThreshold, b2.NoThreshold, b2s.NoThreshold, ad.NoThreshold)
	t.Logf("account-fail B1=%.3f B2=%.3f Adaptive=%.3f",
		b1.Rate(b1.AccountFail), b2.Rate(b2.AccountFail), ad.Rate(ad.AccountFail))
	t.Logf("editor-sees-author B1=%.3f B2=%.3f Adaptive=%.3f  (%d %d %d)",
		b1.Rate(b1.EditorSeesAuthor), b2.Rate(b2.EditorSeesAuthor), ad.Rate(ad.EditorSeesAuthor),
		b1.EditorSeesAuthor, b2.EditorSeesAuthor, ad.EditorSeesAuthor)
	t.Logf("single-point-key   B1=%.3f B2=%.3f Adaptive=%.3f  (%d %d %d)",
		b1.Rate(b1.KeySinglePoint), b2.Rate(b2.KeySinglePoint), ad.Rate(ad.KeySinglePoint),
		b1.KeySinglePoint, b2.KeySinglePoint, ad.KeySinglePoint)
	t.Logf("no-threshold       B1=%.3f B2=%.3f Adaptive=%.3f  (%d %d %d)",
		b1.Rate(b1.NoThreshold), b2.Rate(b2.NoThreshold), ad.Rate(ad.NoThreshold),
		b1.NoThreshold, b2.NoThreshold, ad.NoThreshold)

	if ad.UnderID >= b1.UnderID || ad.UnderID >= b2.UnderID {
		t.Fatalf("adaptive identity under-protection must be strictly below static")
	}
	if ad.UnderData >= b1.UnderData || ad.UnderData >= b2.UnderData {
		t.Fatalf("adaptive data under-protection must be strictly below static")
	}
	if ad.EditorSeesAuthor != 0 {
		t.Fatalf("adaptive must not expose DB author real names, got %d", ad.EditorSeesAuthor)
	}
	if ad.KeySinglePoint >= b1.KeySinglePoint {
		t.Fatalf("adaptive single-point key rate must improve on B1")
	}
}

func TestClosedLoopVsFrozenStaticWeights(t *testing.T) {
	// Static freeze: YAML/B1 never updates after a failed pair.
	// Adaptive: UC fail on PSEUDO|ECDH and verify ANON|MPC → next pick must leave ECDH.
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	w := reasoning.NewPolicyWeightStore()
	w.MarkUCResult(reasoning.IAPPPseudonym, reasoning.DAPPECDH, false)
	w.MarkUCResult(reasoning.IAPPAnonymous, reasoning.DAPPMPC, true)
	coord.AttachWeights(w)

	in := context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
		DataType: "MANUSCRIPT", SecurityLevel: 1,
		RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		ModeConfig: context.ModeConfig{ForceAnonymous: true, MinSecurityLevel: 3},
	}
	dec, err := coord.EvaluatePolicy(in)
	if err != nil {
		t.Fatal(err)
	}
	b1i, b1d := reasoning.StaticB1()
	if b1i != reasoning.IAPPReal || b1d != reasoning.DAPPECDH {
		t.Fatal("B1 must stay frozen")
	}
	if dec.IAPPStrategy != reasoning.IAPPAnonymous || dec.DAPPStrategy != reasoning.DAPPMPC {
		t.Fatalf("after UC weights, expected ANON+MPC, got %s+%s", dec.IAPPStrategy, dec.DAPPStrategy)
	}
}
