package reasoning_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
)

func TestPolicyWeightStoreTiers(t *testing.T) {
	w := reasoning.NewPolicyWeightStore()
	if w.PairWeight(reasoning.IAPPReal, reasoning.DAPPECDH) != reasoning.WeightBaseline {
		t.Fatal("unset pair should be baseline")
	}
	w.MarkUnverified(reasoning.IAPPReal, reasoning.DAPPECDH)
	if w.PairWeight(reasoning.IAPPReal, reasoning.DAPPECDH) != reasoning.WeightUnverified {
		t.Fatal("expected unverified weight")
	}
	w.MarkUCResult(reasoning.IAPPReal, reasoning.DAPPECDH, true)
	if w.PairWeight(reasoning.IAPPReal, reasoning.DAPPECDH) != reasoning.WeightVerified {
		t.Fatal("expected verified weight")
	}
	w.MarkUCResult(reasoning.IAPPPseudonym, reasoning.DAPPECDH, false)
	if w.PairWeight(reasoning.IAPPPseudonym, reasoning.DAPPECDH) != reasoning.WeightFailed {
		t.Fatal("expected failed weight")
	}
}

func TestWeightGovernanceOverridesLowWeightStatic(t *testing.T) {
	w := reasoning.NewPolicyWeightStore()
	// Static would pick PSEUDONYMOUS+ECDH, but that pair failed UC;
	// anonymous+MPC is verified → governance should switch.
	w.MarkUCResult(reasoning.IAPPPseudonym, reasoning.DAPPECDH, false)
	w.MarkUCResult(reasoning.IAPPAnonymous, reasoning.DAPPMPC, true)

	engine, err := reasoning.NewLogicalReasoningEngine(reasoning.DefaultRuleSet())
	if err != nil {
		t.Fatal(err)
	}
	engine.SetWeights(w)
	coord := reasoning.NewAdaptiveCoordinator(engine)
	coord.AttachWeights(w)

	dec, err := coord.EvaluatePolicy(context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
		DataType: "MANUSCRIPT", SecurityLevel: 1,
		RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		ModeConfig: context.ModeConfig{ForceAnonymous: true, MinSecurityLevel: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.IAPPStrategy != reasoning.IAPPAnonymous {
		t.Fatalf("expected weight-governed ANONYMOUS, got %s (%s)", dec.IAPPStrategy, dec.Description)
	}
	if dec.DAPPStrategy != reasoning.DAPPMPC {
		t.Fatalf("expected weight-governed MPC, got %s", dec.DAPPStrategy)
	}
	if dec.SecurityWeight < reasoning.WeightVerified {
		t.Fatalf("expected verified-tier weight, got %d", dec.SecurityWeight)
	}
}

func TestMatchingRulesPreferHigherWeight(t *testing.T) {
	// Two overlapping identity-like rules: same match, different IAPP / priority.
	rs := &reasoning.RuleSet{
		Version: "test",
		Rules: []reasoning.Rule{
			{
				ID: "low_weight_real", Priority: 200,
				Match:  reasoning.RulePattern{S: "REVIEW", M: "AUTHOR", R: "OPEN", D: "*", L: "*"},
				Output: reasoning.RuleOutput{IAPPStrategy: reasoning.IAPPReal},
			},
			{
				ID: "high_weight_anon", Priority: 50,
				Match:  reasoning.RulePattern{S: "REVIEW", M: "AUTHOR", R: "OPEN", D: "*", L: "*"},
				Output: reasoning.RuleOutput{IAPPStrategy: reasoning.IAPPAnonymous},
			},
		},
	}
	engine, err := reasoning.NewLogicalReasoningEngine(rs)
	if err != nil {
		t.Fatal(err)
	}
	w := reasoning.NewPolicyWeightStore()
	w.SetIAPP(reasoning.IAPPReal, reasoning.WeightFailed)
	w.SetIAPP(reasoning.IAPPAnonymous, reasoning.WeightVerified)
	engine.SetWeights(w)

	state := context.NewContextAwarenessModule().Capture(context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "OPEN",
	})
	dec, err := engine.Evaluate(state)
	if err != nil {
		t.Fatal(err)
	}
	if dec.IAPPStrategy != reasoning.IAPPAnonymous {
		t.Fatalf("weight must beat static priority: got %s rule=%s", dec.IAPPStrategy, dec.RuleID)
	}
}
