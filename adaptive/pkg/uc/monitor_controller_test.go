package uc_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
	"privacy-protection/adaptive/pkg/uc"
)

func TestIdealSpecLookupKnownPair(t *testing.T) {
	spec := uc.DefaultIdealSpec()
	e, ok := spec.Lookup(reasoning.IAPPPseudonym, reasoning.DAPPMPC)
	if !ok {
		t.Fatal("expected pseudo|MPC in default IdealSpec")
	}
	if e.FSCPrimitive != uc.PrimitiveMPC {
		t.Fatalf("primitive %s", e.FSCPrimitive)
	}
	vmap := uc.NewVerificationMap(spec)
	_, mapped, verified := vmap.Status(reasoning.IAPPPseudonym, reasoning.DAPPMPC)
	if !mapped {
		t.Fatal("spec pair must be mapped in VerificationMap")
	}
	if verified {
		t.Fatal("marks must start unverified until monitor MarkVerified")
	}
}

func TestVerifiedPairRecordOnly(t *testing.T) {
	mc := uc.NewMonitorController(3)
	mc.Map.MarkVerified(reasoning.IAPPPseudonym, reasoning.DAPPECDH, "boot", true)
	lr := mc.ObserveProduction(uc.ProductionStrategy{
		SID: "sid", IAPP: reasoning.IAPPPseudonym, DAPP: reasoning.DAPPECDH,
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
	})
	if !lr.RecordOnly || lr.UCTriggered || lr.GovernTriggered || lr.FeedbackFired {
		t.Fatalf("verified map entry must record only: %+v", lr)
	}
}

func TestUnverifiedPairTriggersUCAndGovern(t *testing.T) {
	mc := uc.NewMonitorController(3)
	lr := mc.ObserveProduction(uc.ProductionStrategy{
		SID: "sid-uv", UserID: "alice",
		IAPP: reasoning.IAPPPseudonym, DAPP: reasoning.DAPPECDH,
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
		DataType: "MANUSCRIPT", Level: 1, Plaintext: []byte("m"),
	})
	if lr.RecordOnly {
		t.Fatal("unverified must not be record-only")
	}
	if !lr.UCTriggered || !lr.GovernTriggered || !lr.FeedbackFired {
		t.Fatalf("must dual-trigger UC+[4]: %+v", lr)
	}
	if lr.UCConsistent == nil {
		t.Fatal("expected UC result")
	}
	if !*lr.UCConsistent {
		t.Fatalf("golden same DefaultRuleSet should be consistent, got false reason=%s", lr.Reason)
	}
	if !lr.MapUpdated {
		t.Fatal("map should be updated after UC")
	}
	_, _, verified := mc.Map.Status(reasoning.IAPPPseudonym, reasoning.DAPPECDH)
	if !verified {
		t.Fatal("UC pass must mark map verified")
	}
	// Second observe → record only
	lr2 := mc.ObserveProduction(uc.ProductionStrategy{
		SID: "sid-uv2", IAPP: reasoning.IAPPPseudonym, DAPP: reasoning.DAPPECDH,
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
	})
	if !lr2.RecordOnly {
		t.Fatalf("second observe should record only: %+v", lr2)
	}
}

func TestUnmappedStrategyLiftsHotPathCfg(t *testing.T) {
	mc := uc.NewMonitorController(2)
	res := mc.OnIdentityAndDataEvents("sid-1", "UNKNOWN_ID", "UNKNOWN_ENC", "REVIEW", "AUTHOR", "OPEN")
	if res.Mapped {
		t.Fatal("unknown pair must not be mapped")
	}
	if !res.FeedbackFired {
		t.Fatal("FeedbackGovernor must fire")
	}
	if !res.SessionCfg.ForceAnonymous || res.SessionCfg.MinSecurityLevel < 3 {
		t.Fatalf("session cfg not lifted: %+v", res.SessionCfg)
	}
	res2 := mc.OnIdentityAndDataEvents("sid-2", "BAD", "WORSE", "REVIEW", "AUTHOR", "OPEN")
	if !res2.JournalLifted {
		t.Fatal("expected journal lift after streak")
	}
}

func TestFeedbackCfgAffectsReasoningFloor(t *testing.T) {
	mc := uc.NewMonitorController(3)
	_ = mc.OnIdentityAndDataEvents("sid", "X", "Y", "REVIEW", "AUTHOR", "SINGLE_BLIND")

	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	coord.AttachWeights(mc.Feedback.Weights())
	in := context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "SINGLE_BLIND",
		DataType: "MANUSCRIPT", SecurityLevel: 1,
		RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
	}
	mc.PrepareInput(&in)
	lifted, err := coord.EvaluatePolicy(in)
	if err != nil {
		t.Fatal(err)
	}
	if lifted.IAPPStrategy != reasoning.IAPPAnonymous {
		t.Fatalf("after cfg lift expect ANONYMOUS, got %s", lifted.IAPPStrategy)
	}
	if lifted.SecurityLevel < 3 {
		t.Fatalf("min security level should be raised, got %d", lifted.SecurityLevel)
	}
}

func TestGovernorWeightsDriveHotPathSelection(t *testing.T) {
	mc := uc.NewMonitorController(3)
	// Simulate UC pass on anonymous|MPC and fail on pseudo|ECDH.
	mc.Map.MarkVerified(reasoning.IAPPAnonymous, reasoning.DAPPMPC, "uc-ok", true)
	mc.Map.MarkVerified(reasoning.IAPPPseudonym, reasoning.DAPPECDH, "uc-bad", false)
	mc.Feedback.SyncWeightsFromMap(mc.Map)

	w := mc.Feedback.Weights()
	if w.PairWeight(reasoning.IAPPAnonymous, reasoning.DAPPMPC) != reasoning.WeightVerified {
		t.Fatal("verified pair must have high weight")
	}
	if w.PairWeight(reasoning.IAPPPseudonym, reasoning.DAPPECDH) != reasoning.WeightFailed {
		t.Fatal("failed pair must have low weight")
	}

	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	coord.AttachWeights(w)
	in := context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
		DataType: "MANUSCRIPT", SecurityLevel: 1,
		RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		ModeConfig: context.ModeConfig{ForceAnonymous: true, MinSecurityLevel: 3},
	}
	mc.PrepareInput(&in)
	dec, err := coord.EvaluatePolicy(in)
	if err != nil {
		t.Fatal(err)
	}
	if dec.IAPPStrategy != reasoning.IAPPAnonymous || dec.DAPPStrategy != reasoning.DAPPMPC {
		t.Fatalf("governor weights should steer to anon+MPC, got %s+%s (%s)",
			dec.IAPPStrategy, dec.DAPPStrategy, dec.Description)
	}
}

// TestAdaptiveClosedLoopC1toC6 is the paper-facing availability/effectiveness suite
// aligned with eq:loop (Det → D → Gov → next Π_pol).
func TestAdaptiveClosedLoopC1toC6(t *testing.T) {
	t.Run("C1_verified_record_only", TestVerifiedPairRecordOnly)
	t.Run("C2_unverified_uc_then_record_only", TestUnverifiedPairTriggersUCAndGovern)
	t.Run("C3_unmapped_lifts_sigma", TestUnmappedStrategyLiftsHotPathCfg)
	t.Run("C4_sigma_steers_next_policy", TestFeedbackCfgAffectsReasoningFloor)
	t.Run("C5_pair_weight_steers_next_policy", TestGovernorWeightsDriveHotPathSelection)
	t.Run("C6_online_pin_marked_verified", TestObserveProductionPinsOnlineIntoUC)
}
