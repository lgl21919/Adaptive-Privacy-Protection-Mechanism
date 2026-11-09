package uc_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
	"privacy-protection/adaptive/pkg/uc"
)

func TestPiPinsOnlineStrategyAgainstIdeal(t *testing.T) {
	pair, err := uc.NewGoldenAuditPair()
	if err != nil {
		t.Fatal(err)
	}
	req := uc.AdaptiveRequest{
		SID: "sid-online", UserID: "alice",
		Input: context.ContextInput{
			SessionID: "sid-online", Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
			DataType: "MANUSCRIPT", SecurityLevel: 1,
			RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		},
		Plaintext: []byte("m"),
		OnlineStrategy: &uc.OnlineStrategy{
			IAPP: reasoning.IAPPPseudonym, DAPP: reasoning.DAPPECDH, SecurityLevel: 1,
		},
	}
	rec, err := pair.Compare(req)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RealTrace.IAPP != reasoning.IAPPPseudonym || rec.RealTrace.DAPP != reasoning.DAPPECDH {
		t.Fatalf("π must pin online strategy, got %s|%s", rec.RealTrace.IAPP, rec.RealTrace.DAPP)
	}
	// Ideal F re-selects for same C (DefaultRuleSet → pseudo+ECDH here) — should agree.
	if !rec.Consistent {
		t.Fatalf("expected consistent online vs ideal for default rules: real=%s|%s ideal=%s|%s reason=%s",
			rec.RealTrace.IAPP, rec.RealTrace.DAPP, rec.IdealTrace.IAPP, rec.IdealTrace.DAPP, rec.Reason)
	}
}

func TestObserveProductionPinsOnlineIntoUC(t *testing.T) {
	mc := uc.NewMonitorController(3)
	lr := mc.ObserveProduction(uc.ProductionStrategy{
		SID: "sid-pin", UserID: "bob",
		IAPP: reasoning.IAPPPseudonym, DAPP: reasoning.DAPPECDH,
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
		DataType: "MANUSCRIPT", Level: 1, Plaintext: []byte("x"),
	})
	if lr.UCConsistent == nil || !*lr.UCConsistent {
		t.Fatalf("UC with online-pinned π should pass against golden F: %+v", lr)
	}
	_, mapped, verified := mc.Map.Status(reasoning.IAPPPseudonym, reasoning.DAPPECDH)
	if !mapped || !verified {
		t.Fatal("online pair should be marked verified after UC pass")
	}
}
