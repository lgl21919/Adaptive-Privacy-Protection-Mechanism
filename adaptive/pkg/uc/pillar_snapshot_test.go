package uc_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/reasoning"
	"privacy-protection/adaptive/pkg/uc"
)

func TestExtractSnapshotAfterVerification(t *testing.T) {
	rep, snap, err := uc.RunVerificationWithSnapshot(32)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.AllOK {
		t.Fatalf("verification failed: %+v", rep.Results)
	}
	if snap.RunID == "" || len(snap.ConditionChanges) == 0 {
		t.Fatalf("empty snapshot: %+v", snap)
	}
	p := snap.Pillars
	if p.ModelingAssumptions.UCForm == "" || p.ProtocolCode.OrientedForm == "" {
		t.Fatalf("UC-oriented pillar deltas missing: %+v", p)
	}
	if !p.ModelingAssumptions.Verified || !p.ProtocolCode.Verified || !p.Composition.Verified {
		t.Fatalf("UC-oriented pillars not marked verified: %+v", p)
	}
	if !p.Composition.IdealStack.IDStrategy.Verified || !p.Composition.IdealStack.EncProtect.Verified {
		t.Fatalf("ideal stack layers not verified: %+v", p.Composition.IdealStack)
	}
	if len(snap.VerifiedIAPP) == 0 || len(snap.VerifiedDAPP) == 0 {
		t.Fatalf("expected verified strategy lists: iapp=%v dapp=%v", snap.VerifiedIAPP, snap.VerifiedDAPP)
	}
	if len(p.Composition.VerifiedIAPP) == 0 {
		t.Fatal("composition pillar should carry verified IAPP list")
	}
	if len(snap.VerifiedPairs) == 0 {
		t.Fatal("expected verified ideal pairs")
	}
	mc := uc.NewMonitorController(3)
	got, ok := mc.QueryLatestVerifiedOK()
	if !ok || got.RunID != snap.RunID {
		t.Fatalf("controller cannot query snapshot: ok=%v got=%s want=%s", ok, got.RunID, snap.RunID)
	}
	if n, ok := mc.SyncMapFromLatestOK(); !ok || n == 0 {
		t.Fatalf("sync verified pairs into map: n=%d ok=%v", n, ok)
	}
	res := mc.RequireVerifiedPair(reasoning.IAPPPseudonym, reasoning.DAPPMPC)
	if !res.Mapped || res.FeedbackFired {
		t.Fatalf("verified pair should pass: %+v", res)
	}
}
