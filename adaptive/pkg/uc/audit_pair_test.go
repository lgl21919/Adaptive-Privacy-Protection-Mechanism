package uc_test

import (
	"os"
	"path/filepath"
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
	"privacy-protection/adaptive/pkg/uc"
)

func TestGoldenAuditPairSharesProductionCoordinator(t *testing.T) {
	reasoning.ResetCoordinatorFromEnv()
	t.Setenv(reasoning.EnvAdaptiveRulesPath, "")
	reasoning.ResetCoordinatorFromEnv()

	pair, err := uc.NewGoldenAuditPair()
	if err != nil {
		t.Fatal(err)
	}
	if pair.Mode != uc.AuditModeGolden {
		t.Fatalf("mode=%s", pair.Mode)
	}
	prod, err := reasoning.LoadCoordinatorFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if pair.Protocol.Coordinator() != prod {
		t.Fatal("golden π must share production coordinator singleton")
	}
	req := uc.AdaptiveRequest{
		SID: "g1", UserID: "u",
		Input: context.ContextInput{
			Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
			DataType: "MANUSCRIPT", SecurityLevel: 1,
			RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		},
		Plaintext: []byte("m"),
	}
	rec, err := pair.Compare(req)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Consistent {
		t.Fatalf("default rules: golden π should match golden F: %+v vs %+v", rec.RealTrace, rec.IdealTrace)
	}
}

func TestGoldenAuditDetectsProductionRuleDrift(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "drift.yaml")
	// Flip double-blind author from PSEUDONYMOUS (golden) to REAL_IDENTITY.
	body := `
version: "1.0"
rules:
  - id: rev_db_author_real_drift
    priority: 100
    match: { s: REVIEW, m: AUTHOR, r: DOUBLE_BLIND, d: "*", l: "*" }
    output: { iapp_strategy: REAL_IDENTITY }
    description: "drift"
  - id: rev_db_manuscript_l1
    priority: 10
    match: { s: REVIEW, m: "*", r: "*", d: MANUSCRIPT, l: "1" }
    output:
      dapp_strategy: ECDH_HKDF
      enc_algorithms: [ECDH_HKDF]
      compose_mode: SINGLE
      security_level: 1
`
	if err := os.WriteFile(yamlPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(reasoning.EnvAdaptiveRulesPath, yamlPath)
	reasoning.ResetCoordinatorFromEnv()

	golden, err := uc.NewGoldenAuditPair()
	if err != nil {
		t.Fatal(err)
	}
	req := uc.AdaptiveRequest{
		SID: "drift-1", UserID: "alice",
		Input: context.ContextInput{
			Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
			DataType: "MANUSCRIPT", SecurityLevel: 1,
			RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		},
		Plaintext: []byte("paper"),
	}
	rec, err := golden.Compare(req)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Consistent {
		t.Fatal("expected PublicTrace mismatch when production YAML drifts from golden F")
	}
	if rec.RealTrace.IAPP == rec.IdealTrace.IAPP {
		t.Fatalf("IAPP should differ: real=%s ideal=%s", rec.RealTrace.IAPP, rec.IdealTrace.IAPP)
	}

	synced, err := uc.NewSyncedAuditPair()
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := synced.Compare(req)
	if err != nil {
		t.Fatal(err)
	}
	if !rec2.Consistent {
		t.Fatalf("synced mode must align π and F on same coordinator: %+v", rec2)
	}
}

func TestNewAuditPairDefaultGolden(t *testing.T) {
	reasoning.ResetCoordinatorFromEnv()
	t.Setenv(reasoning.EnvAdaptiveRulesPath, "")
	reasoning.ResetCoordinatorFromEnv()
	p, err := uc.NewAuditPair("")
	if err != nil || p.Mode != uc.AuditModeGolden {
		t.Fatalf("err=%v mode=%v", err, p)
	}
}
