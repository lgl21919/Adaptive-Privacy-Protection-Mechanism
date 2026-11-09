package uc_test

import (
	"errors"
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/reasoning"
	"privacy-protection/adaptive/pkg/uc"
)

func TestUCVerificationSuite(t *testing.T) {
	rep, err := uc.RunVerification(48)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rep.Results {
		if !e.Passed {
			t.Errorf("%s %s failed: metric=%.4f threshold=%.4f %s", e.ID, e.Name, e.Metric, e.Threshold, e.Detail)
		}
	}
	if !rep.AllOK {
		t.Fatalf("verification %d/%d passed", rep.Passed, rep.Total)
	}
}

func TestIdealRealStrategyAgreement(t *testing.T) {
	π, err := uc.NewDefaultProtocol()
	if err != nil {
		t.Fatal(err)
	}
	F, err := uc.NewDefaultFAdaptive()
	if err != nil {
		t.Fatal(err)
	}
	req := uc.AdaptiveRequest{
		SID:    "sid-agree",
		UserID: "alice",
		Input: context.ContextInput{
			Phase: "REVIEW", Role: "REVIEWER", ReviewMode: "DOUBLE_BLIND",
			DataType: "FINAL_RECOMMENDATION", SecurityLevel: 3,
			RegisteredRole: "REVIEWER", AuthenticatedPhase: "REVIEW",
		},
		Plaintext: []byte("confidential review"),
	}
	real, err := π.Invoke(req)
	if err != nil {
		t.Fatal(err)
	}
	ideal, err := F.Invoke(req)
	if err != nil {
		t.Fatal(err)
	}
	if real.Trace.IAPP != ideal.Trace.IAPP || real.Trace.DAPP != ideal.Trace.DAPP {
		t.Fatalf("strategy mismatch real=%s/%s ideal=%s/%s", real.Trace.IAPP, real.Trace.DAPP, ideal.Trace.IAPP, ideal.Trace.DAPP)
	}
	if real.Identity.Mode != identity.ModePseudonym {
		t.Fatalf("expected pseudonym, got %s", real.Identity.Mode)
	}
}

func TestMACIntegrity(t *testing.T) {
	key := []byte("integrity-key-32-bytes!!!!!!!!!!!")
	in := context.ContextInput{
		SessionID: "s", Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
		DataType: "MANUSCRIPT", SecurityLevel: 1, IntegrityKey: key,
	}
	in.IntegrityMAC = context.MACStrategyInput(key, in)
	if err := context.ValidateStrategyInput(in); err != nil {
		t.Fatal(err)
	}
	in.Phase = "PUBLICATION"
	if err := context.ValidateStrategyInput(in); err == nil {
		t.Fatal("expected MAC failure after phase rewrite")
	}
	coord, _ := reasoning.NewDefaultCoordinator()
	dec, err := coord.EvaluatePolicy(in)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.FallbackUsed {
		t.Fatal("expected safest fallback")
	}
}

func TestFailClosedAbortsIdentityAndEncryption(t *testing.T) {
	π, err := uc.NewDefaultProtocol()
	if err != nil {
		t.Fatal(err)
	}
	req := uc.AdaptiveRequest{
		SID:    "sid-abort",
		UserID: "alice",
		Input: context.ContextInput{
			Phase:              "REVIEW",
			Role:               "AUTHOR",
			ReviewMode:         "OPEN",
			DataType:           "MANUSCRIPT",
			SecurityLevel:      1,
			AuthenticatedPhase: "SUBMISSION",
			RegisteredRole:     "AUTHOR",
		},
		Plaintext: []byte("should-not-encrypt"),
	}
	resp, err := π.Invoke(req)
	if !errors.Is(err, uc.ErrFailClosedAbort) {
		t.Fatalf("want ErrFailClosedAbort, got %v", err)
	}
	if resp == nil || !resp.Trace.FallbackUsed {
		t.Fatal("abort must still emit PublicTrace with FallbackUsed")
	}
	if resp.Identity.Value != "" || len(resp.Cipher.Blob) > 0 {
		t.Fatalf("business must not mint handle or ciphertext: ident=%+v cipher=%+v", resp.Identity, resp.Cipher)
	}
}
