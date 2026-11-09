package reasoning_test

import (
	"os"
	"testing"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
)

func TestEvaluateIdentityDoubleBlindReviewer(t *testing.T) {
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := coord.EvaluateIdentityPolicy(context.ContextInput{
		Phase: "REVIEW", Role: "REVIEWER", ReviewMode: "DOUBLE_BLIND",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.IAPPStrategy != reasoning.IAPPPseudonym {
		t.Fatalf("expected PSEUDONYMOUS, got %s", dec.IAPPStrategy)
	}
}

func TestEvaluateDataManuscriptLevel2(t *testing.T) {
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := coord.EvaluateDataPolicy(context.ContextInput{
		Phase: "SUBMISSION", DataType: "MANUSCRIPT", SecurityLevel: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.DAPPStrategy != reasoning.DAPPSSS {
		t.Fatalf("expected SSS, got %s", dec.DAPPStrategy)
	}
}

func TestEvaluateCombinedPolicy(t *testing.T) {
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := coord.EvaluatePolicy(context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
		DataType: "MANUSCRIPT", SecurityLevel: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.IAPPStrategy != reasoning.IAPPPseudonym {
		t.Fatalf("IAPP: expected PSEUDONYMOUS, got %s", dec.IAPPStrategy)
	}
	if dec.DAPPStrategy != reasoning.DAPPECDH {
		t.Fatalf("DAPP: expected ECDH_HKDF, got %s", dec.DAPPStrategy)
	}
}

func TestTamperFallback(t *testing.T) {
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := coord.EvaluatePolicy(context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "OPEN",
		DataType: "MANUSCRIPT", SecurityLevel: 1,
		AuthenticatedPhase: "SUBMISSION",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dec.FallbackUsed || dec.IAPPStrategy != reasoning.IAPPAnonymous {
		t.Fatalf("expected fail-closed anonymous, got %+v", dec)
	}
}

func TestLoadFromYAML(t *testing.T) {
	candidates := []string{
		"../config/adaptive_rules.yaml",
		"../../config/adaptive_rules.yaml",
		"config/adaptive_rules.yaml",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("adaptive_rules.yaml not found from test working directory")
	}
	engine, err := reasoning.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	coord := reasoning.NewAdaptiveCoordinator(engine)
	dec, err := coord.EvaluateIdentityPolicy(context.ContextInput{
		Phase: "SUBMISSION", Role: "AUTHOR",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.IAPPStrategy != reasoning.IAPPReal {
		t.Fatalf("expected REAL_IDENTITY, got %s", dec.IAPPStrategy)
	}
}
