package context_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/context"
)

func TestPhaseTamperRejected(t *testing.T) {
	err := context.ValidateStrategyInput(context.ContextInput{
		Phase: "REVIEW", AuthenticatedPhase: "SUBMISSION", Role: "AUTHOR",
	})
	if err == nil {
		t.Fatal("expected phase tamper error")
	}
}

func TestRoleTamperRejected(t *testing.T) {
	err := context.ValidateStrategyInput(context.ContextInput{
		Phase: "REVIEW", Role: "AUTHOR", RegisteredRole: "EDITOR", ReviewMode: "OPEN",
	})
	if err == nil {
		t.Fatal("expected role tamper error")
	}
}

func TestMACRoundTrip(t *testing.T) {
	key := []byte("k")
	in := context.ContextInput{Phase: "SUBMISSION", Role: "AUTHOR", IntegrityKey: key}
	in.IntegrityMAC = context.MACStrategyInput(key, in)
	if err := context.ValidateStrategyInput(in); err != nil {
		t.Fatal(err)
	}
}
