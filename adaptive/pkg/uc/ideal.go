package uc

import (
	"fmt"
	"sync"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/reasoning"
)

// FAdaptive is the composed ideal functionality
// F_id-strategy ∘ F_id-protect ∘ F_enc-strategy ∘ F_enc.
type FAdaptive struct {
	engine *reasoning.LogicalReasoningEngine
	enc    *crypto.Executor
	mu     sync.Mutex
	phase  map[string]string // sid -> authenticated phase
}

func NewFAdaptive(engine *reasoning.LogicalReasoningEngine) *FAdaptive {
	return &FAdaptive{
		engine: engine,
		enc:    crypto.NewExecutor(),
		phase:  make(map[string]string),
	}
}

func NewDefaultFAdaptive() (*FAdaptive, error) {
	eng, err := reasoning.NewLogicalReasoningEngine(reasoning.DefaultRuleSet())
	if err != nil {
		return nil, err
	}
	return NewFAdaptive(eng), nil
}

// Invoke is the ideal-world interface used by environment Z and simulator S.
// Ideal F always re-selects strategies from its rule engine for C; it ignores
// req.OnlineStrategy so CompareRealIdeal contrasts online-pinned π vs ideal F.
func (f *FAdaptive) Invoke(req AdaptiveRequest) (*AdaptiveResponse, error) {
	in := req.Input
	if in.SessionID == "" {
		in.SessionID = req.SID
	}

	f.mu.Lock()
	if auth, ok := f.phase[req.SID]; ok && in.AuthenticatedPhase == "" {
		in.AuthenticatedPhase = auth
	}
	f.mu.Unlock()

	dec, err := f.selectStrategies(in)
	if err != nil {
		return nil, err
	}
	if dec.FallbackUsed || !dec.IntegrityOK {
		return abortBusiness(req.SID, in, dec), ErrFailClosedAbort
	}
	scheme := schemeFromDecision(dec)
	handle := f.idProtect(dec.IAPPStrategy, req)
	ct, err := f.enc.Encrypt(scheme, req.Plaintext)
	if err != nil {
		return nil, err
	}

	if dec.IntegrityOK && context.ValidPhases[context.NewContextAwarenessModule().Capture(in).Vector.S] {
		f.mu.Lock()
		f.phase[req.SID] = in.Phase
		f.mu.Unlock()
	}

	return &AdaptiveResponse{
		Trace:    publicTrace(req.SID, in, dec, scheme),
		Identity: handle,
		Scheme:   scheme,
		Cipher:   ct,
		Decision: dec,
	}, nil
}

func (f *FAdaptive) selectStrategies(in context.ContextInput) (*reasoning.PolicyDecision, error) {
	if err := context.ValidateStrategyInput(in); err != nil {
		return reasoning.SafestFallback(in), nil
	}
	coord := reasoning.NewAdaptiveCoordinator(f.engine)
	return coord.EvaluatePolicy(in)
}

func (f *FAdaptive) idProtect(mode string, req AdaptiveRequest) identity.Handle {
	switch mode {
	case identity.ModeReal:
		return identity.Handle{Mode: mode, Value: "ideal-real:" + req.UserID, LinkScope: "global"}
	case identity.ModePseudonym:
		scope := fmt.Sprintf("%s|%s|%s", req.Input.Phase, req.Input.ReviewMode, req.Input.Role)
		return identity.Handle{Mode: mode, Value: "ideal-pseudo:" + req.SID + ":" + scope, LinkScope: scope}
	default:
		return identity.SimulatedAnonymous()
	}
}

// AdvancePhase records the publication state-machine transition for a session.
func (f *FAdaptive) AdvancePhase(sid, phase string) error {
	p := phase
	if _, ok := context.ValidPhases[p]; !ok {
		return fmt.Errorf("invalid phase %s", phase)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.phase[sid]; ok {
		if context.PhaseOrder[p] < context.PhaseOrder[cur] {
			return fmt.Errorf("illegal backward transition %s -> %s", cur, p)
		}
	}
	f.phase[sid] = p
	return nil
}
