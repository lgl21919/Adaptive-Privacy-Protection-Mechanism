package uc

import (
	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/reasoning"
)

// Protocol π_adaptive is the real-world composition of the four sub-protocols.
type Protocol struct {
	coord *reasoning.AdaptiveCoordinator
	id    *identity.Protector
	enc   *crypto.Executor
}

func NewProtocol(coord *reasoning.AdaptiveCoordinator, master []byte) *Protocol {
	if coord == nil {
		coord, _ = reasoning.NewDefaultCoordinator()
	}
	return &Protocol{
		coord: coord,
		id:    identity.NewProtector(master),
		enc:   crypto.NewExecutor(),
	}
}

func NewDefaultProtocol() (*Protocol, error) {
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		return nil, err
	}
	return NewProtocol(coord, nil), nil
}

// Invoke executes π_id-strategy, π_id-protect, π_enc-strategy, π_enc.
// When req.OnlineStrategy is set, π pins IAPP/DAPP to the online business
// decision instead of re-running EvaluatePolicy (ideal F still re-selects).
func (p *Protocol) Invoke(req AdaptiveRequest) (*AdaptiveResponse, error) {
	in := req.Input
	if in.SessionID == "" {
		in.SessionID = req.SID
	}
	var dec *reasoning.PolicyDecision
	var err error
	if req.OnlineStrategy != nil && req.OnlineStrategy.IAPP != "" && req.OnlineStrategy.DAPP != "" {
		if err := context.ValidateStrategyInput(in); err != nil {
			fb := reasoning.SafestFallback(in)
			reasoning.ApplyModeConfig(fb, in.ModeConfig)
			return abortBusiness(req.SID, in, fb), ErrFailClosedAbort
		}
		dec = decisionFromOnline(in, req.OnlineStrategy)
	} else {
		dec, err = p.coord.EvaluatePolicy(in)
		if err != nil {
			return nil, err
		}
	}
	if dec.FallbackUsed || !dec.IntegrityOK {
		return abortBusiness(req.SID, in, dec), ErrFailClosedAbort
	}
	scheme := schemeFromDecision(dec)
	handle := p.id.Protect(dec.IAPPStrategy, req.UserID, req.SID, in.Phase, in.ReviewMode, in.Role)
	ct, err := p.enc.Encrypt(scheme, req.Plaintext)
	if err != nil {
		return nil, err
	}
	return &AdaptiveResponse{
		Trace:    publicTrace(req.SID, in, dec, scheme),
		Identity: handle,
		Scheme:   scheme,
		Cipher:   ct,
		Decision: dec,
	}, nil
}

// Decrypt opens a ciphertext produced by this protocol instance.
func (p *Protocol) Decrypt(scheme crypto.Scheme, ct crypto.Ciphertext) ([]byte, error) {
	return p.enc.Decrypt(scheme, ct)
}

func abortBusiness(sid string, in context.ContextInput, dec *reasoning.PolicyDecision) *AdaptiveResponse {
	scheme := schemeFromDecision(dec)
	return &AdaptiveResponse{
		Trace:    publicTrace(sid, in, dec, scheme),
		Scheme:   scheme,
		Decision: dec,
	}
}

// InvokeWithMonitor applies FeedbackGovernor cfg, runs π, then observes the
// decision for ideal-map lookup / unmapped feedback. Audit path, not required
// on every pure UC reduction call.
func (p *Protocol) InvokeWithMonitor(req AdaptiveRequest, mon *MonitorController) (*AdaptiveResponse, ControlResult, error) {
	var ctrl ControlResult
	if mon != nil {
		mon.PrepareInput(&req.Input)
	}
	resp, err := p.Invoke(req)
	if mon != nil && resp != nil && resp.Decision != nil {
		ctrl = mon.ObserveAndGovern(req.SID, req.Input, resp.Decision)
		// If this decision was unmapped, cfg is already lifted for the *next* call.
		_ = ctrl
	}
	return resp, ctrl, err
}

func (p *Protocol) Coordinator() *reasoning.AdaptiveCoordinator { return p.coord }

// CaptureContext exposes the context-awareness module for audits.
func Capture(in context.ContextInput) string {
	return context.NewContextAwarenessModule().Capture(in).StateKey
}
