package uc

import (
	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/reasoning"
)

// RhoApp is the unified application protocol ρ_app.
// It calls only F_nym and F_SC (or UC-realising candidates). It does not
// branch on whether identity is pseudo vs anonymous, nor on ECDH vs SSS vs PRE.
// Shared state is not used: identity keys are independent of encryption keys
// (standard UC composition, not JUC/GUC).
type RhoApp struct {
	coord *reasoning.AdaptiveCoordinator
	nym   NymService
	sc    SCService
}

func NewRhoApp(coord *reasoning.AdaptiveCoordinator, nym NymService, sc SCService) *RhoApp {
	if coord == nil {
		coord, _ = reasoning.NewDefaultCoordinator()
	}
	return &RhoApp{coord: coord, nym: nym, sc: sc}
}

// NewHybridRhoApp is ρ_app in the F_nym | F_SC hybrid world.
func NewHybridRhoApp() (*RhoApp, error) {
	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		return nil, err
	}
	return NewRhoApp(coord, NewFNym(), NewFSC()), nil
}

// Invoke realises the business session: public strategy, then nym, then SC.
func (ρ *RhoApp) Invoke(req AdaptiveRequest) (*AdaptiveResponse, error) {
	in := req.Input
	if in.SessionID == "" {
		in.SessionID = req.SID
	}
	dec, err := ρ.coord.EvaluatePolicy(in)
	if err != nil {
		return nil, err
	}
	if dec.FallbackUsed || !dec.IntegrityOK {
		return abortBusiness(req.SID, in, dec), ErrFailClosedAbort
	}
	scheme := schemeFromDecision(dec)
	kind := KindFromIAPP(dec.IAPPStrategy)
	handle := ρ.nym.Issue(NymRequest{
		UID:   req.UserID,
		SA:    req.SID,
		Kind:  kind,
		Scope: nymScope(in.Phase, in.ReviewMode, in.Role),
	})
	ct, err := ρ.sc.Seal(scheme, req.Plaintext)
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

func (ρ *RhoApp) Open(scheme crypto.Scheme, ct crypto.Ciphertext) ([]byte, error) {
	return ρ.sc.Open(scheme, ct)
}

func (ρ *RhoApp) NymName() string { return ρ.nym.Name() }
func (ρ *RhoApp) SCName() string  { return ρ.sc.Name() }

// FApp is the business-level ideal functionality that ρ_app realises
// in the F_nym / F_SC hybrid world (via Canetti composition).
func NewFApp() (*RhoApp, error) {
	return NewHybridRhoApp()
}

// IndependentKeys records that identity protection and encryption do not
// share state in this codebase, so standard UC (not JUC) applies.
func IndependentKeys() bool { return true }
