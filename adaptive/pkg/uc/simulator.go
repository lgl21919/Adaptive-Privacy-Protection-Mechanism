package uc

import (
	"errors"

	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
)

// Simulator S interacts with F_adaptive and produces a view indistinguishable
// from the real protocol for environment Z, without learning uid or plaintext.
type Simulator struct {
	F *FAdaptive
}

func NewSimulator(f *FAdaptive) *Simulator { return &Simulator{F: f} }

// Simulate answers Z using only the public strategy I/O leaked by F, dummy
// anonymous credentials, and random (equal-length) ciphertexts.
func (s *Simulator) Simulate(req AdaptiveRequest) (*AdaptiveResponse, error) {
	plainLen := len(req.Plaintext)
	dummy := AdaptiveRequest{
		SID:       req.SID,
		UserID:    "dummy",
		Input:     req.Input,
		Plaintext: make([]byte, plainLen),
		Adversary: req.Adversary,
	}
	ideal, err := s.F.Invoke(dummy)
	if err != nil {
		if errors.Is(err, ErrFailClosedAbort) {
			return ideal, err
		}
		return nil, err
	}

	out := *ideal
	if ideal.Decision != nil && ideal.Decision.IAPPStrategy == identity.ModeAnonymous {
		out.Identity = identity.SimulatedAnonymous()
	}
	if ideal.Scheme.ComposeMode != crypto.ComposeNone && ideal.Scheme.Token != "PUBLIC" {
		rnd, err := crypto.RandomCiphertext(ideal.Scheme, max(1, plainLen))
		if err != nil {
			return nil, err
		}
		out.Cipher = rnd
	}
	return &out, nil
}

func tracesEqual(a, b PublicTrace) bool {
	return a.SID == b.SID &&
		a.Phase == b.Phase &&
		a.Role == b.Role &&
		a.ReviewMode == b.ReviewMode &&
		a.RequestContent == b.RequestContent &&
		a.DataType == b.DataType &&
		a.SecurityLevel == b.SecurityLevel &&
		a.IAPP == b.IAPP &&
		a.DAPP == b.DAPP &&
		a.EncSchemeID == b.EncSchemeID &&
		a.FallbackUsed == b.FallbackUsed &&
		a.IntegrityOK == b.IntegrityOK
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
