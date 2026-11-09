package uc

import (
	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
)

// NymCandidate is a real protocol that is proved to UC-realise F_nym
// (same ideal functionality; different implementation).
type NymCandidate struct {
	kind NymKind
	prot *identity.Protector
}

func NewNymCandidate(kind NymKind, master []byte) *NymCandidate {
	return &NymCandidate{kind: kind, prot: identity.NewProtector(master)}
}

func (c *NymCandidate) Name() string {
	switch c.kind {
	case NymReal:
		return "π_real"
	case NymPseudo:
		return "π_pseudo"
	default:
		return "π_anon"
	}
}

func (c *NymCandidate) Issue(req NymRequest) identity.Handle {
	kind := req.Kind
	if kind == "" {
		kind = c.kind
	}
	phase, review, role := splitScope(req.Scope)
	return c.prot.Protect(string(kind), req.UID, req.SA, phase, review, role)
}

func splitScope(scope string) (phase, review, role string) {
	n := 0
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == '|' {
			part := scope[start:i]
			switch n {
			case 0:
				phase = part
			case 1:
				review = part
			case 2:
				role = part
			}
			n++
			start = i + 1
		}
	}
	return
}

// SCCandidate is a real encryption protocol that UC-realises F_SC.
// ECDH realises F_KE, SSS realises F_DKG, PRE realises F_PRE; each is
// then used as a drop-in F_SC implementation. ρ_app does not branch on the tag.
type SCCandidate struct {
	alg       string
	primitive string
	ex        *crypto.Executor
}

func NewSCCandidate(alg, primitive string) *SCCandidate {
	return &SCCandidate{alg: alg, primitive: primitive, ex: crypto.NewExecutor()}
}

func (c *SCCandidate) Algorithm() string { return c.alg }
func (c *SCCandidate) Name() string      { return "π_" + c.alg }
func (c *SCCandidate) Primitive() string { return c.primitive }

func (c *SCCandidate) schemeOf(scheme crypto.Scheme) crypto.Scheme {
	if len(scheme.Algorithms) == 0 {
		scheme.Algorithms = []string{c.alg}
	}
	if scheme.Token == "" {
		scheme.Token = c.alg
	}
	return scheme
}

func (c *SCCandidate) Seal(scheme crypto.Scheme, plaintext []byte) (crypto.Ciphertext, error) {
	return c.ex.Encrypt(c.schemeOf(scheme), plaintext)
}

func (c *SCCandidate) Open(scheme crypto.Scheme, ct crypto.Ciphertext) ([]byte, error) {
	return c.ex.Decrypt(c.schemeOf(scheme), ct)
}

// DefaultNymCandidates are the identity realisations of F_nym.
func DefaultNymCandidates(master []byte) []NymService {
	return []NymService{
		NewNymCandidate(NymReal, master),
		NewNymCandidate(NymPseudo, master),
		NewNymCandidate(NymAnonymous, master),
	}
}

// DefaultSCCandidates are the data realisations of F_SC (via F_KE / F_DKG / F_PRE).
func DefaultSCCandidates() []SCService {
	return []SCService{
		NewSCCandidate("ECDH", PrimitiveKE),
		NewSCCandidate("SSS", PrimitiveDKG),
		NewSCCandidate("PRE", PrimitivePRE),
		NewSCCandidate("MPC", PrimitiveMPC),
	}
}
