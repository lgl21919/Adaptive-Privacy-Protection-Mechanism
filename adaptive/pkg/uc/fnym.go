package uc

import (
	"fmt"
	"sync"

	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/reasoning"
)

// NymKind is a public parameter of F_nym, not a separate ideal functionality.
// Pseudonym and anonymous generation are candidate realisations of the same F_nym.
type NymKind string

const (
	NymReal      NymKind = identity.ModeReal
	NymPseudo    NymKind = identity.ModePseudonym
	NymAnonymous NymKind = identity.ModeAnonymous
)

// NymRequest is the F_nym input (uid, service SA, kind, linkability scope).
type NymRequest struct {
	UID   string
	SA    string // journal/paper session (S_A in the nym literature)
	Kind  NymKind
	Scope string // phase|reviewMode|role; empty for anonymous
}

// NymService is the hybrid-world identity port used by ρ_app.
type NymService interface {
	Name() string
	Issue(req NymRequest) identity.Handle
}

// FNym is the identity-layer core ideal functionality.
// It balances in-scope pseudonym linkability with anonymous unlinkability
// and conversion-control: switching P↔A does not leak uid.
type FNym struct {
	mu    sync.Mutex
	table map[string]identity.Handle // key = uid|SA|scope for Kind=P only
}

func NewFNym() *FNym {
	return &FNym{table: make(map[string]identity.Handle)}
}

func (f *FNym) Name() string { return "F_nym" }

func (f *FNym) Issue(req NymRequest) identity.Handle {
	switch req.Kind {
	case NymReal:
		return identity.Handle{Mode: identity.ModeReal, Value: "ideal-real:" + req.UID, LinkScope: "global"}
	case NymPseudo:
		key := req.UID + "|" + req.SA + "|" + req.Scope
		f.mu.Lock()
		defer f.mu.Unlock()
		if h, ok := f.table[key]; ok {
			return h
		}
		h := identity.Handle{
			Mode:      identity.ModePseudonym,
			Value:     "ideal-pseudo:" + key,
			LinkScope: req.Scope,
		}
		f.table[key] = h
		return h
	default:
		return identity.SimulatedAnonymous()
	}
}

// KindFromIAPP maps the public identity strategy onto a F_nym parameter.
func KindFromIAPP(iapp string) NymKind {
	switch iapp {
	case reasoning.IAPPReal:
		return NymReal
	case reasoning.IAPPPseudonym:
		return NymPseudo
	default:
		return NymAnonymous
	}
}

func nymScope(phase, reviewMode, role string) string {
	return fmt.Sprintf("%s|%s|%s", phase, reviewMode, role)
}
