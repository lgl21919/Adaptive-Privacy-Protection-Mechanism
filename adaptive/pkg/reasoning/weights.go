package reasoning

import (
	"strings"
	"sync"
)

// Security-weight tiers used by hot-path strategy selection.
// UC-verified pairs rank above static baseline; unverified / failed pairs rank below.
const (
	WeightVerified   = 100 // UC verification passed
	WeightBaseline   = 50  // static rule only; never seen by UC
	WeightUnverified = 25  // mapped but not yet verified
	WeightFailed     = 10  // UC verification failed / inconsistent
)

// PolicyWeightStore holds UC/governed security weights for IAPP, DAPP, and
// (IAPP|DAPP) combinations. The reasoning engine scores candidates with these
// weights so selection is not driven by static YAML priority alone.
type PolicyWeightStore struct {
	mu    sync.RWMutex
	iapp  map[string]int
	dapp  map[string]int
	pairs map[string]int
}

func NewPolicyWeightStore() *PolicyWeightStore {
	return &PolicyWeightStore{
		iapp:  make(map[string]int),
		dapp:  make(map[string]int),
		pairs: make(map[string]int),
	}
}

func normTok(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func pairKey(iapp, dapp string) string {
	return normTok(iapp) + "|" + normTok(dapp)
}

// SetIAPP sets the identity-strategy security weight.
func (w *PolicyWeightStore) SetIAPP(iapp string, weight int) {
	if w == nil || iapp == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.iapp[normTok(iapp)] = weight
}

// SetDAPP sets the data/security-strategy security weight.
func (w *PolicyWeightStore) SetDAPP(dapp string, weight int) {
	if w == nil || dapp == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dapp[normTok(dapp)] = weight
}

// SetPair sets the combined (IAPP,DAPP) security weight and refreshes token floors.
func (w *PolicyWeightStore) SetPair(iapp, dapp string, weight int) {
	if w == nil || iapp == "" || dapp == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pairs[pairKey(iapp, dapp)] = weight
	// Keep per-token weights as the max over known pairs (monotonic toward safer).
	ik, dk := normTok(iapp), normTok(dapp)
	if cur, ok := w.iapp[ik]; !ok || weight > cur {
		w.iapp[ik] = weight
	}
	if cur, ok := w.dapp[dk]; !ok || weight > cur {
		w.dapp[dk] = weight
	}
}

// MarkUCResult applies UC outcome to a strategy pair.
func (w *PolicyWeightStore) MarkUCResult(iapp, dapp string, verified bool) {
	if verified {
		w.SetPair(iapp, dapp, WeightVerified)
		return
	}
	w.SetPair(iapp, dapp, WeightFailed)
}

// MarkUnverified marks a mapped-but-unchecked pair.
func (w *PolicyWeightStore) MarkUnverified(iapp, dapp string) {
	w.SetPair(iapp, dapp, WeightUnverified)
}

// IAPPWeight returns the security weight for an identity strategy.
func (w *PolicyWeightStore) IAPPWeight(iapp string) int {
	if w == nil || iapp == "" {
		return WeightBaseline
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if v, ok := w.iapp[normTok(iapp)]; ok {
		return v
	}
	return WeightBaseline
}

// DAPPWeight returns the security weight for a data/security strategy.
func (w *PolicyWeightStore) DAPPWeight(dapp string) int {
	if w == nil || dapp == "" {
		return WeightBaseline
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if v, ok := w.dapp[normTok(dapp)]; ok {
		return v
	}
	return WeightBaseline
}

// PairWeight returns the combination weight; falls back to min(IAPP,DAPP) then baseline.
func (w *PolicyWeightStore) PairWeight(iapp, dapp string) int {
	if w == nil {
		return WeightBaseline
	}
	w.mu.RLock()
	if v, ok := w.pairs[pairKey(iapp, dapp)]; ok {
		w.mu.RUnlock()
		return v
	}
	iw, iok := w.iapp[normTok(iapp)]
	dw, dok := w.dapp[normTok(dapp)]
	w.mu.RUnlock()
	switch {
	case iok && dok:
		if iw < dw {
			return iw
		}
		return dw
	case iok:
		return iw
	case dok:
		return dw
	default:
		return WeightBaseline
	}
}

// Score combines UC/governed security weight with static rule priority.
// Weight dominates so verified strategies beat higher-priority static rules
// that failed or were never verified.
func (w *PolicyWeightStore) Score(secWeight, staticPriority int) int {
	return secWeight*1000 + staticPriority
}

// Snapshot copies current weights (for tests / observability).
func (w *PolicyWeightStore) Snapshot() (iapp, dapp, pairs map[string]int) {
	iapp, dapp, pairs = map[string]int{}, map[string]int{}, map[string]int{}
	if w == nil {
		return iapp, dapp, pairs
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	for k, v := range w.iapp {
		iapp[k] = v
	}
	for k, v := range w.dapp {
		dapp[k] = v
	}
	for k, v := range w.pairs {
		pairs[k] = v
	}
	return iapp, dapp, pairs
}
