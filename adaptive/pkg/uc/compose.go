package uc

import (
	"fmt"

	"privacy-protection/adaptive/pkg/identity"
)

// Pair is one (identity candidate × data candidate) plug-in of ρ_app.
// Universal composition says each pair inherits ρ_app's hybrid-world security
// without a dedicated F for that pair.
type Pair struct {
	Nym NymService
	SC  SCService
}

func AllRhoPairs(master []byte) []Pair {
	var out []Pair
	for _, n := range DefaultNymCandidates(master) {
		for _, s := range DefaultSCCandidates() {
			out = append(out, Pair{Nym: n, SC: s})
		}
	}
	return out
}

type CompositionReport struct {
	Pairs           int
	TraceOK         int
	DecryptOK       int
	UnlinkOK        int
	IndependentKeys bool
}

// CheckComposition runs ρ_app against F_nym|F_SC for every candidate pair.
func CheckComposition() (*CompositionReport, error) {
	hybrid, err := NewHybridRhoApp()
	if err != nil {
		return nil, err
	}
	master := []byte("uc-compose-master-key-32bytes!!")
	rep := &CompositionReport{IndependentKeys: IndependentKeys()}
	req := baseReq("REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3, "alice", "paper-uc", []byte("review-body"))

	href, err := hybrid.Invoke(req)
	if err != nil {
		return nil, err
	}

	for _, pair := range AllRhoPairs(master) {
		rep.Pairs++
		ρ := NewRhoApp(hybrid.coord, pair.Nym, pair.SC)
		got, err := ρ.Invoke(req)
		if err != nil {
			return nil, fmt.Errorf("%s+%s: %w", pair.Nym.Name(), pair.SC.Name(), err)
		}
		if tracesEqual(href.Trace, got.Trace) {
			rep.TraceOK++
		}
		pt, err := ρ.Open(got.Scheme, got.Cipher)
		if err == nil && string(pt) == string(req.Plaintext) {
			rep.DecryptOK++
		}
		if nymUnlinkable(ρ, req) {
			rep.UnlinkOK++
		}
	}
	return rep, nil
}

func nymUnlinkable(ρ *RhoApp, req AdaptiveRequest) bool {
	a := req
	a.Input.ModeConfig.ForceAnonymous = true
	r1, err1 := ρ.Invoke(req)
	r2, err2 := ρ.Invoke(a)
	if err1 != nil || err2 != nil {
		return false
	}
	if r2.Identity.Mode != identity.ModeAnonymous {
		return false
	}
	return r1.Identity.Value != r2.Identity.Value
}
