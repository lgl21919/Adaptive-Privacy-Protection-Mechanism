package uc

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/reasoning"
)

// AttackResult is one executable instance: same adversary, static vs adaptive.
// Success=true means the attacker goal is achieved (worse for the scheme).
type AttackResult struct {
	ID, Name           string
	StaticOK, AdaptOK  bool
	StaticDetail, AdaptDetail string
}

func (r AttackResult) AdaptiveBetter() bool {
	return r.StaticOK && !r.AdaptOK
}

func staticPin(req AdaptiveRequest) AdaptiveRequest {
	return staticPinDAPP(req, reasoning.DAPPECDH, 1)
}

func staticPinDAPP(req AdaptiveRequest, dapp string, level int) AdaptiveRequest {
	req.OnlineStrategy = &OnlineStrategy{
		IAPP: reasoning.IAPPReal, DAPP: dapp, SecurityLevel: level,
	}
	return req
}

func oneKeyAttacker(fullKeys [][]byte, mac []byte) *crypto.Executor {
	junk1 := make([]byte, 32)
	junk2 := make([]byte, 32)
	_, _ = rand.Read(junk1)
	_, _ = rand.Read(junk2)
	return crypto.NewExecutorWithKeys([][]byte{append([]byte(nil), fullKeys[0]...), junk1, junk2}, mac)
}

func newKeyedProtocol(keys [][]byte, mac, master []byte) *Protocol {
	coord, _ := reasoning.NewDefaultCoordinator()
	return &Protocol{
		coord: coord,
		id:    identity.NewProtector(master),
		enc:   crypto.NewExecutorWithKeys(keys, mac),
	}
}

// AttackA1ReviewerSeesDBAuthor: a reviewer who obtained the author's submission
// real-id tries to match it to the review-phase author handle. Static REAL
// keeps the same handle; adaptive switches to a phase-scoped pseudonym.
func AttackA1ReviewerSeesDBAuthor(master []byte) AttackResult {
	id := identity.NewProtector(master)
	uid, paper := "author-alice", "paper-42"
	submitted := id.Protect(identity.ModeReal, uid, paper, "SUBMISSION", "DOUBLE_BLIND", "AUTHOR")
	staticReview := id.Protect(identity.ModeReal, uid, paper, "REVIEW", "DOUBLE_BLIND", "AUTHOR")
	adaptReview := id.Protect(identity.ModePseudonym, uid, paper, "REVIEW", "DOUBLE_BLIND", "AUTHOR")
	return AttackResult{
		ID: "A1", Name: "reviewer links double-blind author to submission real-id",
		StaticOK:     staticReview.Value == submitted.Value,
		AdaptOK:      adaptReview.Value == submitted.Value,
		StaticDetail: fmt.Sprintf("review=%s submission=%s", staticReview.Value, submitted.Value),
		AdaptDetail:  fmt.Sprintf("review=%s submission=%s", adaptReview.Value, submitted.Value),
	}
}

// AttackA2CrossPhaseLink: same uid, submission vs review handles.
func AttackA2CrossPhaseLink(master []byte) AttackResult {
	id := identity.NewProtector(master)
	uid, paper := "author-bob", "paper-7"
	stSub := id.Protect(identity.ModeReal, uid, paper, "SUBMISSION", "DOUBLE_BLIND", "AUTHOR")
	stRev := id.Protect(identity.ModeReal, uid, paper, "REVIEW", "DOUBLE_BLIND", "AUTHOR")
	adSub := id.Protect(identity.ModeReal, uid, paper, "SUBMISSION", "DOUBLE_BLIND", "AUTHOR")
	adRev := id.Protect(identity.ModePseudonym, uid, paper, "REVIEW", "DOUBLE_BLIND", "AUTHOR")
	return AttackResult{
		ID: "A2", Name: "cross-phase handle equality (submission ↔ review)",
		StaticOK:     stSub.Value == stRev.Value,
		AdaptOK:      adSub.Value == adRev.Value,
		StaticDetail: "REAL==REAL",
		AdaptDetail:  "REAL vs PSEUDONYMOUS",
	}
}

// AttackA3SinglePointKey: one leaked ECDH/layer-0 key. Static ℓ=2 manuscript is
// still single-layer ECDH; adaptive uses SSS cascade (≥2 layers).
func AttackA3SinglePointKey(keys [][]byte, mac, master []byte) (AttackResult, error) {
	return AttackA3SinglePointKeyAgainst(keys, mac, master, reasoning.DAPPECDH, 1)
}

func AttackA3SinglePointKeyAgainst(keys [][]byte, mac, master []byte, staticDAPP string, staticLevel int) (AttackResult, error) {
	π := newKeyedProtocol(keys, mac, master)
	att := oneKeyAttacker(keys, mac)
	msg := []byte("manuscript-confidential")
	req := baseReq("REVIEW", "REVIEWER", "DOUBLE_BLIND", "MANUSCRIPT", 2, "rev-1", "sid-a3", msg)

	st, err := π.Invoke(staticPinDAPP(req, staticDAPP, staticLevel))
	if err != nil {
		return AttackResult{}, err
	}
	ad, err := π.Invoke(req)
	if err != nil {
		return AttackResult{}, err
	}
	stPT, stErr := att.Decrypt(st.Scheme, st.Cipher)
	adPT, adErr := att.Decrypt(ad.Scheme, ad.Cipher)
	stHit := stErr == nil && bytes.Equal(stPT, msg)
	adHit := adErr == nil && bytes.Equal(adPT, msg)
	return AttackResult{
		ID: "A3", Name: "single leaked key opens ℓ=2 manuscript",
		StaticOK:     stHit,
		AdaptOK:      adHit,
		StaticDetail: fmt.Sprintf("static=%s scheme=%s decrypt_ok=%v", staticDAPP, st.Scheme.ID(), stHit),
		AdaptDetail:  fmt.Sprintf("scheme=%s iapp=%s dapp=%s decrypt_ok=%v", ad.Scheme.ID(), ad.Trace.IAPP, ad.Trace.DAPP, adHit),
	}, nil
}

// AttackA4NoThreshold: one leaked key on ℓ=3 final recommendation.
// Static remains ECDH; adaptive selects MPC composition.
func AttackA4NoThreshold(keys [][]byte, mac, master []byte) (AttackResult, error) {
	return AttackA4NoThresholdAgainst(keys, mac, master, reasoning.DAPPECDH, 1)
}

func AttackA4NoThresholdAgainst(keys [][]byte, mac, master []byte, staticDAPP string, staticLevel int) (AttackResult, error) {
	π := newKeyedProtocol(keys, mac, master)
	att := oneKeyAttacker(keys, mac)
	msg := []byte("accept-with-major-revision")
	req := baseReq("REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3, "rev-2", "sid-a4", msg)

	st, err := π.Invoke(staticPinDAPP(req, staticDAPP, staticLevel))
	if err != nil {
		return AttackResult{}, err
	}
	ad, err := π.Invoke(req)
	if err != nil {
		return AttackResult{}, err
	}
	stPT, stErr := att.Decrypt(st.Scheme, st.Cipher)
	adPT, adErr := att.Decrypt(ad.Scheme, ad.Cipher)
	stHit := stErr == nil && bytes.Equal(stPT, msg)
	adHit := adErr == nil && bytes.Equal(adPT, msg)
	return AttackResult{
		ID: "A4", Name: "single leaked key opens ℓ=3 recommendation (no threshold)",
		StaticOK:     stHit,
		AdaptOK:      adHit,
		StaticDetail: fmt.Sprintf("static=%s scheme=%s decrypt_ok=%v", staticDAPP, st.Scheme.ID(), stHit),
		AdaptDetail:  fmt.Sprintf("scheme=%s dapp=%s decrypt_ok=%v", ad.Scheme.ID(), ad.Trace.DAPP, adHit),
	}, nil
}
