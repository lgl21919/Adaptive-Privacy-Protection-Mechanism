package uc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/reasoning"
)

// ExperimentResult is one effectiveness check for the paper's UC argument.
type ExperimentResult struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Passed    bool    `json:"passed"`
	Trials    int     `json:"trials"`
	Metric    float64 `json:"metric"`
	Threshold float64 `json:"threshold"`
	Detail    string  `json:"detail"`
	ElapsedMS float64 `json:"elapsed_ms"`
}

// Report aggregates verification experiments.
type Report struct {
	GeneratedAt string             `json:"generated_at"`
	Passed      int                `json:"passed"`
	Total       int                `json:"total"`
	AllOK       bool               `json:"all_ok"`
	Results     []ExperimentResult `json:"results"`
}

func (r *Report) add(e ExperimentResult) {
	r.Results = append(r.Results, e)
	r.Total++
	if e.Passed {
		r.Passed++
	}
}

// RunVerification executes the UC-oriented effectiveness suite.
func RunVerification(trials int) (*Report, error) {
	if trials < 32 {
		trials = 32
	}
	rep := &Report{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}

	π, err := NewDefaultProtocol()
	if err != nil {
		return nil, err
	}
	F, err := NewDefaultFAdaptive()
	if err != nil {
		return nil, err
	}
	S := NewSimulator(F)

	rep.add(expStrategyDeterminism(π, trials))
	rep.add(expStrategyIntegrity(π, trials))
	rep.add(expPublicTraceSim(π, S, trials))
	rep.add(expUnlinkabilitySwitch(π, trials))
	rep.add(expPseudonymLink(π, trials))
	rep.add(expEncCorrectness(π, trials))
	rep.add(expCompositionCorrectness(π, trials))
	rep.add(expINDCPAAdvantage(π, trials))
	rep.add(expModeConfigFloor(π))
	rep.add(expRequestContentAdapt(π))
	rep.add(expLayeredComposition())

	rep.AllOK = rep.Passed == rep.Total

	imap := DefaultIdealSpec()
	snap := ExtractSnapshot(rep, imap)
	DefaultVerificationStore().Publish(snap)

	return rep, nil
}

// RunVerificationWithSnapshot runs the suite and returns both report and pillar snapshot.
func RunVerificationWithSnapshot(trials int) (*Report, VerificationSnapshot, error) {
	rep, err := RunVerification(trials)
	if err != nil {
		return nil, VerificationSnapshot{}, err
	}
	snap, ok := DefaultVerificationStore().Latest()
	if !ok {
		snap = ExtractSnapshot(rep, DefaultIdealSpec())
	}
	return rep, snap, nil
}

func baseReq(phase, role, mode, dtype string, level int, uid, sid string, pt []byte) AdaptiveRequest {
	in := context.ContextInput{
		SessionID:          sid,
		Phase:              phase,
		Role:               role,
		ReviewMode:         mode,
		RequestContent:     "SUBMIT_REVIEW",
		DataType:           dtype,
		SecurityLevel:      level,
		RegisteredRole:     role,
		AuthenticatedPhase: phase,
	}
	return AdaptiveRequest{SID: sid, UserID: uid, Input: in, Plaintext: pt, Adversary: StaticCorruption}
}

func timed(id, name string, trials int, fn func() (bool, float64, float64, string)) ExperimentResult {
	t0 := time.Now()
	ok, metric, thr, detail := fn()
	return ExperimentResult{
		ID: id, Name: name, Passed: ok, Trials: trials,
		Metric: metric, Threshold: thr, Detail: detail,
		ElapsedMS: float64(time.Since(t0).Microseconds()) / 1000.0,
	}
}

func expStrategyDeterminism(π *Protocol, trials int) ExperimentResult {
	return timed("E1", "public strategy function is deterministic", trials, func() (bool, float64, float64, string) {
		mismatch := 0
		req := baseReq("REVIEW", "AUTHOR", "DOUBLE_BLIND", "MANUSCRIPT", 1, "u1", "s1", []byte("paper"))
		first, err := π.Invoke(req)
		if err != nil {
			return false, 1, 0, err.Error()
		}
		for i := 1; i < trials; i++ {
			got, err := π.Invoke(req)
			if err != nil || !tracesEqual(first.Trace, got.Trace) {
				mismatch++
			}
		}
		rate := 1 - float64(mismatch)/float64(trials-1)
		return mismatch == 0, rate, 1.0, fmt.Sprintf("identical public traces %d/%d", trials-1-mismatch, trials-1)
	})
}

func expStrategyIntegrity(π *Protocol, trials int) ExperimentResult {
	return timed("E2", "tampered strategy input fail-closes", trials, func() (bool, float64, float64, string) {
		okN := 0
		for i := 0; i < trials; i++ {
			in := context.ContextInput{
				Phase:              "REVIEW",
				Role:               "AUTHOR",
				ReviewMode:         "OPEN",
				DataType:           "MANUSCRIPT",
				SecurityLevel:      1,
				AuthenticatedPhase: "SUBMISSION", // tamper: claim REVIEW while SM is SUBMISSION
				RegisteredRole:     "AUTHOR",
			}
			dec, err := π.coord.EvaluatePolicy(in)
			if err == nil && dec.FallbackUsed && dec.IAPPStrategy == reasoning.IAPPAnonymous && dec.SecurityLevel >= 3 {
				okN++
			}
		}
		rate := float64(okN) / float64(trials)
		return okN == trials, rate, 1.0, fmt.Sprintf("fail-closed %d/%d", okN, trials)
	})
}

func expPublicTraceSim(π *Protocol, S *Simulator, trials int) ExperimentResult {
	return timed("E3", "simulator matches public strategy I/O", trials, func() (bool, float64, float64, string) {
		mismatch := 0
		cases := []AdaptiveRequest{
			baseReq("SUBMISSION", "AUTHOR", "", "MANUSCRIPT", 1, "uA", "sid-sub", []byte("m1")),
			baseReq("REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3, "uR", "sid-rev", []byte("m2")),
			baseReq("REVIEW", "AUTHOR", "SINGLE_BLIND", "MANUSCRIPT", 2, "uA", "sid-sb", []byte("m3")),
			baseReq("PUBLICATION", "EDITOR", "", "MESSAGE", 0, "uE", "sid-pub", []byte("m4")),
		}
		n := 0
		for i := 0; i < trials; i++ {
			req := cases[i%len(cases)]
			req.SID = fmt.Sprintf("%s-%d", req.SID, i)
			real, err1 := π.Invoke(req)
			sim, err2 := S.Simulate(req)
			n++
			if err1 != nil || err2 != nil || !tracesEqual(real.Trace, sim.Trace) {
				mismatch++
			}
		}
		rate := 1 - float64(mismatch)/float64(n)
		return mismatch == 0, rate, 1.0, fmt.Sprintf("trace match %d/%d", n-mismatch, n)
	})
}

func expUnlinkabilitySwitch(π *Protocol, trials int) ExperimentResult {
	return timed("E4", "pseudonym→anonymous unlinkability", trials, func() (bool, float64, float64, string) {
		linked := 0
		for i := 0; i < trials; i++ {
			uid := fmt.Sprintf("user-%d", i)
			pseudoReq := baseReq("REVIEW", "AUTHOR", "DOUBLE_BLIND", "MANUSCRIPT", 1, uid, "paper-1", []byte("a"))
			anonReq := baseReq("REVIEW", "AUTHOR", "DOUBLE_BLIND", "MANUSCRIPT", 1, uid, "paper-1", []byte("b"))
			anonReq.Input.ModeConfig.ForceAnonymous = true
			p, err1 := π.Invoke(pseudoReq)
			a, err2 := π.Invoke(anonReq)
			if err1 != nil || err2 != nil {
				linked++
				continue
			}
			if p.Identity.Value == a.Identity.Value || a.Identity.Mode != identity.ModeAnonymous {
				linked++
			}
		}
		unlink := 1 - float64(linked)/float64(trials)
		return linked == 0, unlink, 1.0, fmt.Sprintf("unlinked sessions %d/%d", trials-linked, trials)
	})
}

func expPseudonymLink(π *Protocol, trials int) ExperimentResult {
	return timed("E5", "intra-phase pseudonym linkability / cross-phase unlinkability", trials, func() (bool, float64, float64, string) {
		bad := 0
		for i := 0; i < trials; i++ {
			uid := "author-fixed"
			r1 := baseReq("REVIEW", "AUTHOR", "DOUBLE_BLIND", "MANUSCRIPT", 1, uid, "pX", []byte("a"))
			r2 := baseReq("REVIEW", "AUTHOR", "DOUBLE_BLIND", "MESSAGE", 1, uid, "pX", []byte("b"))
			r3 := baseReq("PUBLICATION", "AUTHOR", "", "MANUSCRIPT", 1, uid, "pX", []byte("c"))
			a, e1 := π.Invoke(r1)
			b, e2 := π.Invoke(r2)
			c, e3 := π.Invoke(r3)
			if e1 != nil || e2 != nil || e3 != nil {
				bad++
				continue
			}
			if a.Identity.Value != b.Identity.Value {
				bad++
			}
			if a.Identity.Value == c.Identity.Value {
				bad++
			}
		}
		okRate := 1 - float64(bad)/float64(trials)
		return bad == 0, okRate, 1.0, fmt.Sprintf("link/unlink checks passed %d/%d", trials-bad, trials)
	})
}

func expEncCorrectness(π *Protocol, trials int) ExperimentResult {
	return timed("E6", "F_enc correctness (single algorithm)", trials, func() (bool, float64, float64, string) {
		fail := 0
		for i := 0; i < trials; i++ {
			msg := []byte(fmt.Sprintf("manuscript-%d", i))
			req := baseReq("SUBMISSION", "AUTHOR", "", "MANUSCRIPT", 1, "u", "s", msg)
			resp, err := π.Invoke(req)
			if err != nil {
				fail++
				continue
			}
			pt, err := π.Decrypt(resp.Scheme, resp.Cipher)
			if err != nil || string(pt) != string(msg) {
				fail++
			}
		}
		rate := 1 - float64(fail)/float64(trials)
		return fail == 0, rate, 1.0, fmt.Sprintf("decrypt ok %d/%d", trials-fail, trials)
	})
}

func expCompositionCorrectness(π *Protocol, trials int) ExperimentResult {
	return timed("E7", "multi-algorithm composition correctness", trials, func() (bool, float64, float64, string) {
		fail := 0
		for i := 0; i < trials; i++ {
			msg := []byte(fmt.Sprintf("recommendation-%d", i))
			req := baseReq("REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3, "rev", "sid", msg)
			resp, err := π.Invoke(req)
			if err != nil {
				fail++
				continue
			}
			if len(resp.Scheme.Algorithms) < 2 && resp.Scheme.ComposeMode != crypto.ComposeSTE {
				fail++
				continue
			}
			pt, err := π.Decrypt(resp.Scheme, resp.Cipher)
			if err != nil || string(pt) != string(msg) {
				fail++
			}
		}
		rate := 1 - float64(fail)/float64(trials)
		return fail == 0, rate, 1.0, fmt.Sprintf("compose decrypt ok %d/%d", trials-fail, trials)
	})
}

func expINDCPAAdvantage(π *Protocol, trials int) ExperimentResult {
	return timed("E8", "ciphertext does not leak plaintext (advantage ≈ 0)", trials, func() (bool, float64, float64, string) {
		hits := 0
		m0 := bytesOf('A', 64)
		m1 := bytesOf('B', 64)
		for i := 0; i < trials; i++ {
			bit := i % 2
			msg := m0
			if bit == 1 {
				msg = m1
			}
			req := baseReq("REVIEW", "AUTHOR", "DOUBLE_BLIND", "MANUSCRIPT", 2, "u", fmt.Sprintf("s-%d", i), msg)
			resp, err := π.Invoke(req)
			if err != nil {
				continue
			}
			guess := distinguishByPlaintextEcho(resp.Cipher.Blob, m0, m1)
			if guess == bit {
				hits++
			}
		}
		acc := float64(hits) / float64(trials)
		adv := math.Abs(2*acc - 1)
		return adv < 0.35, adv, 0.35, fmt.Sprintf("guess accuracy=%.3f advantage=%.3f (threshold 0.35)", acc, adv)
	})
}

func distinguishByPlaintextEcho(ct, m0, m1 []byte) int {
	s0 := sha256.Sum256(m0)
	s1 := sha256.Sum256(m1)
	h := hex.EncodeToString(ct)
	if len(h) >= 16 && h[:16] == hex.EncodeToString(s0[:8]) {
		return 0
	}
	if len(h) >= 16 && h[:16] == hex.EncodeToString(s1[:8]) {
		return 1
	}
	n0, n1 := 0, 0
	lim := len(ct)
	if lim > len(m0) {
		lim = len(m0)
	}
	for i := 0; i < lim; i++ {
		if ct[i] == m0[i] {
			n0++
		}
		if ct[i] == m1[i] {
			n1++
		}
	}
	if n1 > n0 {
		return 1
	}
	return 0
}

func expModeConfigFloor(π *Protocol) ExperimentResult {
	return timed("E9", "mode-config raises protection floor", 1, func() (bool, float64, float64, string) {
		req := baseReq("REVIEW", "AUTHOR", "SINGLE_BLIND", "MANUSCRIPT", 1, "u", "s", []byte("x"))
		base, err := π.Invoke(req)
		if err != nil {
			return false, 0, 1, err.Error()
		}
		req.Input.ModeConfig = context.ModeConfig{ForceAnonymous: true, MinSecurityLevel: 3, AllowComposition: true}
		lifted, err := π.Invoke(req)
		if err != nil {
			return false, 0, 1, err.Error()
		}
		ok := lifted.Identity.Mode == identity.ModeAnonymous &&
			lifted.Decision.SecurityLevel >= 3 &&
			len(lifted.Scheme.Algorithms) >= 2 &&
			base.Trace.IAPP == reasoning.IAPPReal
		if ok {
			return true, 1, 1, "single-blind author REAL → cfg-forced ANONYMOUS + composition"
		}
		return false, 0, 1, fmt.Sprintf("base=%s lifted=%s algs=%v", base.Trace.IAPP, lifted.Trace.IAPP, lifted.Scheme.Algorithms)
	})
}

func expRequestContentAdapt(π *Protocol) ExperimentResult {
	return timed("E10", "request content + review mode enter public trace", 1, func() (bool, float64, float64, string) {
		req := baseReq("REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3, "r", "s", []byte("rev"))
		req.Input.RequestContent = "SUBMIT_REVIEW_REPORT"
		resp, err := π.Invoke(req)
		if err != nil {
			return false, 0, 1, err.Error()
		}
		ok := resp.Trace.RequestContent == "SUBMIT_REVIEW_REPORT" &&
			resp.Trace.IAPP == reasoning.IAPPPseudonym &&
			resp.Trace.DAPP == reasoning.DAPPMPC
		if ok {
			return true, 1, 1, "reviewer double-blind report → PSEUDONYMOUS + MPC composition"
		}
		return false, 0, 1, fmt.Sprintf("iapp=%s dapp=%s q=%s", resp.Trace.IAPP, resp.Trace.DAPP, resp.Trace.RequestContent)
	})
}

func expLayeredComposition() ExperimentResult {
	return timed("E11", "F_nym × F_SC composition (no per-pair ideal)", 12, func() (bool, float64, float64, string) {
		rep, err := CheckComposition()
		if err != nil {
			return false, 0, 1, err.Error()
		}
		ok := rep.TraceOK == rep.Pairs && rep.DecryptOK == rep.Pairs && rep.UnlinkOK == rep.Pairs && rep.IndependentKeys
		rate := float64(rep.TraceOK) / float64(rep.Pairs)
		return ok, rate, 1.0, fmt.Sprintf("pairs=%d trace=%d decrypt=%d unlink=%d independent_keys=%v",
			rep.Pairs, rep.TraceOK, rep.DecryptOK, rep.UnlinkOK, rep.IndependentKeys)
	})
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
