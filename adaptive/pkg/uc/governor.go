package uc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"privacy-protection/adaptive/pkg/context"
)

// ConsistencyRecord is a public attestation of π vs F/S strategy traces.
// Ciphertexts, uids and ideal handle strings are not included.
type ConsistencyRecord struct {
	SID          string      `json:"sid"`
	Consistent   bool        `json:"consistent"`
	Reason       string      `json:"reason,omitempty"`
	RealTrace    PublicTrace `json:"real_trace"`
	IdealTrace   PublicTrace `json:"ideal_trace"`
	TraceHash    string      `json:"trace_hash"`
	RecordedAt   string      `json:"recorded_at"`
	LiftSession  bool        `json:"lift_session"`
	LiftJournal  bool        `json:"lift_journal"`
}

// OnChainConsistencyPayload is the compact ledger record (no plaintext/uid).
type OnChainConsistencyPayload struct {
	SID          string `json:"sid"`
	Consistent   bool   `json:"consistent"`
	TraceHash    string `json:"trace_hash"`
	Reason       string `json:"reason,omitempty"`
	FallbackUsed bool   `json:"fallback_used,omitempty"`
	RecordedAt   string `json:"recorded_at"`
}

// CompareRealIdeal runs π and S(F) on the same request and compares PublicTrace only.
func CompareRealIdeal(π *Protocol, S *Simulator, req AdaptiveRequest) (*ConsistencyRecord, error) {
	real, errR := π.Invoke(req)
	ideal, errS := S.Simulate(req)
	if real == nil {
		return nil, errR
	}
	if ideal == nil {
		return nil, errS
	}
	if errR != nil && !errors.Is(errR, ErrFailClosedAbort) {
		return nil, errR
	}
	if errS != nil && !errors.Is(errS, ErrFailClosedAbort) {
		return nil, errS
	}
	ok := tracesEqual(real.Trace, ideal.Trace)
	reason := ""
	if !ok {
		reason = "public_trace_mismatch"
	}
	if real.Trace.FallbackUsed || ideal.Trace.FallbackUsed || errors.Is(errR, ErrFailClosedAbort) || errors.Is(errS, ErrFailClosedAbort) {
		if reason == "" {
			reason = "fail_closed_abort"
		}
	}
	rec := &ConsistencyRecord{
		SID:         req.SID,
		Consistent:  ok,
		Reason:      reason,
		RealTrace:   real.Trace,
		IdealTrace:  ideal.Trace,
		RecordedAt:  time.Now().UTC().Format(time.RFC3339),
		LiftSession: !ok || real.Trace.FallbackUsed || ideal.Trace.FallbackUsed,
		LiftJournal: false,
	}
	rec.TraceHash = hashTraces(rec.RealTrace, rec.IdealTrace)
	return rec, nil
}

func hashTraces(a, b PublicTrace) string {
	raw, _ := json.Marshal([]PublicTrace{a, b})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func (r *ConsistencyRecord) OnChainPayload() OnChainConsistencyPayload {
	return OnChainConsistencyPayload{
		SID:        r.SID,
		Consistent: r.Consistent,
		TraceHash:  r.TraceHash,
		Reason:     r.Reason,
		FallbackUsed: r.RealTrace.FallbackUsed || r.IdealTrace.FallbackUsed,
		RecordedAt: r.RecordedAt,
	}
}

// LiftModeConfig monotonically raises production cfg after an attested mismatch.
// It never lowers anonymity or encryption strength.
func LiftModeConfig(cfg context.ModeConfig, mismatch bool) context.ModeConfig {
	if !mismatch {
		return cfg
	}
	out := cfg
	out.ForceAnonymous = true
	if out.MinSecurityLevel < 3 {
		out.MinSecurityLevel = 3
	}
	out.AllowComposition = true
	out.RequireSTE = true
	return out
}

// Governor applies session or journal cfg lifts from on-chain mismatch flags.
type Governor struct {
	MismatchStreak int
	JournalThreshold int // consecutive mismatches before journal-wide lift
}

func NewGovernor(journalThreshold int) *Governor {
	if journalThreshold <= 0 {
		journalThreshold = 3
	}
	return &Governor{JournalThreshold: journalThreshold}
}

// ApplyIngestedRecord consumes a ledger mismatch flag and returns updated cfgs.
func (g *Governor) ApplyIngestedRecord(journal, session context.ModeConfig, rec OnChainConsistencyPayload) (journalOut, sessionOut context.ModeConfig, journalLifted bool) {
	journalOut, sessionOut = journal, session
	if rec.Consistent && !rec.FallbackUsed {
		g.MismatchStreak = 0
		return journalOut, sessionOut, false
	}
	sessionOut = LiftModeConfig(session, true)
	g.MismatchStreak++
	if g.MismatchStreak >= g.JournalThreshold {
		journalOut = LiftModeConfig(journal, true)
		g.MismatchStreak = 0
		return journalOut, sessionOut, true
	}
	return journalOut, sessionOut, false
}
