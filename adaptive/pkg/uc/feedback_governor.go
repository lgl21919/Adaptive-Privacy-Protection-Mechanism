package uc

import (
	"fmt"
	"sync"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
)

// FeedbackGovernor raises production hot-path ModeConfig (σ/cfg) and maintains
// UC-driven security weights that the reasoning engine uses for strategy
// selection (verified → high weight; unverified/failed → low weight).
type FeedbackGovernor struct {
	mu         sync.Mutex
	gov        *Governor
	journalCfg context.ModeConfig
	sessionCfg context.ModeConfig
	liftCount  int
	lastReason string
	weights    *reasoning.PolicyWeightStore
}

func NewFeedbackGovernor(journalThreshold int) *FeedbackGovernor {
	return &FeedbackGovernor{
		gov:     NewGovernor(journalThreshold),
		weights: reasoning.NewPolicyWeightStore(),
	}
}

// Weights returns the security-weight store governing hot-path selection.
func (f *FeedbackGovernor) Weights() *reasoning.PolicyWeightStore {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.weights == nil {
		f.weights = reasoning.SharedPolicyWeights()
	}
	return f.weights
}

// SetWeights replaces the weight store (tests / isolated monitor instances).
func (f *FeedbackGovernor) SetWeights(w *reasoning.PolicyWeightStore) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if w == nil {
		w = reasoning.NewPolicyWeightStore()
	}
	f.weights = w
}

func (f *FeedbackGovernor) JournalCfg() context.ModeConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.journalCfg
}

func (f *FeedbackGovernor) SessionCfg() context.ModeConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessionCfg
}

// EffectiveCfg is journal floor merged under session (session wins on True/higher).
func (f *FeedbackGovernor) EffectiveCfg() context.ModeConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return mergeModeConfig(f.journalCfg, f.sessionCfg)
}

func mergeModeConfig(journal, session context.ModeConfig) context.ModeConfig {
	out := journal
	if session.ForceAnonymous {
		out.ForceAnonymous = true
	}
	if session.MinSecurityLevel > out.MinSecurityLevel {
		out.MinSecurityLevel = session.MinSecurityLevel
	}
	if session.AllowComposition {
		out.AllowComposition = true
	}
	if session.RequireSTE {
		out.RequireSTE = true
	}
	return out
}

// SyncWeightsFromMap mirrors VerificationMap marks into security weights
// used by the hot-path reasoning module.
func (f *FeedbackGovernor) SyncWeightsFromMap(vmap *VerificationMap) {
	if vmap == nil {
		return
	}
	w := f.Weights()
	for _, e := range vmap.Entries() {
		switch {
		case e.Verified:
			w.MarkUCResult(e.IAPP, e.DAPP, true)
		case e.VerifiedRunID != "":
			// UC ran and failed (mark present, Verified=false).
			w.MarkUCResult(e.IAPP, e.DAPP, false)
		default:
			w.MarkUnverified(e.IAPP, e.DAPP)
		}
	}
}

// ApplyUCWeight updates one pair after a UC compare and refreshes shared store.
func (f *FeedbackGovernor) ApplyUCWeight(iapp, dapp string, verified bool) {
	w := f.Weights()
	w.MarkUCResult(iapp, dapp, verified)
}

// OnUnmappedStrategy triggers Feedback Governor: lift session cfg (and journal
// after streak), never lowering protection.
func (f *FeedbackGovernor) OnUnmappedStrategy(reason string) (session, journal context.ModeConfig, journalLifted bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReason = reason
	f.liftCount++
	rec := OnChainConsistencyPayload{
		Consistent:   false,
		FallbackUsed: true,
		Reason:       reason,
	}
	journal, session, journalLifted = f.gov.ApplyIngestedRecord(f.journalCfg, f.sessionCfg, rec)
	f.journalCfg, f.sessionCfg = journal, session
	return session, journal, journalLifted
}

// DemotePair lowers security weight for an unmapped / failed combination.
func (f *FeedbackGovernor) DemotePair(iapp, dapp string) {
	if iapp == "" || dapp == "" {
		return
	}
	f.Weights().MarkUCResult(iapp, dapp, false)
}

// ApplyConsistencyRecord forwards π vs S mismatch attestations (existing path).
func (f *FeedbackGovernor) ApplyConsistencyRecord(rec OnChainConsistencyPayload) (session, journal context.ModeConfig, journalLifted bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	journal, session, journalLifted = f.gov.ApplyIngestedRecord(f.journalCfg, f.sessionCfg, rec)
	f.journalCfg, f.sessionCfg = journal, session
	if !rec.Consistent || rec.FallbackUsed {
		f.liftCount++
		f.lastReason = rec.Reason
	}
	return session, journal, journalLifted
}

func (f *FeedbackGovernor) LiftCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.liftCount
}

func (f *FeedbackGovernor) LastReason() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReason
}

// ApplyToInput writes EffectiveCfg into a hot-path ContextInput and attaches
// the governor weight store to the shared AdaptiveCoordinator so Evaluate*
// selects by UC weights rather than static rules alone.
func (f *FeedbackGovernor) ApplyToInput(in *context.ContextInput) {
	if in == nil {
		return
	}
	f.mu.Lock()
	cfg := mergeModeConfig(f.journalCfg, f.sessionCfg)
	w := f.weights
	if w == nil {
		w = reasoning.SharedPolicyWeights()
		f.weights = w
	}
	f.mu.Unlock()

	in.ModeConfig = mergeModeConfig(in.ModeConfig, cfg)
	reasoning.SetSharedPolicyWeights(w)
	if coord, err := reasoning.LoadCoordinatorFromEnv(); err == nil && coord != nil {
		coord.AttachWeights(w)
	}
}

// ControlResult is the outcome of one monitor/controller step.
type ControlResult struct {
	Mapped        bool               `json:"mapped"`
	Entry         *IdealMappingEntry `json:"entry,omitempty"`
	FeedbackFired bool               `json:"feedback_fired"`
	JournalLifted bool               `json:"journal_lifted"`
	SessionCfg    context.ModeConfig `json:"session_cfg"`
	JournalCfg    context.ModeConfig `json:"journal_cfg"`
	EffectiveCfg  context.ModeConfig `json:"effective_cfg"`
	Reason        string             `json:"reason,omitempty"`
}

// TriggerController compares received strategies against the UC IdealSpec
// (via VerificationMap); on miss it triggers FeedbackGovernor.
type TriggerController struct {
	vmap     *VerificationMap
	feedback *FeedbackGovernor
}

func NewTriggerController(vmap *VerificationMap, fb *FeedbackGovernor) *TriggerController {
	if vmap == nil {
		vmap = NewVerificationMap(DefaultIdealSpec())
	}
	if fb == nil {
		fb = NewFeedbackGovernor(3)
	}
	return &TriggerController{vmap: vmap, feedback: fb}
}

// HandleEvent looks up (IAPP,DAPP). Missing IAPP or DAPP alone is treated as incomplete.
func (c *TriggerController) HandleEvent(ev StrategyEvent) ControlResult {
	if ev.IAPP == "" || ev.DAPP == "" {
		session, journal, jl := c.feedback.OnUnmappedStrategy("incomplete_strategy_event")
		return ControlResult{
			Mapped: false, FeedbackFired: true, JournalLifted: jl,
			SessionCfg: session, JournalCfg: journal, EffectiveCfg: c.feedback.EffectiveCfg(),
			Reason: "incomplete_strategy_event",
		}
	}
	entry, ok := c.vmap.Lookup(ev.IAPP, ev.DAPP)
	if ok {
		return ControlResult{
			Mapped: true, Entry: &entry, FeedbackFired: false,
			SessionCfg: c.feedback.SessionCfg(), JournalCfg: c.feedback.JournalCfg(),
			EffectiveCfg: c.feedback.EffectiveCfg(),
			Reason:       fmt.Sprintf("mapped:%s", entry.FAdaptivePath),
		}
	}
	reason := fmt.Sprintf("unmapped_strategy:%s|%s", ev.IAPP, ev.DAPP)
	session, journal, jl := c.feedback.OnUnmappedStrategy(reason)
	c.feedback.DemotePair(ev.IAPP, ev.DAPP)
	return ControlResult{
		Mapped: false, FeedbackFired: true, JournalLifted: jl,
		SessionCfg: session, JournalCfg: journal, EffectiveCfg: c.feedback.EffectiveCfg(),
		Reason: reason,
	}
}
