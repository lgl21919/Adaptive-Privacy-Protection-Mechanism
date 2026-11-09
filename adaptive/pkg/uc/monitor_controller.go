package uc

import (
	"fmt"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
)

// ProductionStrategy is the IAPP/DAPP trace emitted by the real business path.
type ProductionStrategy struct {
	SID        string
	UserID     string
	IAPP       string
	DAPP       string
	Phase      string
	Role       string
	ReviewMode string
	DataType   string
	Level      int
	Plaintext  []byte // optional; used only for UC sample encrypt path
}

// LoopResult is the outcome of one closed-loop control step.
type LoopResult struct {
	ControlResult
	RecordOnly    bool   `json:"record_only"`     // map hit + verified → only log
	UCTriggered   bool   `json:"uc_triggered"`    // [3] UC verify module ran
	GovernTriggered bool `json:"govern_triggered"` // [4] FeedbackGovernor ran
	UCConsistent  *bool  `json:"uc_consistent,omitempty"`
	MapUpdated    bool   `json:"map_updated"`
	AuditMode     string `json:"audit_mode,omitempty"`
}

// MonitorController is [2] monitor+control: EventDetector + VerificationMap
// (IdealSpec⊕marks) + dual trigger of [3] UC verify and [4] FeedbackGovernor.
type MonitorController struct {
	Detector   *EventDetector
	Spec       *IdealSpec         // UC catalogue (read-mostly)
	Map        *VerificationMap   // monitor-owned marks over Spec
	Controller *TriggerController
	Feedback   *FeedbackGovernor
	Store      *VerificationStore
	Audit      *AuditPair // golden π(production coord) vs F by default
}

func NewMonitorController(journalThreshold int) *MonitorController {
	spec := DefaultIdealSpec()
	vmap := NewVerificationMap(spec)
	fb := NewFeedbackGovernor(journalThreshold)
	fb.SyncWeightsFromMap(vmap) // unverified defaults → low weight until UC passes
	pair, _ := NewGoldenAuditPair()
	return &MonitorController{
		Detector:   NewEventDetector(256),
		Spec:       spec,
		Map:        vmap,
		Controller: NewTriggerController(vmap, fb),
		Feedback:   fb,
		Store:      DefaultVerificationStore(),
		Audit:      pair,
	}
}

// SetAuditPair replaces the UC sampling pair (tests / synced mode).
func (m *MonitorController) SetAuditPair(p *AuditPair) {
	m.Audit = p
}

func (m *MonitorController) QueryLatestVerification() (VerificationSnapshot, bool) {
	if m.Store == nil {
		return VerificationSnapshot{}, false
	}
	return m.Store.Latest()
}

func (m *MonitorController) QueryLatestVerifiedOK() (VerificationSnapshot, bool) {
	if m.Store == nil {
		return VerificationSnapshot{}, false
	}
	return m.Store.LatestOK()
}

// RequireVerifiedPair is a query-only map+snapshot check (no dual trigger).
func (m *MonitorController) RequireVerifiedPair(iapp, dapp string) ControlResult {
	entry, mapped, verified := m.Map.Status(iapp, dapp)
	if mapped && verified {
		e := entry
		return ControlResult{
			Mapped: true, Entry: &e, FeedbackFired: false,
			SessionCfg: m.Feedback.SessionCfg(), JournalCfg: m.Feedback.JournalCfg(),
			EffectiveCfg: m.Feedback.EffectiveCfg(),
			Reason:       "verified_map_entry",
		}
	}
	reason := "not_verified_or_unmapped:" + mappingKey(iapp, dapp)
	session, journal, jl := m.Feedback.OnUnmappedStrategy(reason)
	return ControlResult{
		Mapped: mapped, Entry: mapEntryPtr(entry, mapped), FeedbackFired: true, JournalLifted: jl,
		SessionCfg: session, JournalCfg: journal, EffectiveCfg: m.Feedback.EffectiveCfg(),
		Reason: reason,
	}
}

func mapEntryPtr(e IdealMappingEntry, mapped bool) *IdealMappingEntry {
	if !mapped {
		return nil
	}
	return &e
}

// ObserveProduction is the production→[2] entry: ingest real IAPP/DAPP, check
// verification map; verified → record only; else trigger [3]+[4] together.
func (m *MonitorController) ObserveProduction(ps ProductionStrategy) LoopResult {
	ev := m.Detector.ReceiveCombinedEvent(ps.SID, ps.IAPP, ps.DAPP, ps.Phase, ps.Role, ps.ReviewMode)
	return m.runClosedLoop(ev, ps)
}

// OnHotPathDecision adapts a PolicyDecision into the closed loop.
func (m *MonitorController) OnHotPathDecision(sid string, dec *reasoning.PolicyDecision, in context.ContextInput) ControlResult {
	ps := ProductionStrategy{
		SID: sid, IAPP: "", DAPP: "",
		Phase: in.Phase, Role: in.Role, ReviewMode: in.ReviewMode,
		DataType: in.DataType, Level: in.SecurityLevel,
	}
	if dec != nil {
		ps.IAPP, ps.DAPP = dec.IAPPStrategy, dec.DAPPStrategy
	}
	lr := m.ObserveProduction(ps)
	return lr.ControlResult
}

// OnIdentityAndDataEvents merges separate taps then runs the closed loop.
func (m *MonitorController) OnIdentityAndDataEvents(sid, iapp, dapp, phase, role, reviewMode string) ControlResult {
	m.Detector.ReceiveIdentityEvent(sid, iapp, phase, role, reviewMode)
	m.Detector.ReceiveDataEvent(sid, dapp, phase, role, reviewMode)
	lr := m.ObserveProduction(ProductionStrategy{
		SID: sid, IAPP: iapp, DAPP: dapp, Phase: phase, Role: role, ReviewMode: reviewMode,
	})
	return lr.ControlResult
}

// ObserveAndGovern is the hot-path alias for OnHotPathDecision.
func (m *MonitorController) ObserveAndGovern(sid string, in context.ContextInput, dec *reasoning.PolicyDecision) ControlResult {
	return m.OnHotPathDecision(sid, dec, in)
}

func (m *MonitorController) PrepareInput(in *context.ContextInput) {
	// Refresh weights from map so hot-path reasoning prefers UC-verified pairs.
	m.Feedback.SyncWeightsFromMap(m.Map)
	m.Feedback.ApplyToInput(in)
}

// SyncMapFromLatestOK marks VerifiedPairs from the last OK UC snapshot as verified.
func (m *MonitorController) SyncMapFromLatestOK() (int, bool) {
	snap, ok := m.QueryLatestVerifiedOK()
	if !ok {
		return 0, false
	}
	n := 0
	for _, e := range snap.VerifiedPairs {
		m.Map.MarkVerified(e.IAPP, e.DAPP, snap.RunID, true)
		n++
	}
	return n, true
}

func (m *MonitorController) runClosedLoop(ev StrategyEvent, ps ProductionStrategy) LoopResult {
	out := LoopResult{}
	if ev.IAPP == "" || ev.DAPP == "" {
		session, journal, jl := m.Feedback.OnUnmappedStrategy("incomplete_strategy_event")
		out.ControlResult = ControlResult{
			Mapped: false, FeedbackFired: true, JournalLifted: jl,
			SessionCfg: session, JournalCfg: journal, EffectiveCfg: m.Feedback.EffectiveCfg(),
			Reason: "incomplete_strategy_event",
		}
		out.GovernTriggered = true
		return out
	}

	entry, mapped, verified := m.Map.Status(ev.IAPP, ev.DAPP)
	if mapped && verified {
		e := entry
		out.RecordOnly = true
		out.ControlResult = ControlResult{
			Mapped: true, Entry: &e, FeedbackFired: false,
			SessionCfg: m.Feedback.SessionCfg(), JournalCfg: m.Feedback.JournalCfg(),
			EffectiveCfg: m.Feedback.EffectiveCfg(),
			Reason:       fmt.Sprintf("verified_record_only:%s", entry.FAdaptivePath),
		}
		return out
	}

	// Not mapped or not verified → [3] UC on this request's σ, then [4] Gov.
	out.UCTriggered = true
	out.GovernTriggered = true
	reason := "unverified_or_unmapped:" + mappingKey(ev.IAPP, ev.DAPP)
	if mapped && !verified {
		reason = "map_entry_unverified:" + mappingKey(ev.IAPP, ev.DAPP)
	} else if !mapped {
		reason = "unmapped_strategy:" + mappingKey(ev.IAPP, ev.DAPP)
	}

	cfgAtObserve := m.Feedback.EffectiveCfg()
	ucOK, mapUpdated, auditMode := m.runUCVerifyAndUpdateMap(ps, cfgAtObserve)

	session := m.Feedback.SessionCfg()
	journal := m.Feedback.JournalCfg()
	jl := false
	needLift := !mapped || ucOK == nil || !*ucOK
	if needLift {
		session, journal, jl = m.Feedback.OnUnmappedStrategy(reason)
	}
	if ucOK != nil {
		m.Feedback.ApplyUCWeight(ev.IAPP, ev.DAPP, *ucOK)
	} else if !mapped {
		m.Feedback.DemotePair(ev.IAPP, ev.DAPP)
	}
	m.Feedback.SyncWeightsFromMap(m.Map)

	out.ControlResult = ControlResult{
		Mapped: mapped, Entry: mapEntryPtr(entry, mapped),
		FeedbackFired: true, JournalLifted: jl,
		SessionCfg: session, JournalCfg: journal, EffectiveCfg: m.Feedback.EffectiveCfg(),
		Reason: reason,
	}
	out.UCConsistent = ucOK
	out.MapUpdated = mapUpdated
	out.AuditMode = auditMode
	if ucOK != nil && *ucOK {
		if e, ok, v := m.Map.Status(ev.IAPP, ev.DAPP); ok {
			out.Entry = &e
			out.Mapped = true
			if v {
				out.Reason = reason + "|uc_pass_marked_verified"
			}
		}
	}
	return out
}

func (m *MonitorController) runUCVerifyAndUpdateMap(ps ProductionStrategy, cfg context.ModeConfig) (consistent *bool, mapUpdated bool, mode string) {
	if m.Audit == nil {
		pair, err := NewGoldenAuditPair()
		if err != nil {
			return nil, false, ""
		}
		m.Audit = pair
	}
	mode = string(m.Audit.Mode)
	pt := ps.Plaintext
	if len(pt) == 0 {
		pt = []byte("uc-closed-loop-sample")
	}
	level := ps.Level
	if level < 0 {
		level = 1
	}
	dtype := ps.DataType
	if dtype == "" {
		dtype = "MANUSCRIPT"
	}
	req := AdaptiveRequest{
		SID: ps.SID, UserID: ps.UserID,
		Input: context.ContextInput{
			SessionID: ps.SID, Phase: ps.Phase, Role: ps.Role, ReviewMode: ps.ReviewMode,
			DataType: dtype, SecurityLevel: level,
			RegisteredRole: ps.Role, AuthenticatedPhase: ps.Phase,
			ModeConfig: cfg,
		},
		Plaintext: pt,
		// π pins the online business strategy; F re-selects ideal for same C.
		OnlineStrategy: &OnlineStrategy{
			IAPP: ps.IAPP, DAPP: ps.DAPP, SecurityLevel: level,
		},
	}
	if req.UserID == "" {
		req.UserID = "prod-audit"
	}
	// Keep IdealSpec aligned with live emissions (config-level online sync).
	if m.Spec != nil {
		m.Spec.EnsureOnlinePair(ps.IAPP, ps.DAPP)
	} else if m.Map != nil && m.Map.Spec() != nil {
		m.Map.Spec().EnsureOnlinePair(ps.IAPP, ps.DAPP)
	}
	rec, err := m.Audit.Compare(req)
	if err != nil {
		m.Map.MarkVerified(ps.IAPP, ps.DAPP, "uc-error", false)
		f := false
		return &f, true, mode
	}
	runID := rec.TraceHash
	if runID == "" {
		runID = "uc-" + ps.SID
	}
	m.Map.MarkVerified(ps.IAPP, ps.DAPP, runID, rec.Consistent)
	// Also apply consistency to governor path if mismatch (attest-style).
	if !rec.Consistent || rec.RealTrace.FallbackUsed {
		m.Feedback.ApplyConsistencyRecord(rec.OnChainPayload())
	}
	ok := rec.Consistent
	return &ok, true, mode
}
