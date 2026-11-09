package uc

import (
	"sync"
	"time"
)

// VerificationMark is the monitor-owned runtime UC outcome for one strategy pair.
type VerificationMark struct {
	Verified      bool   `json:"verified"`
	VerifiedRunID string `json:"verified_run_id,omitempty"`
	VerifiedAt    string `json:"verified_at,omitempty"`
}

// VerificationMap is the monitor/control module's runtime table:
// IdealSpec (UC, read-only reference) ⊕ verification marks (monitor-written).
// Only MonitorController should call MarkVerified.
type VerificationMap struct {
	mu    sync.RWMutex
	spec  *IdealSpec
	marks map[string]VerificationMark
}

// NewVerificationMap binds a UC IdealSpec; marks start empty (unverified).
func NewVerificationMap(spec *IdealSpec) *VerificationMap {
	if spec == nil {
		spec = DefaultIdealSpec()
	}
	return &VerificationMap{
		spec:  spec,
		marks: make(map[string]VerificationMark),
	}
}

// Spec returns the UC ideal-port catalogue (read-mostly).
func (v *VerificationMap) Spec() *IdealSpec {
	if v == nil {
		return DefaultIdealSpec()
	}
	return v.spec
}

// Lookup returns the merged entry if the pair exists in IdealSpec.
func (v *VerificationMap) Lookup(iapp, dapp string) (IdealMappingEntry, bool) {
	if v == nil {
		return IdealMappingEntry{}, false
	}
	spec, ok := v.spec.Lookup(iapp, dapp)
	if !ok {
		return IdealMappingEntry{}, false
	}
	v.mu.RLock()
	mark := v.marks[mappingKey(iapp, dapp)]
	v.mu.RUnlock()
	return spec.toMapping(mark), true
}

// Status reports IdealSpec presence and monitor verification mark.
func (v *VerificationMap) Status(iapp, dapp string) (entry IdealMappingEntry, mapped, verified bool) {
	entry, mapped = v.Lookup(iapp, dapp)
	if !mapped {
		return IdealMappingEntry{}, false, false
	}
	return entry, true, entry.Verified
}

// MarkVerified writes the monitor-side UC outcome. If the pair is absent from
// IdealSpec, a stub spec entry is registered so the closed loop can track it.
func (v *VerificationMap) MarkVerified(iapp, dapp, runID string, ok bool) IdealMappingEntry {
	if v == nil {
		return IdealMappingEntry{}
	}
	if _, exists := v.spec.Lookup(iapp, dapp); !exists {
		v.spec.Register(IdealSpecEntry{
			IAPP: iapp, DAPP: dapp,
			FAdaptivePath: "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc",
			Description:   "registered by monitor closed-loop (absent from IdealSpec)",
		})
	}
	mark := VerificationMark{
		Verified:      ok,
		VerifiedRunID: runID,
		VerifiedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	v.mu.Lock()
	v.marks[mappingKey(iapp, dapp)] = mark
	v.mu.Unlock()
	spec, _ := v.spec.Lookup(iapp, dapp)
	return spec.toMapping(mark)
}

// Entries returns IdealSpec entries merged with current marks (for weight sync).
func (v *VerificationMap) Entries() []IdealMappingEntry {
	if v == nil {
		return nil
	}
	specs := v.spec.Entries()
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]IdealMappingEntry, 0, len(specs))
	for _, s := range specs {
		mark := v.marks[mappingKey(s.IAPP, s.DAPP)]
		out = append(out, s.toMapping(mark))
	}
	return out
}

func (v *VerificationMap) Len() int {
	if v == nil || v.spec == nil {
		return 0
	}
	return v.spec.Len()
}
