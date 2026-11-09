package uc

import (
	"strings"
	"sync"

	"privacy-protection/adaptive/pkg/reasoning"
)

// IdealSpecEntry is the UC-side specification: an allowed (IAPP,DAPP) pair
// bound to ideal functionality ports. It carries no runtime verification mark.
type IdealSpecEntry struct {
	IAPP          string `json:"iapp"`
	DAPP          string `json:"dapp"`
	FNymKind      string `json:"f_nym_kind"`
	FSCPrimitive  string `json:"f_sc_primitive"`
	FAdaptivePath string `json:"f_adaptive_path"`
	Description   string `json:"description,omitempty"`
}

// IdealMappingEntry is the monitor-facing merged view: UC IdealSpecEntry plus
// runtime verification marks owned by VerificationMap.
type IdealMappingEntry struct {
	IAPP          string `json:"iapp"`
	DAPP          string `json:"dapp"`
	FNymKind      string `json:"f_nym_kind"`
	FSCPrimitive  string `json:"f_sc_primitive"`
	FAdaptivePath string `json:"f_adaptive_path"`
	Description   string `json:"description,omitempty"`
	Verified      bool   `json:"verified"`
	VerifiedRunID string `json:"verified_run_id,omitempty"`
	VerifiedAt    string `json:"verified_at,omitempty"`
}

func (e IdealSpecEntry) toMapping(mark VerificationMark) IdealMappingEntry {
	return IdealMappingEntry{
		IAPP: e.IAPP, DAPP: e.DAPP,
		FNymKind: e.FNymKind, FSCPrimitive: e.FSCPrimitive,
		FAdaptivePath: e.FAdaptivePath, Description: e.Description,
		Verified: mark.Verified, VerifiedRunID: mark.VerifiedRunID, VerifiedAt: mark.VerifiedAt,
	}
}

func mappingKey(iapp, dapp string) string {
	return strings.ToUpper(strings.TrimSpace(iapp)) + "|" + strings.ToUpper(strings.TrimSpace(dapp))
}

// IdealSpec is the UC module's read-mostly catalogue of strategy→F bindings.
// Runtime Verified marks do not live here — see VerificationMap (monitor).
// Version must stay aligned with reasoning.ConfigCatalogVersion / RuleSet.Version.
type IdealSpec struct {
	mu      sync.RWMutex
	version string
	byKey   map[string]IdealSpecEntry
}

// DefaultIdealSpec returns the built-in UC ideal-port catalogue.
func DefaultIdealSpec() *IdealSpec {
	s := &IdealSpec{
		version: SpecCatalogVersion,
		byKey:   make(map[string]IdealSpecEntry),
	}
	s.LoadDefaults()
	return s
}

// Version reports the config-catalog generation (for hot-path sync checks).
func (s *IdealSpec) Version() string {
	if s == nil {
		return SpecCatalogVersion
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.version == "" {
		return SpecCatalogVersion
	}
	return s.version
}

func (s *IdealSpec) LoadDefaults() {
	defaults := []IdealSpecEntry{
		{reasoning.IAPPReal, reasoning.DAPPECDH, string(NymReal), PrimitiveKE, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "real + ECDH"},
		{reasoning.IAPPReal, reasoning.DAPPPublic, string(NymReal), PrimitiveMPC, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "real + public"},
		{reasoning.IAPPPseudonym, reasoning.DAPPECDH, string(NymPseudo), PrimitiveKE, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "pseudo + ECDH"},
		{reasoning.IAPPPseudonym, reasoning.DAPPSSS, string(NymPseudo), PrimitiveDKG, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "pseudo + SSS"},
		{reasoning.IAPPPseudonym, reasoning.DAPPPRE, string(NymPseudo), PrimitivePRE, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "pseudo + PRE"},
		{reasoning.IAPPPseudonym, reasoning.DAPPMPC, string(NymPseudo), PrimitiveMPC, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "pseudo + MPC"},
		{reasoning.IAPPAnonymous, reasoning.DAPPECDH, string(NymAnonymous), PrimitiveKE, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "anon + ECDH"},
		{reasoning.IAPPAnonymous, reasoning.DAPPSSS, string(NymAnonymous), PrimitiveDKG, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "anon + SSS"},
		{reasoning.IAPPAnonymous, reasoning.DAPPPRE, string(NymAnonymous), PrimitivePRE, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "anon + PRE"},
		{reasoning.IAPPAnonymous, reasoning.DAPPMPC, string(NymAnonymous), PrimitiveMPC, "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc", "anon + MPC"},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range defaults {
		s.byKey[mappingKey(e.IAPP, e.DAPP)] = e
	}
}

func (s *IdealSpec) Register(e IdealSpecEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey[mappingKey(e.IAPP, e.DAPP)] = e
}

func (s *IdealSpec) Lookup(iapp, dapp string) (IdealSpecEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byKey[mappingKey(iapp, dapp)]
	return e, ok
}

func (s *IdealSpec) Entries() []IdealSpecEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]IdealSpecEntry, 0, len(s.byKey))
	for _, e := range s.byKey {
		out = append(out, e)
	}
	return out
}

func (s *IdealSpec) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey)
}

// EnsureOnlinePair registers an IdealSpec stub for a live business (IAPP,DAPP)
// if missing, so Spec stays configuration-synced with online emissions.
func (s *IdealSpec) EnsureOnlinePair(iapp, dapp string) IdealSpecEntry {
	if s == nil {
		s = DefaultIdealSpec()
	}
	if e, ok := s.Lookup(iapp, dapp); ok {
		return e
	}
	e := IdealSpecEntry{
		IAPP: iapp, DAPP: dapp,
		FNymKind:      inferNymKind(iapp),
		FSCPrimitive:  inferSCPrimitive(dapp),
		FAdaptivePath: "F_id-strategy∘F_id-protect∘F_enc-strategy∘F_enc",
		Description:   "ensured from online business strategy",
	}
	s.Register(e)
	return e
}

func inferNymKind(iapp string) string {
	switch strings.ToUpper(strings.TrimSpace(iapp)) {
	case reasoning.IAPPReal:
		return string(NymReal)
	case reasoning.IAPPPseudonym:
		return string(NymPseudo)
	default:
		return string(NymAnonymous)
	}
}

func inferSCPrimitive(dapp string) string {
	switch strings.ToUpper(strings.TrimSpace(dapp)) {
	case reasoning.DAPPECDH:
		return PrimitiveKE
	case reasoning.DAPPSSS:
		return PrimitiveDKG
	case reasoning.DAPPPRE:
		return PrimitivePRE
	case reasoning.DAPPMPC, reasoning.DAPPPublic:
		return PrimitiveMPC
	default:
		return PrimitiveKE
	}
}

// NewIdealFunctionalityMap is deprecated naming kept for UC snapshot helpers:
// it returns a VerificationMap bound to DefaultIdealSpec (monitor view).
// Prefer DefaultIdealSpec() for UC and NewVerificationMap(spec) for monitor.
func NewIdealFunctionalityMap() *VerificationMap {
	return NewVerificationMap(DefaultIdealSpec())
}
