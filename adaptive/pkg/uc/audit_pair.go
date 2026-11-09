package uc

import (
	"fmt"

	"privacy-protection/adaptive/pkg/reasoning"
)

// AuditMode selects how π and F bind rule coordinators for UC sampling.
//
//	AuditModeGolden (selected): π shares the production coordinator
//	(ADAPTIVE_RULES_PATH / DefaultRuleSet); F stays on the golden DefaultRuleSet.
//	If ops changes production rules without updating the golden F, PublicTrace
//	mismatches — intentional drift detection.
//
//	AuditModeSynced: π and F share one coordinator (self-consistent after a
//	legal rule release that intentionally updates both).
type AuditMode string

const (
	AuditModeGolden AuditMode = "golden"
	AuditModeSynced AuditMode = "synced"
)

// AuditPair is π + S(F) wired for CompareRealIdeal.
type AuditPair struct {
	Mode       AuditMode
	Protocol   *Protocol
	Ideal      *FAdaptive
	Simulator  *Simulator
	CoordPath  string // production rules path ("" = DefaultRuleSet)
	GoldenPath string // always "" for built-in golden F in golden mode
}

// NewProductionProtocol builds π with the same AdaptiveCoordinator singleton as
// identity-policy / data-policy (LoadCoordinatorFromEnv).
func NewProductionProtocol() (*Protocol, error) {
	coord, err := reasoning.LoadCoordinatorFromEnv()
	if err != nil {
		return nil, err
	}
	return NewProtocol(coord, nil), nil
}

// NewGoldenFAdaptive is the fixed UC-spec baseline (built-in DefaultRuleSet).
// It does not follow ADAPTIVE_RULES_PATH — by design under AuditModeGolden.
func NewGoldenFAdaptive() (*FAdaptive, error) {
	return NewDefaultFAdaptive()
}

// NewGoldenAuditPair wires production π against golden F (selected mode).
func NewGoldenAuditPair() (*AuditPair, error) {
	π, err := NewProductionProtocol()
	if err != nil {
		return nil, err
	}
	F, err := NewGoldenFAdaptive()
	if err != nil {
		return nil, err
	}
	return &AuditPair{
		Mode:       AuditModeGolden,
		Protocol:   π,
		Ideal:      F,
		Simulator:  NewSimulator(F),
		CoordPath:  reasoning.CoordinatorEnvPath(),
		GoldenPath: "",
	}, nil
}

// NewSyncedAuditPair wires π and F to the same production coordinator.
func NewSyncedAuditPair() (*AuditPair, error) {
	coord, err := reasoning.LoadCoordinatorFromEnv()
	if err != nil {
		return nil, err
	}
	π := NewProtocol(coord, nil)
	F := NewFAdaptive(coord.Engine())
	return &AuditPair{
		Mode:       AuditModeSynced,
		Protocol:   π,
		Ideal:      F,
		Simulator:  NewSimulator(F),
		CoordPath:  reasoning.CoordinatorEnvPath(),
		GoldenPath: reasoning.CoordinatorEnvPath(),
	}, nil
}

// NewAuditPair selects golden (default) or synced wiring.
func NewAuditPair(mode AuditMode) (*AuditPair, error) {
	switch mode {
	case "", AuditModeGolden:
		return NewGoldenAuditPair()
	case AuditModeSynced:
		return NewSyncedAuditPair()
	default:
		return nil, fmt.Errorf("unknown audit mode %q (want golden|synced)", mode)
	}
}

// Compare runs CompareRealIdeal on this pair.
// If req.OnlineStrategy is set, π uses the online business strategies while
// F/S still compute the ideal strategies for the same context C.
func (p *AuditPair) Compare(req AdaptiveRequest) (*ConsistencyRecord, error) {
	if p == nil || p.Protocol == nil || p.Simulator == nil {
		return nil, fmt.Errorf("nil audit pair")
	}
	return CompareRealIdeal(p.Protocol, p.Simulator, req)
}

// CompareOnline pins π to the given production IAPP/DAPP then compares to ideal F.
func (p *AuditPair) CompareOnline(req AdaptiveRequest, iapp, dapp string, level int) (*ConsistencyRecord, error) {
	req.OnlineStrategy = &OnlineStrategy{IAPP: iapp, DAPP: dapp, SecurityLevel: level}
	return p.Compare(req)
}
