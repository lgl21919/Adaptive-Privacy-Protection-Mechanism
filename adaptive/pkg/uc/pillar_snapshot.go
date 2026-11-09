package uc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"privacy-protection/adaptive/pkg/reasoning"
)

// UCOrientedPillars are the four variables that distinguish UC-oriented experiment
// instances. They parallel true UC pillars, but form / checking / rigor are weakened:
//
//	建模假设: mathematical premises → engineering + experimental constraints
//	协议代码: ITM programs → Go executable slices
//	底层假设: reduction targets → lemma premises
//	组合方式: composition theorem → hybrid argument + strategy configuration
type UCOrientedPillars struct {
	ModelingAssumptions PillarModeling `json:"modeling_assumptions"`
	ProtocolCode        PillarProtocol `json:"protocol_code"`
	CryptoAssumptions   PillarCrypto   `json:"crypto_assumptions"`
	Composition         PillarCompose  `json:"composition"`
}

// PillarDelta records how a UC-oriented pillar differs from true UC.
type PillarDelta struct {
	UCForm       string `json:"uc_form"`       // true UC
	OrientedForm string `json:"oriented_form"` // this codebase
}

// PillarModeling: engineering + experimental constraints (not mathematical premises).
type PillarModeling struct {
	PillarDelta
	EngineeringConstraints  []string `json:"engineering_constraints"`
	ExperimentalConstraints []string `json:"experimental_constraints"`
	AdversaryModel          string   `json:"adversary_model"`
	Verified                bool     `json:"verified"`
}

// PillarProtocol: Go packages / entry points (not ITM programs).
type PillarProtocol struct {
	PillarDelta
	Packages    []string `json:"packages"`
	EntryPoints []string `json:"entry_points"`
	Verified    bool     `json:"verified"`
}

// CryptoPremise is a lemma-level assumption used by UC-oriented checks.
type CryptoPremise struct {
	Name           string   `json:"name"`
	UCRole         string   `json:"uc_role"`       // e.g. reduction target
	OrientedRole   string   `json:"oriented_role"` // e.g. lemma premise
	SupportingExps []string `json:"supporting_experiments,omitempty"`
	Checked        bool     `json:"checked"` // experiment-level check present (may be soft)
}

// PillarCrypto: lemma premises (not full reduction targets).
type PillarCrypto struct {
	PillarDelta
	Premises []CryptoPremise `json:"premises"`
	Verified bool            `json:"verified"` // all hard lemma-slice checks passed
}

// IdealLayerSpec is one layer of F_adaptive (strategy configuration under composition).
type IdealLayerSpec struct {
	Name              string   `json:"name"`
	IdealLabel        string   `json:"ideal_label"`
	RealisedBy        string   `json:"realised_by"`
	PublicInputs      []string `json:"public_inputs,omitempty"`
	AllowedStrategies []string `json:"allowed_strategies,omitempty"`
	SupportingExps    []string `json:"supporting_experiments,omitempty"`
	Verified          bool     `json:"verified"`
}

// IdealStack is F_adaptive = F_id-strategy ∘ F_id-protect ∘ F_enc-strategy ∘ F_enc.
// It is strategy configuration inside the composition pillar — not the UC-oriented four pillars.
type IdealStack struct {
	IDStrategy  IdealLayerSpec `json:"f_id_strategy"`
	IDProtect   IdealLayerSpec `json:"f_id_protect"`
	EncStrategy IdealLayerSpec `json:"f_enc_strategy"`
	EncProtect  IdealLayerSpec `json:"f_enc"`
	ComposePath string         `json:"compose_path"`
}

// PillarCompose: hybrid argument + strategy configuration (not UC composition theorem).
type PillarCompose struct {
	PillarDelta
	HybridPath     string     `json:"hybrid_path"` // H0 → … → H4
	IdealStack     IdealStack `json:"ideal_stack"`
	VerifiedIAPP   []string   `json:"verified_iapp_strategies"`
	VerifiedDAPP   []string   `json:"verified_dapp_strategies"`
	SupportingExps []string   `json:"supporting_experiments,omitempty"`
	Verified       bool       `json:"verified"`
}

// ConditionChange records one deterministic check within a UC verification run.
type ConditionChange struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Passed        bool    `json:"passed"`
	Metric        float64 `json:"metric"`
	Threshold     float64 `json:"threshold"`
	Detail        string  `json:"detail"`
	AffectsIAPP   bool    `json:"affects_iapp,omitempty"`
	AffectsDAPP   bool    `json:"affects_dapp,omitempty"`
	AffectsMap    bool    `json:"affects_ideal_map,omitempty"`
	AffectsPillar string  `json:"affects_pillar,omitempty"` // modeling|protocol|crypto|composition
}

// VerificationSnapshot is queryable by MonitorController after each UC run.
type VerificationSnapshot struct {
	RunID            string              `json:"run_id"`
	GeneratedAt      string              `json:"generated_at"`
	AllOK            bool                `json:"all_ok"`
	Passed           int                 `json:"passed"`
	Total            int                 `json:"total"`
	Pillars          UCOrientedPillars   `json:"four_pillars"`
	VerifiedIAPP     []string            `json:"verified_iapp_strategies"`
	VerifiedDAPP     []string            `json:"verified_dapp_strategies"`
	VerifiedPairs    []IdealMappingEntry `json:"verified_ideal_pairs"`
	ConditionChanges []ConditionChange   `json:"condition_changes"`
	IdealMapSize     int                 `json:"ideal_map_size"`
	Report           *Report             `json:"report,omitempty"`
}

// VerificationStore keeps historical UC verification snapshots for the controller.
type VerificationStore struct {
	mu      sync.RWMutex
	runs    []VerificationSnapshot
	maxKeep int
}

var defaultVerificationStore = NewVerificationStore(32)

func DefaultVerificationStore() *VerificationStore { return defaultVerificationStore }

func NewVerificationStore(maxKeep int) *VerificationStore {
	if maxKeep <= 0 {
		maxKeep = 32
	}
	return &VerificationStore{maxKeep: maxKeep}
}

func (s *VerificationStore) Publish(snap VerificationSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs = append(s.runs, snap)
	if len(s.runs) > s.maxKeep {
		s.runs = s.runs[len(s.runs)-s.maxKeep:]
	}
}

func (s *VerificationStore) Latest() (VerificationSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.runs) == 0 {
		return VerificationSnapshot{}, false
	}
	return s.runs[len(s.runs)-1], true
}

func (s *VerificationStore) LatestOK() (VerificationSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.runs) - 1; i >= 0; i-- {
		if s.runs[i].AllOK {
			return s.runs[i], true
		}
	}
	return VerificationSnapshot{}, false
}

func (s *VerificationStore) All() []VerificationSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]VerificationSnapshot, len(s.runs))
	copy(out, s.runs)
	return out
}

// PairVerified reports whether (iapp,dapp) appears in the latest successful run.
func (s *VerificationStore) PairVerified(iapp, dapp string) bool {
	snap, ok := s.LatestOK()
	if !ok {
		return false
	}
	key := mappingKey(iapp, dapp)
	for _, p := range snap.VerifiedPairs {
		if mappingKey(p.IAPP, p.DAPP) == key {
			return true
		}
	}
	return false
}

// ExtractSnapshot builds a queryable snapshot from a Report and the UC IdealSpec.
func ExtractSnapshot(rep *Report, spec *IdealSpec) VerificationSnapshot {
	if spec == nil {
		spec = DefaultIdealSpec()
	}
	if rep == nil {
		rep = &Report{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	runID := "uc-" + time.Now().UTC().Format("20060102T150405Z")
	if len(rep.GeneratedAt) > 0 {
		sum := sha256Short(rep.GeneratedAt + "|" + itoa(rep.Passed) + "/" + itoa(rep.Total))
		runID = "uc-" + sum
	}

	expOK := map[string]bool{}
	changes := make([]ConditionChange, 0, len(rep.Results))
	for _, e := range rep.Results {
		expOK[e.ID] = e.Passed
		ch := ConditionChange{
			ID: e.ID, Name: e.Name, Passed: e.Passed,
			Metric: e.Metric, Threshold: e.Threshold, Detail: e.Detail,
		}
		switch e.ID {
		case "E1", "E2", "E3", "E4", "E5", "E9", "E10":
			ch.AffectsIAPP = true
		}
		switch e.ID {
		case "E1", "E2", "E3", "E6", "E7", "E8", "E9", "E10":
			ch.AffectsDAPP = true
		}
		if e.ID == "E11" || e.ID == "E3" {
			ch.AffectsMap = true
		}
		switch e.ID {
		case "E1", "E2", "E9", "E10":
			ch.AffectsPillar = "modeling"
		case "E3", "E4", "E5", "E6", "E7":
			ch.AffectsPillar = "protocol"
		case "E8":
			ch.AffectsPillar = "crypto"
		case "E11":
			ch.AffectsPillar = "composition"
		}
		changes = append(changes, ch)
	}

	idStratOK := expOK["E1"] && expOK["E2"] && expOK["E3"]
	idProtOK := expOK["E4"] && expOK["E5"]
	encStratOK := expOK["E1"] && expOK["E2"] && expOK["E3"] && expOK["E10"]
	encOK := expOK["E6"] && expOK["E7"]
	mapOK := expOK["E11"]
	// E8 is soft IND-CCA distinguisher — lemma premise check, not a reduction.

	iappSet := map[string]struct{}{}
	dappSet := map[string]struct{}{}
	var pairs []IdealMappingEntry
	for _, e := range spec.Entries() {
		pairOK := idStratOK && encStratOK
		if e.IAPP == reasoning.IAPPPseudonym || e.IAPP == reasoning.IAPPAnonymous || e.IAPP == reasoning.IAPPReal {
			pairOK = pairOK && idProtOK
		}
		if e.DAPP != reasoning.DAPPPublic {
			pairOK = pairOK && encOK
		}
		if _, hasE11 := expOK["E11"]; hasE11 {
			pairOK = pairOK && mapOK
		}
		if pairOK {
			pairs = append(pairs, IdealMappingEntry{
				IAPP: e.IAPP, DAPP: e.DAPP,
				FNymKind: e.FNymKind, FSCPrimitive: e.FSCPrimitive,
				FAdaptivePath: e.FAdaptivePath, Description: e.Description,
				Verified: true, VerifiedRunID: runID,
			})
			iappSet[e.IAPP] = struct{}{}
			dappSet[e.DAPP] = struct{}{}
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		return mappingKey(pairs[i].IAPP, pairs[i].DAPP) < mappingKey(pairs[j].IAPP, pairs[j].DAPP)
	})

	verifiedIAPP := sortedKeys(iappSet)
	verifiedDAPP := sortedKeys(dappSet)

	modelingOK := expOK["E1"] && expOK["E2"] && expOK["E9"]
	protocolOK := expOK["E3"] && expOK["E4"] && expOK["E5"] && expOK["E6"] && expOK["E7"]
	cryptoOK := encOK && idProtOK // hard lemma slices; E8 reported but soft
	if _, has := expOK["E8"]; has {
		cryptoOK = cryptoOK && expOK["E8"]
	}
	composeOK := mapOK && idStratOK && encStratOK

	stack := IdealStack{
		IDStrategy: IdealLayerSpec{
			Name: "identity-strategy", IdealLabel: "F_id-strategy", RealisedBy: "π_id-strategy / reasoning.f_id",
			PublicInputs: []string{"C.s", "C.m", "C.r", "C.q", "σ"}, AllowedStrategies: verifiedIAPP,
			SupportingExps: []string{"E1", "E2", "E3"}, Verified: idStratOK,
		},
		IDProtect: IdealLayerSpec{
			Name: "identity-protect", IdealLabel: "F_id-protect / F_nym", RealisedBy: "π_id-protect / identity.Protector",
			PublicInputs: []string{"X", "uid", "sid", "scope"}, AllowedStrategies: verifiedIAPP,
			SupportingExps: []string{"E4", "E5"}, Verified: idProtOK,
		},
		EncStrategy: IdealLayerSpec{
			Name: "encryption-strategy", IdealLabel: "F_enc-strategy", RealisedBy: "π_enc-strategy / reasoning.f_enc",
			PublicInputs: []string{"C.s", "C.d", "C.l", "σ"}, AllowedStrategies: verifiedDAPP,
			SupportingExps: []string{"E1", "E2", "E3", "E9", "E10"}, Verified: encStratOK,
		},
		EncProtect: IdealLayerSpec{
			Name: "encryption", IdealLabel: "F_enc / F_SC", RealisedBy: "π_enc / crypto.Executor",
			PublicInputs: []string{"P", "|M|"}, AllowedStrategies: verifiedDAPP,
			SupportingExps: []string{"E6", "E7", "E8"}, Verified: encOK,
		},
		ComposePath: "F_id-strategy ∘ F_id-protect ∘ F_enc-strategy ∘ F_enc",
	}

	pillars := UCOrientedPillars{
		ModelingAssumptions: PillarModeling{
			PillarDelta: PillarDelta{
				UCForm: "mathematical premises", OrientedForm: "engineering constraints + experimental constraints",
			},
			EngineeringConstraints: []string{
				"authenticated strategy input C (MAC / state machine)",
				"public deterministic f_id / f_enc",
				"fail-closed on integrity failure",
				"ModeConfig lifts protection floor (σ)",
				"static corruption (default adversary)",
			},
			ExperimentalConstraints: []string{
				"E1 public-trace determinism",
				"E2 tamper → fail-closed",
				"E9 ModeConfig monotonic lift",
				"E10 strategy output in declared alphabet",
			},
			AdversaryModel: string(StaticCorruption),
			Verified:       modelingOK,
		},
		ProtocolCode: PillarProtocol{
			PillarDelta: PillarDelta{
				UCForm: "ITM programs", OrientedForm: "Go executable slices (π / F / S / ρ_app)",
			},
			Packages: []string{
				"pkg/context", "pkg/reasoning", "pkg/identity", "pkg/crypto", "pkg/uc",
			},
			EntryPoints: []string{
				"Protocol.Invoke", "IdealAdaptive.Invoke", "Simulator.PublicTrace",
				"RhoApp", "FNym", "FSC", "RunVerification",
			},
			Verified: protocolOK,
		},
		CryptoAssumptions: PillarCrypto{
			PillarDelta: PillarDelta{
				UCForm: "reduction targets (IND-CCA, unlinkability, …)", OrientedForm: "lemma premises checked by observable slices",
			},
			Premises: []CryptoPremise{
				{
					Name: "strategy determinism + integrity", UCRole: "part of F_id/enc-strategy UC proof",
					OrientedRole: "lemma premise (L1/L3 slices)", SupportingExps: []string{"E1", "E2", "E3"},
					Checked: expOK["E1"] && expOK["E2"] && expOK["E3"],
				},
				{
					Name: "pseudonym unlinkability / anonymous SimAnon", UCRole: "reduction to PRF / anonymous credential",
					OrientedRole: "lemma premise (L2 slices)", SupportingExps: []string{"E4", "E5"},
					Checked: idProtOK,
				},
				{
					Name: "scheme correctness (single / cascade / STE)", UCRole: "F_enc correctness under IND-CCA schemes",
					OrientedRole: "lemma premise (L4 correctness slices)", SupportingExps: []string{"E6", "E7"},
					Checked: encOK,
				},
				{
					Name: "IND-CCA / ciphertext non-leakage", UCRole: "reduction target for F_enc",
					OrientedRole: "soft lemma premise (naive distinguisher)", SupportingExps: []string{"E8"},
					Checked: expOK["E8"],
				},
			},
			Verified: cryptoOK,
		},
		Composition: PillarCompose{
			PillarDelta: PillarDelta{
				UCForm: "universal composition theorem", OrientedForm: "hybrid argument (H0→H4) + strategy configuration",
			},
			HybridPath:     "H0=EXEC → H1(C) → H2(V) → H3(P) → H4=IDEAL",
			IdealStack:     stack,
			VerifiedIAPP:   verifiedIAPP,
			VerifiedDAPP:   verifiedDAPP,
			SupportingExps: []string{"E3", "E11"},
			Verified:       composeOK,
		},
	}

	return VerificationSnapshot{
		RunID: runID, GeneratedAt: rep.GeneratedAt, AllOK: rep.AllOK,
		Passed: rep.Passed, Total: rep.Total,
		Pillars:      pillars,
		VerifiedIAPP: verifiedIAPP, VerifiedDAPP: verifiedDAPP,
		VerifiedPairs: pairs, ConditionChanges: changes,
		IdealMapSize: spec.Len(), Report: rep,
	}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string {
	return jsonNumber(n)
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func sha256Short(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
