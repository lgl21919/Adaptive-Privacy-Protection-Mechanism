package utils

import (
	"github.com/tap-thesis/privacy-protection-identity/internal/db"
	"fmt"
	"math/rand/v2"
	"strings"
)

// AttackScenarioName identifies a simulated attack / evaluation scenario.
type AttackScenarioName string

const (
	// ScenarioMetadataInstitution: adversary observes leaked institution (or affiliation) metadata alongside pseudonym.
	ScenarioMetadataInstitution AttackScenarioName = "METADATA_INSTITUTION"
	// ScenarioMetadataEmailDomain: adversary observes leaked e-mail domain correlated with pseudonymous activity.
	ScenarioMetadataEmailDomain AttackScenarioName = "METADATA_EMAIL_DOMAIN"
	// ScenarioMetadataCombined: institution + domain tuple leakage (stronger correlation).
	ScenarioMetadataCombined AttackScenarioName = "METADATA_COMBINED_LEAK"
	// ScenarioCrossPhaseLinkage: within REVIEW phase, link reviewer keys across DOUBLE_BLIND vs SINGLE_BLIND (same off_chain_id observable in both modes).
	ScenarioCrossPhaseLinkage AttackScenarioName = "CROSS_PHASE_SIDE_CHANNEL"
	// ScenarioCrossPhaseOnChainIdentity: REVIEW phase, DOUBLE_BLIND vs SINGLE_BLIND reviewer on_chain_identity overlap.
	ScenarioCrossPhaseOnChainIdentity AttackScenarioName = "CROSS_PHASE_ONCHAIN_ID"
	// ScenarioCrossPhasePhasePseudonym: REVIEW phase, DOUBLE_BLIND vs SINGLE_BLIND reviewer phase_pseudonym overlap.
	ScenarioCrossPhasePhasePseudonym AttackScenarioName = "CROSS_PHASE_PHASE_PSEUDONYM"
)

// DeanonymisationAttackResult aggregates outcomes for one scenario on a fixed cohort.
type DeanonymisationAttackResult struct {
	Scenario            AttackScenarioName
	CohortDescription   string
	CohortSize          int
	EvaluatedTargets    int
	// UniqueMatchCount: targets for whom the attack reduces the candidate set to exactly one user in the cohort.
	UniqueMatchCount int
	// AmbiguousCount: candidate set size > 1 (residual anonymity within cohort).
	AmbiguousCount int
	// NoSignalCount: missing or UNKNOWN metadata so no meaningful narrowing.
	NoSignalCount int
	// AvgCandidateSetSize among evaluated targets (excluding no-signal if we skip them - we include as size cohort).
	AvgCandidateSetSize float64
	// DeanonymisationRate: fraction of evaluated targets with candidate set size == 1 (unique re-identification within cohort).
	DeanonymisationRate float64
	// AmbiguousRate: fraction with candidate set size > 1.
	AmbiguousRate float64
}

// SyntheticSimulationParams drives Monte-Carlo style metadata collision simulation.
type SyntheticSimulationParams struct {
	NumReviewers        int
	NumInstitutionSlots int // distinct institution labels drawn uniformly
	NumDomainSlots      int // distinct email domains drawn uniformly
	Iterations          int
	Seed                uint64 // passed to rand.PCG; 0 uses default PCG seed
}

// SyntheticSimulationRow is one row of the synthetic sweep table.
type SyntheticSimulationRow struct {
	NumReviewers        int
	NumInstitutionSlots int
	NumDomainSlots      int
	AvgDeanonymRate     float64 // mean over iterations of fraction uniquely narrowed
	AvgAmbiguousRate    float64
	AvgAvgCandidates    float64
	// Source: SynthRowSourceMonteCarlo (蒙特卡洛) or SynthRowSourceRealDBCombined（真实库一次统计）
	Source string
}

const (
	SynthRowSourceMonteCarlo       = "MONTE_CARLO"
	SynthRowSourceRealDBCombined = "REAL_DB_COMBINED"
)

func institutionKey(u db.UserIdentityInfo) string {
	if u.Attributes != nil {
		for _, k := range []string{"institution", "affiliation", "org", "organization"} {
			if v := strings.TrimSpace(u.Attributes[k]); v != "" {
				return strings.ToLower(v)
			}
		}
	}
	return ""
}

func emailDomainKey(u db.UserIdentityInfo) string {
	s := strings.TrimSpace(u.OffChainID)
	if i := strings.LastIndex(s, "@"); i >= 0 && i < len(s)-1 {
		return strings.ToLower(strings.TrimSpace(s[i+1:]))
	}
	return ""
}

func combinedMetadataKey(u db.UserIdentityInfo) string {
	inst := institutionKey(u)
	dom := emailDomainKey(u)
	if inst == "" && dom == "" {
		return ""
	}
	if inst == "" {
		return "inst:UNKNOWN|dom:" + dom
	}
	if dom == "" {
		return "inst:" + inst + "|dom:UNKNOWN"
	}
	return "inst:" + inst + "|dom:" + dom
}

func countByKey(cohort []db.UserIdentityInfo, keyFn func(db.UserIdentityInfo) string) map[string]int {
	m := make(map[string]int)
	for _, u := range cohort {
		k := keyFn(u)
		if k == "" {
			continue
		}
		m[k]++
	}
	return m
}

// EvaluateDeanonymisationOnCohort runs all metadata scenarios on the given user slice (e.g. double-blind reviewers).
func EvaluateDeanonymisationOnCohort(cohort []db.UserIdentityInfo, cohortDescription string) []DeanonymisationAttackResult {
	if len(cohort) == 0 {
		return nil
	}
	out := make([]DeanonymisationAttackResult, 0, 4)

	out = append(out, evaluateMetadataKeyAttack(
		ScenarioMetadataInstitution,
		cohortDescription,
		cohort,
		institutionKey,
	))

	out = append(out, evaluateMetadataKeyAttack(
		ScenarioMetadataEmailDomain,
		cohortDescription,
		cohort,
		emailDomainKey,
	))

	out = append(out, evaluateMetadataKeyAttack(
		ScenarioMetadataCombined,
		cohortDescription,
		cohort,
		combinedMetadataKey,
	))

	return out
}

func evaluateMetadataKeyAttack(
	scenario AttackScenarioName,
	desc string,
	cohort []db.UserIdentityInfo,
	keyFn func(db.UserIdentityInfo) string,
) DeanonymisationAttackResult {
	counts := countByKey(cohort, keyFn)
	var sumSizes float64
	nEval := 0
	unique := 0
	ambiguous := 0
	noSignal := 0

	for _, u := range cohort {
		k := keyFn(u)
		if k == "" {
			noSignal++
			continue
		}
		c := counts[k]
		if c <= 0 {
			noSignal++
			continue
		}
		nEval++
		sumSizes += float64(c)
		switch {
		case c == 1:
			unique++
		case c > 1:
			ambiguous++
		}
	}

	var avg float64
	var rate float64
	var ambRate float64
	if nEval > 0 {
		avg = sumSizes / float64(nEval)
		rate = float64(unique) / float64(nEval) * 100
		ambRate = float64(ambiguous) / float64(nEval) * 100
	}

	return DeanonymisationAttackResult{
		Scenario:            scenario,
		CohortDescription:   desc,
		CohortSize:          len(cohort),
		EvaluatedTargets:    nEval,
		UniqueMatchCount:    unique,
		AmbiguousCount:      ambiguous,
		NoSignalCount:       noSignal,
		AvgCandidateSetSize: avg,
		DeanonymisationRate: rate,
		AmbiguousRate:       ambRate,
	}
}

// EvaluateCrossPhaseSideChannel counts off_chain_id overlap for REVIEWER between DOUBLE_BLIND and SINGLE_BLIND (phase REVIEW).
func EvaluateCrossPhaseSideChannel(allUsers []db.UserIdentityInfo) DeanonymisationAttackResult {
	return evaluateCrossReviewModesByKey(
		allUsers,
		ScenarioCrossPhaseLinkage,
		"审稿阶段内双盲↔单盲（仅审稿人）：同一链下 ID（off_chain_id）在两种审稿模式下均可观测时可关联（侧信道/配置泄露模型）",
		func(u db.UserIdentityInfo) string { return strings.TrimSpace(u.OffChainID) },
		"DOUBLE_BLIND",
		"SINGLE_BLIND",
		"REVIEWER",
	)
}

// EvaluateCrossPhaseOnChainIdentityLinkage counts on_chain_identity overlap for REVIEWER between DOUBLE_BLIND and SINGLE_BLIND.
func EvaluateCrossPhaseOnChainIdentityLinkage(allUsers []db.UserIdentityInfo) DeanonymisationAttackResult {
	return evaluateCrossReviewModesByKey(
		allUsers,
		ScenarioCrossPhaseOnChainIdentity,
		"审稿阶段内双盲↔单盲（仅审稿人）：同一链上身份（on_chain_identity）在两种审稿模式下均可观测时可关联",
		func(u db.UserIdentityInfo) string { return strings.TrimSpace(u.OnChainIdentity) },
		"DOUBLE_BLIND",
		"SINGLE_BLIND",
		"REVIEWER",
	)
}

// EvaluateCrossPhasePhasePseudonymLinkage counts phase_pseudonym overlap for REVIEWER between DOUBLE_BLIND and SINGLE_BLIND.
func EvaluateCrossPhasePhasePseudonymLinkage(allUsers []db.UserIdentityInfo) DeanonymisationAttackResult {
	return evaluateCrossReviewModesByKey(
		allUsers,
		ScenarioCrossPhasePhasePseudonym,
		"审稿阶段内双盲↔单盲（仅审稿人）：同一阶段伪名（phase_pseudonym）在两种审稿模式下均可观测时可关联（复用/泄露模型）",
		func(u db.UserIdentityInfo) string { return strings.TrimSpace(u.PhasePseudonym) },
		"DOUBLE_BLIND",
		"SINGLE_BLIND",
		"REVIEWER",
	)
}

// evaluateCrossReviewModesByKey compares keys for REVIEW phase only, across two review modes (e.g. DOUBLE_BLIND vs SINGLE_BLIND).
// Denominator = distinct non-empty keys among reviewers in reviewModeDenominator; linked = those keys also seen for reviewers in reviewModeMatch.
func evaluateCrossReviewModesByKey(
	allUsers []db.UserIdentityInfo,
	scenario AttackScenarioName,
	description string,
	keyFn func(db.UserIdentityInfo) string,
	reviewModeDenominator string,
	reviewModeMatch string,
	requireRole string,
) DeanonymisationAttackResult {
	const phaseReview = "REVIEW"
	rmDen := strings.ToUpper(strings.TrimSpace(reviewModeDenominator))
	rmMatch := strings.ToUpper(strings.TrimSpace(reviewModeMatch))
	requireRole = strings.ToUpper(strings.TrimSpace(requireRole))

	setDen := make(map[string]bool)
	setMatch := make(map[string]bool)
	for _, u := range allUsers {
		key := keyFn(u)
		if key == "" {
			continue
		}
		ph := strings.ToUpper(strings.TrimSpace(u.Phase))
		role := strings.ToUpper(strings.TrimSpace(u.Role))
		rm := strings.ToUpper(strings.TrimSpace(u.ReviewMode))
		if requireRole != "" && role != requireRole {
			continue
		}
		if ph != phaseReview {
			continue
		}
		if rm == rmDen {
			setDen[key] = true
		}
		if rm == rmMatch {
			setMatch[key] = true
		}
	}
	linked := 0
	for key := range setDen {
		if setMatch[key] {
			linked++
		}
	}
	total := len(setDen)
	if total == 0 {
		return DeanonymisationAttackResult{
			Scenario:          scenario,
			CohortDescription: description,
			CohortSize:        0,
		}
	}
	rate := float64(linked) / float64(total) * 100
	return DeanonymisationAttackResult{
		Scenario:            scenario,
		CohortDescription:   description,
		CohortSize:          total,
		EvaluatedTargets:    total,
		UniqueMatchCount:    linked,
		AmbiguousCount:      0,
		NoSignalCount:       0,
		AvgCandidateSetSize: 0,
		DeanonymisationRate: rate,
		AmbiguousRate:       0,
	}
}

// FilterReviewersDoubleBlind returns REVIEW + DOUBLE_BLIND + REVIEWER users.
func FilterReviewersDoubleBlind(users []db.UserIdentityInfo) []db.UserIdentityInfo {
	var out []db.UserIdentityInfo
	for _, u := range users {
		phase := strings.ToUpper(strings.TrimSpace(u.Phase))
		mode := strings.ToUpper(strings.TrimSpace(u.ReviewMode))
		role := strings.ToUpper(strings.TrimSpace(u.Role))
		if phase == "REVIEW" && mode == "DOUBLE_BLIND" && role == "REVIEWER" {
			out = append(out, u)
		}
	}
	return out
}

// CombinedMetadataRowFromRealCohort builds one table row aligned with section C:
// same combined-metadata collision metrics as synthetic rows, but from the real DB cohort.
// NumInstitutionSlots / NumDomainSlots are the counts of distinct non-empty institution / domain keys in the cohort.
func CombinedMetadataRowFromRealCohort(cohort []db.UserIdentityInfo) SyntheticSimulationRow {
	instDistinct := make(map[string]struct{})
	domDistinct := make(map[string]struct{})
	for _, u := range cohort {
		if ik := institutionKey(u); ik != "" {
			instDistinct[ik] = struct{}{}
		}
		if dk := emailDomainKey(u); dk != "" {
			domDistinct[dk] = struct{}{}
		}
	}
	res := evaluateMetadataKeyAttack(
		ScenarioMetadataCombined,
		"真实库双盲审稿人队列（组合元数据，一次统计非蒙特卡洛）",
		cohort,
		combinedMetadataKey,
	)
	return SyntheticSimulationRow{
		NumReviewers:        len(cohort),
		NumInstitutionSlots: len(instDistinct),
		NumDomainSlots:      len(domDistinct),
		AvgDeanonymRate:     res.DeanonymisationRate,
		AvgAmbiguousRate:    res.AmbiguousRate,
		AvgAvgCandidates:    res.AvgCandidateSetSize,
		Source:              SynthRowSourceRealDBCombined,
	}
}

// RunDeanonymisationSimulationFromDB loads users and returns real-cohort results plus optional synthetic table.
func RunDeanonymisationSimulationFromDB(includeSynthetic bool) ([]DeanonymisationAttackResult, []SyntheticSimulationRow, error) {
	all, err := db.GetAllUsers()
	if err != nil {
		return nil, nil, fmt.Errorf("读取用户失败: %w", err)
	}

	cohort := FilterReviewersDoubleBlind(all)
	desc := "REVIEW + DOUBLE_BLIND + REVIEWER"
	realResults := EvaluateDeanonymisationOnCohort(cohort, desc)
	realResults = append(realResults, EvaluateCrossPhaseSideChannel(all))
	realResults = append(realResults, EvaluateCrossPhaseOnChainIdentityLinkage(all))
	realResults = append(realResults, EvaluateCrossPhasePhasePseudonymLinkage(all))

	var synth []SyntheticSimulationRow
	if includeSynthetic {
		synth = RunSyntheticMetadataSweep([]SyntheticSimulationParams{
			{NumReviewers: 100, NumInstitutionSlots: 50, NumDomainSlots: 20, Iterations: 200, Seed: 1},
			{NumReviewers: 100, NumInstitutionSlots: 10, NumDomainSlots: 5, Iterations: 200, Seed: 2},
			{NumReviewers: 200, NumInstitutionSlots: 5, NumDomainSlots: 3, Iterations: 150, Seed: 3},
		})
		synth = append(synth, CombinedMetadataRowFromRealCohort(cohort))
	}
	return realResults, synth, nil
}

// RunSyntheticMetadataSweep assigns random institution/domain labels to synthetic reviewers and estimates deanonymisation rate.
func RunSyntheticMetadataSweep(params []SyntheticSimulationParams) []SyntheticSimulationRow {
	rows := make([]SyntheticSimulationRow, 0, len(params))
	for _, p := range params {
		if p.NumReviewers <= 0 || p.Iterations <= 0 {
			continue
		}
		instN := p.NumInstitutionSlots
		if instN <= 0 {
			instN = 1
		}
		domN := p.NumDomainSlots
		if domN <= 0 {
			domN = 1
		}
		var sumDean, sumAmb, sumAvg float64
		r := rand.New(rand.NewPCG(p.Seed, p.Seed^0x9E3779B97F4A7C15))
		for it := 0; it < p.Iterations; it++ {
			labels := make([]string, p.NumReviewers)
			for i := range labels {
				labels[i] = fmt.Sprintf("inst:%d|dom:%d", r.IntN(instN), r.IntN(domN))
			}
			counts := make(map[string]int)
			for _, L := range labels {
				counts[L]++
			}
			var uCount, ambCount int
			var sumC float64
			for _, L := range labels {
				c := counts[L]
				sumC += float64(c)
				if c == 1 {
					uCount++
				} else if c > 1 {
					ambCount++
				}
			}
			sumDean += float64(uCount) / float64(p.NumReviewers) * 100
			sumAmb += float64(ambCount) / float64(p.NumReviewers) * 100
			sumAvg += sumC / float64(p.NumReviewers)
		}
		rows = append(rows, SyntheticSimulationRow{
			NumReviewers:        p.NumReviewers,
			NumInstitutionSlots: instN,
			NumDomainSlots:      domN,
			AvgDeanonymRate:     sumDean / float64(p.Iterations),
			AvgAmbiguousRate:    sumAmb / float64(p.Iterations),
			AvgAvgCandidates:    sumAvg / float64(p.Iterations),
			Source:              SynthRowSourceMonteCarlo,
		})
	}
	return rows
}
