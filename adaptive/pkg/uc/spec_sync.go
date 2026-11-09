package uc

import (
	"fmt"
	"strings"

	"privacy-protection/adaptive/pkg/reasoning"
)

// SpecCatalogVersion mirrors reasoning.ConfigCatalogVersion for IdealSpec digests.
const SpecCatalogVersion = reasoning.ConfigCatalogVersion

// CheckHotPathSpecSync verifies configuration-level alignment between the
// hot-path rule base and UC IdealSpec:
//
//  1. catalog versions match (RuleSet.Version == SpecCatalogVersion / IdealSpec.Version)
//  2. every IdealSpec pair uses IAPP/DAPP tokens that the rule base can emit
//  3. every hot-path IAPP/DAPP token appears in at least one IdealSpec entry
//     (no “orphan” production strategy with no F binding)
//
// Call at process boot / in CI — not on every request.
func CheckHotPathSpecSync(spec *IdealSpec, rs *reasoning.RuleSet) error {
	if spec == nil {
		spec = DefaultIdealSpec()
	}
	if rs == nil {
		rs = reasoning.DefaultRuleSet()
	}
	var problems []string

	ruleVer := rs.Version
	if ruleVer == "" {
		ruleVer = reasoning.ConfigCatalogVersion
	}
	specVer := spec.Version()
	if specVer == "" {
		specVer = SpecCatalogVersion
	}
	if ruleVer != specVer {
		problems = append(problems, fmt.Sprintf("version mismatch: rules=%q spec=%q", ruleVer, specVer))
	}

	vocab := reasoning.HotPathStrategyVocabulary(rs)
	entries := spec.Entries()

	specIAPP := map[string]struct{}{}
	specDAPP := map[string]struct{}{}
	for _, e := range entries {
		specIAPP[strings.ToUpper(e.IAPP)] = struct{}{}
		specDAPP[strings.ToUpper(e.DAPP)] = struct{}{}
		if !vocab.HasIAPP(e.IAPP) {
			problems = append(problems, fmt.Sprintf("IdealSpec pair %s|%s: IAPP %q not in hot-path vocabulary", e.IAPP, e.DAPP, e.IAPP))
		}
		if !vocab.HasDAPP(e.DAPP) {
			problems = append(problems, fmt.Sprintf("IdealSpec pair %s|%s: DAPP %q not in hot-path vocabulary", e.IAPP, e.DAPP, e.DAPP))
		}
	}

	// Orphan check: tokens that appear in declarative rules must be bound in Spec.
	ruleOnly := reasoning.CollectStrategyVocabulary(rs)
	for tok := range ruleOnly.IAPP {
		if _, ok := specIAPP[tok]; !ok {
			problems = append(problems, fmt.Sprintf("hot-path rule IAPP %q has no IdealSpec binding", tok))
		}
	}
	for tok := range ruleOnly.DAPP {
		if _, ok := specDAPP[tok]; !ok {
			problems = append(problems, fmt.Sprintf("hot-path rule DAPP %q has no IdealSpec binding", tok))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("IdealSpec ↔ hot-path config sync failed (%d):\n  - %s",
		len(problems), strings.Join(problems, "\n  - "))
}

// MustHotPathSpecSync panics if CheckHotPathSpecSync fails (boot / tests).
func MustHotPathSpecSync(spec *IdealSpec, rs *reasoning.RuleSet) {
	if err := CheckHotPathSpecSync(spec, rs); err != nil {
		panic(err)
	}
}
