package reasoning

import "strings"

// ConfigCatalogVersion is the shared config generation for hot-path RuleSet
// and UC IdealSpec. Bump together when adding/renaming IAPP/DAPP tokens or pairs.
const ConfigCatalogVersion = "1.0"

// StrategyVocabulary is the set of IAPP/DAPP tokens the hot-path rule base can emit.
type StrategyVocabulary struct {
	Version string
	IAPP    map[string]struct{}
	DAPP    map[string]struct{}
}

// CollectStrategyVocabulary extracts strategy tokens from a declarative rule set.
func CollectStrategyVocabulary(rs *RuleSet) StrategyVocabulary {
	out := StrategyVocabulary{
		Version: ConfigCatalogVersion,
		IAPP:    map[string]struct{}{},
		DAPP:    map[string]struct{}{},
	}
	if rs == nil {
		return out
	}
	if rs.Version != "" {
		out.Version = rs.Version
	}
	for _, r := range rs.Rules {
		if s := strings.TrimSpace(r.Output.IAPPStrategy); s != "" {
			out.IAPP[strings.ToUpper(s)] = struct{}{}
		}
		if s := strings.TrimSpace(r.Output.DAPPStrategy); s != "" {
			out.DAPP[strings.ToUpper(s)] = struct{}{}
		}
	}
	return out
}

// HotPathStrategyVocabulary is rule tokens plus strategies the hot path can
// emit via fail-closed fallback / ModeConfig / weight governance (e.g. ANONYMOUS, MPC).
func HotPathStrategyVocabulary(rs *RuleSet) StrategyVocabulary {
	out := CollectStrategyVocabulary(rs)
	for _, s := range []string{IAPPReal, IAPPPseudonym, IAPPAnonymous} {
		out.IAPP[s] = struct{}{}
	}
	for _, s := range []string{DAPPECDH, DAPPSSS, DAPPPRE, DAPPMPC, DAPPPublic} {
		out.DAPP[s] = struct{}{}
	}
	return out
}

// HasIAPP reports whether the vocabulary contains an identity strategy token.
func (v StrategyVocabulary) HasIAPP(iapp string) bool {
	_, ok := v.IAPP[strings.ToUpper(strings.TrimSpace(iapp))]
	return ok
}

// HasDAPP reports whether the vocabulary contains a data strategy token.
func (v StrategyVocabulary) HasDAPP(dapp string) bool {
	_, ok := v.DAPP[strings.ToUpper(strings.TrimSpace(dapp))]
	return ok
}
