// Package reasoning implements the Logical Reasoning Engine: declarative
// rule-based pattern matching over semantic state vectors.
//
// Policy = f(s, m, r, d, l) → {IAPP_Strategy, DAPP_Strategy}
package reasoning

import (
	"fmt"
	"os"
	"strings"

	"privacy-protection/adaptive/pkg/context"
	"gopkg.in/yaml.v3"
)

// IAPP strategy tokens (identity adaptive privacy policy).
const (
	IAPPReal      = "REAL_IDENTITY"
	IAPPPseudonym = "PSEUDONYMOUS"
	IAPPAnonymous = "ANONYMOUS"
)

// DAPP strategy tokens (data adaptive privacy policy).
const (
	DAPPECDH   = "ECDH_HKDF"
	DAPPSSS    = "SSS"
	DAPPPRE    = "PROXY_REENCRYPTION"
	DAPPMPC    = "MPC"
	DAPPPublic = "PUBLIC"
)

// PolicyDecision output of f(s,m,r,d,l).
type PolicyDecision struct {
	IAPPStrategy   string                `json:"iapp_strategy" yaml:"iapp_strategy"`
	DAPPStrategy   string                `json:"dapp_strategy" yaml:"dapp_strategy"`
	EncAlgorithms  []string              `json:"enc_algorithms,omitempty" yaml:"enc_algorithms,omitempty"`
	ComposeMode    string                `json:"compose_mode,omitempty" yaml:"compose_mode,omitempty"`
	SecurityLevel  int                   `json:"security_level,omitempty" yaml:"security_level,omitempty"`
	SecurityWeight int                   `json:"security_weight,omitempty" yaml:"security_weight,omitempty"`
	RuleID         string                `json:"rule_id" yaml:"rule_id"`
	Description    string                `json:"description,omitempty" yaml:"description,omitempty"`
	StateKey       string                `json:"state_key,omitempty"`
	Vector         context.ContextVector `json:"vector,omitempty"`
	IntegrityOK    bool                  `json:"integrity_ok,omitempty"`
	FallbackUsed   bool                  `json:"fallback_used,omitempty"`
}

// RulePattern declarative match pattern; "*" matches any value.
type RulePattern struct {
	S string `yaml:"s"`
	M string `yaml:"m"`
	R string `yaml:"r"`
	Q string `yaml:"q"`
	D string `yaml:"d"`
	L string `yaml:"l"`
}

// RuleOutput strategy outputs for a matched rule.
type RuleOutput struct {
	IAPPStrategy   string   `yaml:"iapp_strategy"`
	DAPPStrategy   string   `yaml:"dapp_strategy"`
	EncAlgorithms  []string `yaml:"enc_algorithms,omitempty"`
	ComposeMode    string   `yaml:"compose_mode,omitempty"`
	SecurityLevel  int      `yaml:"security_level,omitempty"`
}

// Rule single declarative rule entry.
type Rule struct {
	ID          string      `yaml:"id"`
	Priority    int         `yaml:"priority"`
	Match       RulePattern `yaml:"match"`
	Output      RuleOutput  `yaml:"output"`
	Description string      `yaml:"description,omitempty"`
}

// RuleSet declarative rule base loaded from configuration.
type RuleSet struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// LogicalReasoningEngine evaluates Policy = f(s,m,r,d,l) via pattern matching
// scored by UC/governed security weights (not static priority alone).
type LogicalReasoningEngine struct {
	rules   []Rule
	weights *PolicyWeightStore
}

// NewLogicalReasoningEngine creates an engine from an in-memory rule set.
func NewLogicalReasoningEngine(rs *RuleSet) (*LogicalReasoningEngine, error) {
	if rs == nil || len(rs.Rules) == 0 {
		return nil, fmt.Errorf("rule set is empty")
	}
	rules := make([]Rule, len(rs.Rules))
	copy(rules, rs.Rules)
	sortRulesByPriority(rules)
	return &LogicalReasoningEngine{rules: rules}, nil
}

// SetWeights attaches (or replaces) the UC/governor-driven weight store.
func (e *LogicalReasoningEngine) SetWeights(w *PolicyWeightStore) {
	if e == nil {
		return
	}
	e.weights = w
}

// Weights returns the active security-weight store (may be nil).
func (e *LogicalReasoningEngine) Weights() *PolicyWeightStore {
	if e == nil {
		return nil
	}
	return e.weights
}

// LoadFromFile loads a declarative rule base from YAML configuration.
func LoadFromFile(path string) (*LogicalReasoningEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule config: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses rule configuration from YAML bytes.
func LoadFromBytes(data []byte) (*LogicalReasoningEngine, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse rule config: %w", err)
	}
	return NewLogicalReasoningEngine(&rs)
}

// MatchingRules returns every rule that matches the semantic state (priority order).
func (e *LogicalReasoningEngine) MatchingRules(state *context.SemanticState) []Rule {
	if state == nil || e == nil {
		return nil
	}
	var out []Rule
	for _, rule := range e.rules {
		if matchPattern(rule.Match, state.Vector) {
			out = append(out, rule)
		}
	}
	return out
}

// Evaluate applies f(s,m,r,d,l) to derive IAPP and DAPP strategies.
// Among matching rules, selection maximizes UC/governor security weight then
// static priority — not first-match on static config alone.
func (e *LogicalReasoningEngine) Evaluate(state *context.SemanticState) (*PolicyDecision, error) {
	if state == nil {
		return nil, fmt.Errorf("semantic state is nil")
	}
	matches := e.MatchingRules(state)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no matching rule for state %v", state.Vector)
	}
	best := matches[0]
	bestW := e.ruleSecurityWeight(best)
	bestScore := scoreWithWeights(e.weights, bestW, best.Priority)
	for _, rule := range matches[1:] {
		w := e.ruleSecurityWeight(rule)
		s := scoreWithWeights(e.weights, w, rule.Priority)
		if s > bestScore {
			best, bestW, bestScore = rule, w, s
		}
	}
	return decisionFromRule(best, state, bestW), nil
}

func (e *LogicalReasoningEngine) ruleSecurityWeight(rule Rule) int {
	w := e.weights
	if w == nil {
		return WeightBaseline
	}
	iapp, dapp := rule.Output.IAPPStrategy, rule.Output.DAPPStrategy
	switch {
	case iapp != "" && dapp != "":
		return w.PairWeight(iapp, dapp)
	case iapp != "":
		return w.IAPPWeight(iapp)
	case dapp != "":
		return w.DAPPWeight(dapp)
	default:
		return WeightBaseline
	}
}

func scoreWithWeights(store *PolicyWeightStore, secWeight, priority int) int {
	if store == nil {
		// No governed weights: preserve legacy priority-first behaviour.
		return priority
	}
	return store.Score(secWeight, priority)
}

func decisionFromRule(rule Rule, state *context.SemanticState, secWeight int) *PolicyDecision {
	level := rule.Output.SecurityLevel
	if level <= 0 && rule.Output.DAPPStrategy != "" && rule.Output.DAPPStrategy != DAPPPublic {
		level = 1
	}
	algs := append([]string(nil), rule.Output.EncAlgorithms...)
	if len(algs) == 0 && rule.Output.DAPPStrategy != "" {
		algs = []string{rule.Output.DAPPStrategy}
	}
	compose := rule.Output.ComposeMode
	if compose == "" {
		if len(algs) > 1 {
			compose = "CASCADE"
		} else {
			compose = "SINGLE"
		}
	}
	return &PolicyDecision{
		IAPPStrategy:   rule.Output.IAPPStrategy,
		DAPPStrategy:   rule.Output.DAPPStrategy,
		EncAlgorithms:  algs,
		ComposeMode:    compose,
		SecurityLevel:  level,
		SecurityWeight: secWeight,
		RuleID:         rule.ID,
		Description:    rule.Description,
		StateKey:       state.StateKey,
		Vector:         state.Vector,
		IntegrityOK:    true,
	}
}

// Rules returns a copy of loaded rules (for inspection / audit).
func (e *LogicalReasoningEngine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

func matchPattern(p RulePattern, vec context.ContextVector) bool {
	return fieldMatch(p.S, vec.S) &&
		fieldMatch(p.M, vec.M) &&
		fieldMatch(p.R, vec.R) &&
		fieldMatch(p.Q, vec.Q) &&
		fieldMatch(p.D, vec.D) &&
		fieldMatch(p.L, vec.L)
}

func fieldMatch(pattern, value string) bool {
	pattern = strings.TrimSpace(strings.ToUpper(pattern))
	value = strings.TrimSpace(strings.ToUpper(value))
	if pattern == "" || pattern == context.DimAny || pattern == "*" {
		return true
	}
	return pattern == value
}

func sortRulesByPriority(rules []Rule) {
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].Priority > rules[i].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}
}

// DefaultRuleSet returns the built-in rule base mirroring legacy hard-coded policies.
func DefaultRuleSet() *RuleSet {
	return &RuleSet{
		Version: ConfigCatalogVersion,
		Rules:   defaultRules(),
	}
}

func defaultRules() []Rule {
	type idRule struct {
		id, s, m, r, iapp, desc string
	}
	identityRules := []idRule{
		{"sub_author_real", "SUBMISSION", "AUTHOR", "*", IAPPReal, "作者在投稿时必须使用真实身份"},
		{"sub_editor_real", "SUBMISSION", "EDITOR", "*", IAPPReal, "编辑在处理投稿时使用真实身份"},
		{"rev_db_author_pseudo", "REVIEW", "AUTHOR", "DOUBLE_BLIND", IAPPPseudonym, "作者在双盲审稿阶段使用伪名"},
		{"rev_db_reviewer_pseudo", "REVIEW", "REVIEWER", "DOUBLE_BLIND", IAPPPseudonym, "审稿人在双盲评审中使用伪名"},
		{"rev_db_editor_real", "REVIEW", "EDITOR", "DOUBLE_BLIND", IAPPReal, "编辑在双盲审稿管理中使用真实身份"},
		{"rev_sb_author_real", "REVIEW", "AUTHOR", "SINGLE_BLIND", IAPPReal, "作者在单盲审稿阶段使用真实身份"},
		{"rev_sb_reviewer_pseudo", "REVIEW", "REVIEWER", "SINGLE_BLIND", IAPPPseudonym, "审稿人在单盲评审中使用伪名"},
		{"rev_sb_editor_real", "REVIEW", "EDITOR", "SINGLE_BLIND", IAPPReal, "编辑在单盲审稿管理中使用真实身份"},
		{"rev_open_author_real", "REVIEW", "AUTHOR", "OPEN", IAPPReal, "作者在开放审稿阶段使用真实身份"},
		{"rev_open_reviewer_real", "REVIEW", "REVIEWER", "OPEN", IAPPReal, "审稿人在开放评审中使用真实身份"},
		{"rev_open_editor_real", "REVIEW", "EDITOR", "OPEN", IAPPReal, "编辑在开放审稿管理中使用真实身份"},
		{"pub_author_real", "PUBLICATION", "AUTHOR", "*", IAPPReal, "出版时公开作者真实身份"},
		{"pub_reviewer_real", "PUBLICATION", "REVIEWER", "*", IAPPReal, "可选择公开致谢审稿人"},
		{"pub_editor_real", "PUBLICATION", "EDITOR", "*", IAPPReal, "出版时公开编辑真实身份"},
	}

	type dataRule struct {
		id, s, d, l, dapp, desc string
		level                   int
	}
	dataRules := []dataRule{
		{"sub_manuscript_l1", "SUBMISSION", "MANUSCRIPT", "1", DAPPECDH, "投稿稿件基础加密", 1},
		{"sub_manuscript_l2", "SUBMISSION", "MANUSCRIPT", "2", DAPPSSS, "投稿稿件高级加密", 2},
		{"sub_message_l1", "SUBMISSION", "MESSAGE", "1", DAPPECDH, "投稿消息基础加密", 1},
		{"sub_message_l2", "SUBMISSION", "MESSAGE", "2", DAPPPRE, "投稿消息代理重加密", 2},
		{"sub_enckey_l1", "SUBMISSION", "ENCRYPTION_KEY", "1", DAPPPRE, "投稿密钥PRE保护", 1},
		{"rev_manuscript_l1", "REVIEW", "MANUSCRIPT", "1", DAPPECDH, "审稿稿件基础加密", 1},
		{"rev_manuscript_l2", "REVIEW", "MANUSCRIPT", "2", DAPPSSS, "审稿稿件高级加密", 2},
		{"rev_supp_l1", "REVIEW", "SUPPLEMENTARY_DATA", "1", DAPPECDH, "补充数据基础加密", 1},
		{"rev_supp_l2", "REVIEW", "SUPPLEMENTARY_DATA", "2", DAPPPRE, "补充数据PRE加密", 2},
		{"rev_message_l1", "REVIEW", "MESSAGE", "1", DAPPECDH, "审稿消息基础加密", 1},
		{"rev_message_l2", "REVIEW", "MESSAGE", "2", DAPPPRE, "审稿消息PRE加密", 2},
		{"rev_final_l1", "REVIEW", "FINAL_RECOMMENDATION", "1", DAPPECDH, "最终建议基础加密", 1},
		{"rev_final_l2", "REVIEW", "FINAL_RECOMMENDATION", "2", DAPPPRE, "最终建议PRE加密", 2},
		{"rev_final_l3", "REVIEW", "FINAL_RECOMMENDATION", "3", DAPPMPC, "最终建议MPC/多算法组合强加密", 3},
		{"rev_enckey_l1", "REVIEW", "ENCRYPTION_KEY", "1", DAPPPRE, "审稿密钥PRE保护", 1},
		{"pub_manuscript_l1", "PUBLICATION", "MANUSCRIPT", "1", DAPPECDH, "出版稿件基础加密", 1},
		{"pub_manuscript_l2", "PUBLICATION", "MANUSCRIPT", "2", DAPPSSS, "出版稿件高级加密", 2},
		{"pub_message_l0", "PUBLICATION", "MESSAGE", "0", DAPPPublic, "出版阶段公开消息", 0},
		{"pub_enckey_l1", "PUBLICATION", "ENCRYPTION_KEY", "1", DAPPPRE, "出版密钥PRE保护", 1},
	}

	var rules []Rule
	for _, ir := range identityRules {
		rules = append(rules, Rule{
			ID:          ir.id,
			Priority:    100,
			Match:       RulePattern{S: ir.s, M: ir.m, R: ir.r, D: "*", L: "*"},
			Output:      RuleOutput{IAPPStrategy: ir.iapp},
			Description: ir.desc,
		})
	}
	for _, dr := range dataRules {
		algs, compose := defaultEncScheme(dr.dapp, dr.level)
		rules = append(rules, Rule{
			ID:       dr.id,
			Priority: dr.level * 10,
			Match:    RulePattern{S: dr.s, M: "*", R: "*", D: dr.d, L: dr.l},
			Output: RuleOutput{
				DAPPStrategy:  dr.dapp,
				EncAlgorithms: algs,
				ComposeMode:   compose,
				SecurityLevel: dr.level,
			},
			Description: dr.desc,
		})
	}
	return rules
}

// AdaptiveCoordinator wires Context-Awareness + Logical Reasoning.
type AdaptiveCoordinator struct {
	context *context.ContextAwarenessModule
	engine  *LogicalReasoningEngine
}

func NewAdaptiveCoordinator(engine *LogicalReasoningEngine) *AdaptiveCoordinator {
	return &AdaptiveCoordinator{
		context: context.NewContextAwarenessModule(),
		engine:  engine,
	}
}

// AttachWeights binds a governor/monitor-owned weight store into the hot-path engine.
func (ac *AdaptiveCoordinator) AttachWeights(w *PolicyWeightStore) {
	if ac == nil || ac.engine == nil {
		return
	}
	ac.engine.SetWeights(w)
}

// PolicyWeights returns the engine's security-weight store.
func (ac *AdaptiveCoordinator) PolicyWeights() *PolicyWeightStore {
	if ac == nil || ac.engine == nil {
		return nil
	}
	return ac.engine.Weights()
}

// NewDefaultCoordinator uses built-in default rules (no external config file).
func NewDefaultCoordinator() (*AdaptiveCoordinator, error) {
	engine, err := NewLogicalReasoningEngine(DefaultRuleSet())
	if err != nil {
		return nil, err
	}
	return NewAdaptiveCoordinator(engine), nil
}

// NewCoordinatorFromFile loads rules from a declarative YAML configuration file.
func NewCoordinatorFromFile(configPath string) (*AdaptiveCoordinator, error) {
	engine, err := LoadFromFile(configPath)
	if err != nil {
		return nil, err
	}
	return NewAdaptiveCoordinator(engine), nil
}

func defaultEncScheme(dapp string, level int) ([]string, string) {
	return DefaultEncSchemeFor(dapp, level)
}

// DefaultEncSchemeFor maps a DAPP token (+ level) to algorithm list / compose mode.
// Used by hot-path rules and by UC when pinning online strategies into π.
func DefaultEncSchemeFor(dapp string, level int) ([]string, string) {
	switch dapp {
	case DAPPPublic:
		return []string{DAPPPublic}, "NONE"
	case DAPPMPC:
		return []string{DAPPECDH, DAPPSSS, DAPPPRE}, "CASCADE"
	case DAPPPRE:
		if level >= 2 {
			return []string{DAPPECDH, DAPPPRE}, "CASCADE"
		}
		return []string{DAPPPRE}, "SINGLE"
	case DAPPSSS:
		return []string{DAPPECDH, DAPPSSS}, "CASCADE"
	default:
		if dapp == "" {
			return nil, "SINGLE"
		}
		return []string{dapp}, "SINGLE"
	}
}

// SafestFallback is the fail-closed *policy decision* when strategy inputs
// fail integrity checks. The hot path must abort Protect/Encrypt; it must not
// enact this policy as a successful business transaction.
func SafestFallback(in context.ContextInput) *PolicyDecision {
	state := context.NewContextAwarenessModule().Capture(in)
	return &PolicyDecision{
		IAPPStrategy:   IAPPAnonymous,
		DAPPStrategy:   DAPPMPC,
		EncAlgorithms:  []string{DAPPECDH, DAPPSSS, DAPPPRE},
		ComposeMode:    "CASCADE",
		SecurityLevel:  3,
		SecurityWeight: WeightVerified,
		RuleID:         "fallback_safest",
		Description:    "strategy-input integrity failure: fail closed to anonymous + strongest composition",
		StateKey:       state.StateKey,
		Vector:         state.Vector,
		IntegrityOK:    false,
		FallbackUsed:   true,
	}
}

// ApplyModeConfig raises the protection floor according to public journal config.
func ApplyModeConfig(dec *PolicyDecision, cfg context.ModeConfig) {
	if dec == nil {
		return
	}
	if cfg.ForceAnonymous && dec.IAPPStrategy != IAPPAnonymous {
		dec.IAPPStrategy = IAPPAnonymous
		dec.Description += "; cfg: force anonymous"
	}
	if cfg.MinSecurityLevel > dec.SecurityLevel && dec.DAPPStrategy != DAPPPublic {
		dec.SecurityLevel = cfg.MinSecurityLevel
		if cfg.MinSecurityLevel >= 3 {
			dec.DAPPStrategy = DAPPMPC
			dec.EncAlgorithms = []string{DAPPECDH, DAPPSSS, DAPPPRE}
			dec.ComposeMode = "CASCADE"
		}
	}
	if cfg.RequireSTE && dec.DAPPStrategy != DAPPPublic {
		dec.ComposeMode = "SIGN_THEN_ENCRYPT"
		if len(dec.EncAlgorithms) < 2 {
			dec.EncAlgorithms = []string{DAPPECDH, "HMAC-SHA256"}
		}
	}
	if cfg.AllowComposition && len(dec.EncAlgorithms) == 1 && dec.DAPPStrategy != DAPPPublic && dec.SecurityLevel >= 2 {
		dec.EncAlgorithms = append(dec.EncAlgorithms, DAPPECDH)
		dec.ComposeMode = "CASCADE"
	}
}

// EvaluatePolicy full pipeline: capture context → weight-aware reasoning → {IAPP, DAPP}.
// Joint selection maximizes combination security weight across matching identity × data
// rule candidates; static YAML is only the candidate generator, not the sole decider.
func (ac *AdaptiveCoordinator) EvaluatePolicy(in context.ContextInput) (*PolicyDecision, error) {
	if err := context.ValidateStrategyInput(in); err != nil {
		fb := SafestFallback(in)
		ApplyModeConfig(fb, in.ModeConfig)
		return fb, nil
	}
	idIn := in
	idIn.DataType = "*"
	idIn.SecurityLevel = -1
	idState := ac.context.Capture(idIn)
	dataIn := in
	dataIn.Role = "*"
	dataIn.ReviewMode = "*"
	dataState := ac.context.Capture(dataIn)

	idRules := ac.engine.MatchingRules(idState)
	dataRules := ac.engine.MatchingRules(dataState)
	if len(idRules) == 0 || len(dataRules) == 0 {
		// Fall back to independent Evaluate paths (preserves prior errors).
		iapp, err := ac.EvaluateIdentityPolicy(in)
		if err != nil {
			return nil, err
		}
		dapp, err := ac.EvaluateDataPolicy(in)
		if err != nil {
			return nil, err
		}
		return ac.mergeDecisions(in, iapp, dapp)
	}

	wstore := ac.engine.Weights()
	bestI, bestD := idRules[0], dataRules[0]
	bestPairW := WeightBaseline
	if wstore != nil {
		bestPairW = wstore.PairWeight(bestI.Output.IAPPStrategy, bestD.Output.DAPPStrategy)
	}
	bestScore := scoreWithWeights(wstore, bestPairW, bestI.Priority+bestD.Priority)
	for _, ir := range idRules {
		for _, dr := range dataRules {
			pw := WeightBaseline
			if wstore != nil {
				pw = wstore.PairWeight(ir.Output.IAPPStrategy, dr.Output.DAPPStrategy)
			}
			s := scoreWithWeights(wstore, pw, ir.Priority+dr.Priority)
			if s > bestScore {
				bestI, bestD, bestPairW, bestScore = ir, dr, pw, s
			}
		}
	}

	state := ac.context.Capture(in)
	iappDec := decisionFromRule(bestI, idState, bestPairW)
	dappDec := decisionFromRule(bestD, dataState, bestPairW)
	algs := append([]string(nil), dappDec.EncAlgorithms...)
	compose := dappDec.ComposeMode
	dec := &PolicyDecision{
		IAPPStrategy:   iappDec.IAPPStrategy,
		DAPPStrategy:   dappDec.DAPPStrategy,
		EncAlgorithms:  algs,
		ComposeMode:    compose,
		SecurityLevel:  dappDec.SecurityLevel,
		SecurityWeight: bestPairW,
		RuleID:         iappDec.RuleID + "+" + dappDec.RuleID,
		Description:    iappDec.Description + "; " + dappDec.Description,
		StateKey:       state.StateKey,
		Vector:         state.Vector,
		IntegrityOK:    true,
	}
	ApplyModeConfig(dec, in.ModeConfig)
	ApplyWeightGovernance(dec, wstore, in.ModeConfig)
	return dec, nil
}

func (ac *AdaptiveCoordinator) mergeDecisions(in context.ContextInput, iapp, dapp *PolicyDecision) (*PolicyDecision, error) {
	state := ac.context.Capture(in)
	algs := append([]string(nil), dapp.EncAlgorithms...)
	compose := dapp.ComposeMode
	pw := WeightBaseline
	wstore := ac.engine.Weights()
	if wstore != nil {
		pw = wstore.PairWeight(iapp.IAPPStrategy, dapp.DAPPStrategy)
	}
	dec := &PolicyDecision{
		IAPPStrategy:   iapp.IAPPStrategy,
		DAPPStrategy:   dapp.DAPPStrategy,
		EncAlgorithms:  algs,
		ComposeMode:    compose,
		SecurityLevel:  dapp.SecurityLevel,
		SecurityWeight: pw,
		RuleID:         iapp.RuleID + "+" + dapp.RuleID,
		Description:    iapp.Description + "; " + dapp.Description,
		StateKey:       state.StateKey,
		Vector:         state.Vector,
		IntegrityOK:    true,
	}
	ApplyModeConfig(dec, in.ModeConfig)
	ApplyWeightGovernance(dec, wstore, in.ModeConfig)
	return dec, nil
}

// ApplyWeightGovernance lets governor/UC weights override a low-weight static
// pick when a safer verified (or floor-elevated) combination outranks it.
func ApplyWeightGovernance(dec *PolicyDecision, w *PolicyWeightStore, cfg context.ModeConfig) {
	if dec == nil || w == nil || dec.FallbackUsed {
		return
	}
	pw := w.PairWeight(dec.IAPPStrategy, dec.DAPPStrategy)
	dec.SecurityWeight = pw
	if pw >= WeightVerified {
		return
	}
	altI, altD := IAPPAnonymous, DAPPMPC
	altW := w.PairWeight(altI, altD)
	promote := altW > pw && (altW >= WeightVerified || cfg.ForceAnonymous || cfg.MinSecurityLevel >= 3)
	if !promote {
		return
	}
	dec.IAPPStrategy = altI
	dec.DAPPStrategy = altD
	dec.EncAlgorithms = []string{DAPPECDH, DAPPSSS, DAPPPRE}
	dec.ComposeMode = "CASCADE"
	if dec.SecurityLevel < 3 {
		dec.SecurityLevel = 3
	}
	dec.SecurityWeight = altW
	dec.Description += "; weight-governance: prefer higher-weight combination"
}

// EvaluateIdentityPolicy derives IAPP strategy for identity protection.
func (ac *AdaptiveCoordinator) Engine() *LogicalReasoningEngine { return ac.engine }

func (ac *AdaptiveCoordinator) EvaluateIdentityPolicy(in context.ContextInput) (*PolicyDecision, error) {
	idIn := in
	idIn.DataType = "*"
	idIn.SecurityLevel = -1
	state := ac.context.Capture(idIn)
	dec, err := ac.engine.Evaluate(state)
	if err != nil {
		return nil, err
	}
	ApplyWeightGovernanceIdentity(dec, ac.engine.Weights(), in.ModeConfig)
	return dec, nil
}

// EvaluateDataPolicy derives DAPP strategy for data protection.
func (ac *AdaptiveCoordinator) EvaluateDataPolicy(in context.ContextInput) (*PolicyDecision, error) {
	dataIn := in
	dataIn.Role = "*"
	dataIn.ReviewMode = "*"
	state := ac.context.Capture(dataIn)
	dec, err := ac.engine.Evaluate(state)
	if err != nil {
		return nil, err
	}
	ApplyWeightGovernanceData(dec, ac.engine.Weights(), in.ModeConfig)
	return dec, nil
}

// ApplyWeightGovernanceIdentity raises IAPP toward anonymous when static pick
// is low-weight and a safer identity strategy is preferred by UC/governor.
func ApplyWeightGovernanceIdentity(dec *PolicyDecision, w *PolicyWeightStore, cfg context.ModeConfig) {
	if dec == nil || w == nil || dec.FallbackUsed || dec.IAPPStrategy == "" {
		return
	}
	cur := w.IAPPWeight(dec.IAPPStrategy)
	dec.SecurityWeight = cur
	if cur >= WeightVerified {
		return
	}
	alt := IAPPAnonymous
	altW := w.IAPPWeight(alt)
	if altW > cur && (altW >= WeightVerified || cfg.ForceAnonymous) {
		dec.IAPPStrategy = alt
		dec.SecurityWeight = altW
		dec.Description += "; weight-governance: prefer higher-weight IAPP"
	}
}

// ApplyWeightGovernanceData raises DAPP toward stronger schemes when static
// pick is low-weight and UC/governor prefer a higher-weight data strategy.
func ApplyWeightGovernanceData(dec *PolicyDecision, w *PolicyWeightStore, cfg context.ModeConfig) {
	if dec == nil || w == nil || dec.FallbackUsed || dec.DAPPStrategy == "" || dec.DAPPStrategy == DAPPPublic {
		return
	}
	cur := w.DAPPWeight(dec.DAPPStrategy)
	dec.SecurityWeight = cur
	if cur >= WeightVerified {
		return
	}
	alt := DAPPMPC
	altW := w.DAPPWeight(alt)
	if altW > cur && (altW >= WeightVerified || cfg.MinSecurityLevel >= 3) {
		dec.DAPPStrategy = alt
		dec.EncAlgorithms = []string{DAPPECDH, DAPPSSS, DAPPPRE}
		dec.ComposeMode = "CASCADE"
		if dec.SecurityLevel < 3 {
			dec.SecurityLevel = 3
		}
		dec.SecurityWeight = altW
		dec.Description += "; weight-governance: prefer higher-weight DAPP"
	}
}

