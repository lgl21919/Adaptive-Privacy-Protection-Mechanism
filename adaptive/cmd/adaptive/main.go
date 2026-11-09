package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/reasoning"
	"gopkg.in/yaml.v3"
)

const (
	exp1 = "实验一：审稿模式切换(IAPP)"
	exp2 = "实验二：安全级别切换(DAPP)"
	exp3 = "实验三：规则热更新(IAPP+DAPP)"
	expCoverIAPP = "覆盖：IAPP全规则"
	expCoverDAPP = "覆盖：DAPP全规则"
)

type scenario struct {
	ID           string
	Experiment   string
	Phase        string
	Role         string
	ReviewMode   string
	DataType     string
	SecurityLevel int
	ExpectIAPP   string
	ExpectDAPP   string
	ExpectRule   string
	Notes        string
}

type resultRow struct {
	Experiment      string  `json:"experiment"`
	ScenarioID      string  `json:"scenario_id"`
	S               string  `json:"s"`
	M               string  `json:"m"`
	R               string  `json:"r"`
	D               string  `json:"d"`
	L               string  `json:"l"`
	StateKey        string  `json:"state_key"`
	ExpectIAPP      string  `json:"expect_iapp"`
	ExpectDAPP      string  `json:"expect_dapp"`
	ActualIAPP      string  `json:"actual_iapp"`
	ActualDAPP      string  `json:"actual_dapp"`
	BeforeIAPP      string  `json:"before_iapp,omitempty"`
	BeforeDAPP      string  `json:"before_dapp,omitempty"`
	AfterIAPP       string  `json:"after_iapp,omitempty"`
	AfterDAPP       string  `json:"after_dapp,omitempty"`
	RuleID          string  `json:"rule_id"`
	ExpectRule      string  `json:"expect_rule"`
	Passed          bool    `json:"passed"`
	HotUpdateMs     float64 `json:"hot_update_ms,omitempty"`
	ChaincodeRedeploy string `json:"chaincode_redeploy"`
	Notes           string  `json:"notes,omitempty"`
}

type summaryMetrics struct {
	TotalScenarios       int     `json:"total_scenarios"`
	PassedScenarios      int     `json:"passed_scenarios"`
	CoverageTotal        int     `json:"coverage_total"`
	CoveragePassed       int     `json:"coverage_passed"`
	CoverageRate         float64 `json:"coverage_rate"`
	ConsistencyRate      float64 `json:"consistency_rate"`
	ContextDistinguish   float64 `json:"context_distinguish_rate"`
	Exp1Consistency      float64 `json:"exp1_consistency_rate"`
	Exp2Consistency      float64 `json:"exp2_consistency_rate"`
	Exp3IAPPChanged      bool    `json:"exp3_iapp_changed"`
	Exp3DAPPChanged      bool    `json:"exp3_dapp_changed"`
	HotUpdateLoadMs      float64 `json:"hot_update_load_ms"`
	ChaincodeRedeploy    string  `json:"chaincode_redeploy"`
	GeneratedAt          string  `json:"generated_at"`
}

func main() {
	outDir := flag.String("out", "./benchmark_output", "output directory for CSV/JSON/LaTeX")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	coord, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		fmt.Fprintf(os.Stderr, "coordinator: %v\n", err)
		os.Exit(1)
	}

	scenarios := buildAllScenarios()
	rows := make([]resultRow, 0, len(scenarios))

	// Baseline runs (Exp1, Exp2, coverage)
	for _, sc := range scenarios {
		if sc.Experiment == exp3 {
			continue
		}
		row := runScenario(coord, sc)
		rows = append(rows, row)
	}

	// Exp3: hot-update with modified rules
	exp3Rows, hotMs, err := runHotUpdateExperiment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hot update: %v\n", err)
		os.Exit(1)
	}
	rows = append(rows, exp3Rows...)

	summary := computeSummary(rows, hotMs)

	base := filepath.Join(*outDir, "adaptive_benchmark_results")
	if err := writeJSON(base+".json", map[string]interface{}{
		"summary": summary,
		"rows":    rows,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "json: %v\n", err)
		os.Exit(1)
	}
	if err := writeSummaryJSON(filepath.Join(*outDir, "adaptive_benchmark_summary.json"), summary); err != nil {
		fmt.Fprintf(os.Stderr, "summary json: %v\n", err)
		os.Exit(1)
	}
	if err := writeCSV(base+".csv", rows, summary); err != nil {
		fmt.Fprintf(os.Stderr, "csv: %v\n", err)
		os.Exit(1)
	}
	if err := writeLaTeX(base+".tex", rows, summary); err != nil {
		fmt.Fprintf(os.Stderr, "latex: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Adaptive benchmark complete.\n")
	fmt.Printf("  Scenarios: %d passed / %d (%.1f%%)\n", summary.PassedScenarios, summary.TotalScenarios, summary.ConsistencyRate*100)
	fmt.Printf("  Coverage: %.1f%% | Context distinguish: %.1f%%\n", summary.CoverageRate*100, summary.ContextDistinguish*100)
	fmt.Printf("  Exp3 hot-update load: %.3f ms | chaincode redeploy: %s\n", summary.HotUpdateLoadMs, summary.ChaincodeRedeploy)
	fmt.Printf("  Output: %s\n", *outDir)
}

func buildAllScenarios() []scenario {
	var all []scenario

	// Experiment 1: review mode switching
	for i, rm := range []struct {
		mode, expect, rule string
	}{
		{"DOUBLE_BLIND", reasoning.IAPPPseudonym, "rev_db_author_pseudo"},
		{"SINGLE_BLIND", reasoning.IAPPReal, "rev_sb_author_real"},
		{"OPEN", reasoning.IAPPReal, "rev_open_author_real"},
	} {
		all = append(all, scenario{
			ID: fmt.Sprintf("E1-%02d", i+1), Experiment: exp1,
			Phase: "REVIEW", Role: "AUTHOR", ReviewMode: rm.mode,
			ExpectIAPP: rm.expect, ExpectRule: rm.rule,
			Notes: "控制 s=REVIEW,m=AUTHOR; 自变量 r",
		})
	}

	// Experiment 2: security level switching
	for i, lv := range []struct {
		level int
		expect, rule string
	}{
		{1, reasoning.DAPPECDH, "rev_final_l1"},
		{2, reasoning.DAPPPRE, "rev_final_l2"},
		{3, reasoning.DAPPMPC, "rev_final_l3"},
	} {
		all = append(all, scenario{
			ID: fmt.Sprintf("E2-%02d", i+1), Experiment: exp2,
			Phase: "REVIEW", DataType: "FINAL_RECOMMENDATION", SecurityLevel: lv.level,
			ExpectDAPP: lv.expect, ExpectRule: lv.rule,
			Notes: "控制 s=REVIEW,d=FINAL_RECOMMENDATION; 自变量 l",
		})
	}

	// Experiment 3 placeholders (filled in runHotUpdateExperiment)
	all = append(all,
		scenario{ID: "E3-01", Experiment: exp3, Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
			ExpectIAPP: reasoning.IAPPAnonymous, Notes: "IAPP热更新: 双盲作者 PSEUDONYMOUS→ANONYMOUS"},
		scenario{ID: "E3-02", Experiment: exp3, Phase: "REVIEW", DataType: "SUPPLEMENTARY_DATA", SecurityLevel: 2,
			ExpectDAPP: reasoning.DAPPMPC, ExpectRule: "rev_supp_l2_mpc", Notes: "DAPP热更新: SUPP_DATA@L2 PRE→MPC"},
	)

	// Full IAPP coverage (14 rules)
	iappCases := []scenario{
		{"I-01", expCoverIAPP, "SUBMISSION", "AUTHOR", "", "", -1, reasoning.IAPPReal, "", "sub_author_real", ""},
		{"I-02", expCoverIAPP, "SUBMISSION", "EDITOR", "", "", -1, reasoning.IAPPReal, "", "sub_editor_real", ""},
		{"I-03", expCoverIAPP, "REVIEW", "AUTHOR", "DOUBLE_BLIND", "", -1, reasoning.IAPPPseudonym, "", "rev_db_author_pseudo", ""},
		{"I-04", expCoverIAPP, "REVIEW", "REVIEWER", "DOUBLE_BLIND", "", -1, reasoning.IAPPPseudonym, "", "rev_db_reviewer_pseudo", ""},
		{"I-05", expCoverIAPP, "REVIEW", "EDITOR", "DOUBLE_BLIND", "", -1, reasoning.IAPPReal, "", "rev_db_editor_real", ""},
		{"I-06", expCoverIAPP, "REVIEW", "AUTHOR", "SINGLE_BLIND", "", -1, reasoning.IAPPReal, "", "rev_sb_author_real", ""},
		{"I-07", expCoverIAPP, "REVIEW", "REVIEWER", "SINGLE_BLIND", "", -1, reasoning.IAPPPseudonym, "", "rev_sb_reviewer_pseudo", ""},
		{"I-08", expCoverIAPP, "REVIEW", "EDITOR", "SINGLE_BLIND", "", -1, reasoning.IAPPReal, "", "rev_sb_editor_real", ""},
		{"I-09", expCoverIAPP, "REVIEW", "AUTHOR", "OPEN", "", -1, reasoning.IAPPReal, "", "rev_open_author_real", ""},
		{"I-10", expCoverIAPP, "REVIEW", "REVIEWER", "OPEN", "", -1, reasoning.IAPPReal, "", "rev_open_reviewer_real", ""},
		{"I-11", expCoverIAPP, "REVIEW", "EDITOR", "OPEN", "", -1, reasoning.IAPPReal, "", "rev_open_editor_real", ""},
		{"I-12", expCoverIAPP, "PUBLICATION", "AUTHOR", "", "", -1, reasoning.IAPPReal, "", "pub_author_real", ""},
		{"I-13", expCoverIAPP, "PUBLICATION", "REVIEWER", "", "", -1, reasoning.IAPPReal, "", "pub_reviewer_real", ""},
		{"I-14", expCoverIAPP, "PUBLICATION", "EDITOR", "", "", -1, reasoning.IAPPReal, "", "pub_editor_real", ""},
	}
	all = append(all, iappCases...)

	// Full DAPP coverage (19 rules)
	dappCases := []struct {
		id, phase, dt, l, dapp, rule string
		level int
	}{
		{"D-01", "SUBMISSION", "MANUSCRIPT", "1", reasoning.DAPPECDH, "sub_manuscript_l1", 1},
		{"D-02", "SUBMISSION", "MANUSCRIPT", "2", reasoning.DAPPSSS, "sub_manuscript_l2", 2},
		{"D-03", "SUBMISSION", "MESSAGE", "1", reasoning.DAPPECDH, "sub_message_l1", 1},
		{"D-04", "SUBMISSION", "MESSAGE", "2", reasoning.DAPPPRE, "sub_message_l2", 2},
		{"D-05", "SUBMISSION", "ENCRYPTION_KEY", "1", reasoning.DAPPPRE, "sub_enckey_l1", 1},
		{"D-06", "REVIEW", "MANUSCRIPT", "1", reasoning.DAPPECDH, "rev_manuscript_l1", 1},
		{"D-07", "REVIEW", "MANUSCRIPT", "2", reasoning.DAPPSSS, "rev_manuscript_l2", 2},
		{"D-08", "REVIEW", "SUPPLEMENTARY_DATA", "1", reasoning.DAPPECDH, "rev_supp_l1", 1},
		{"D-09", "REVIEW", "SUPPLEMENTARY_DATA", "2", reasoning.DAPPPRE, "rev_supp_l2", 2},
		{"D-10", "REVIEW", "MESSAGE", "1", reasoning.DAPPECDH, "rev_message_l1", 1},
		{"D-11", "REVIEW", "MESSAGE", "2", reasoning.DAPPPRE, "rev_message_l2", 2},
		{"D-12", "REVIEW", "FINAL_RECOMMENDATION", "1", reasoning.DAPPECDH, "rev_final_l1", 1},
		{"D-13", "REVIEW", "FINAL_RECOMMENDATION", "2", reasoning.DAPPPRE, "rev_final_l2", 2},
		{"D-14", "REVIEW", "FINAL_RECOMMENDATION", "3", reasoning.DAPPMPC, "rev_final_l3", 3},
		{"D-15", "REVIEW", "ENCRYPTION_KEY", "1", reasoning.DAPPPRE, "rev_enckey_l1", 1},
		{"D-16", "PUBLICATION", "MANUSCRIPT", "1", reasoning.DAPPECDH, "pub_manuscript_l1", 1},
		{"D-17", "PUBLICATION", "MANUSCRIPT", "2", reasoning.DAPPSSS, "pub_manuscript_l2", 2},
		{"D-18", "PUBLICATION", "MESSAGE", "0", reasoning.DAPPPublic, "pub_message_l0", 0},
		{"D-19", "PUBLICATION", "ENCRYPTION_KEY", "1", reasoning.DAPPPRE, "pub_enckey_l1", 1},
	}
	for _, dc := range dappCases {
		all = append(all, scenario{
			ID: dc.id, Experiment: expCoverDAPP, Phase: dc.phase, DataType: dc.dt, SecurityLevel: dc.level,
			ExpectDAPP: dc.dapp, ExpectRule: dc.rule,
		})
	}

	return all
}

func runScenario(coord *reasoning.AdaptiveCoordinator, sc scenario) resultRow {
	in := context.ContextInput{
		Phase: sc.Phase, Role: sc.Role, ReviewMode: sc.ReviewMode,
		DataType: sc.DataType, SecurityLevel: sc.SecurityLevel,
	}
	state := context.NewContextAwarenessModule().Capture(in)

	var actualIAPP, actualDAPP, ruleID string
	passed := true

	if sc.ExpectIAPP != "" {
		dec, err := coord.EvaluateIdentityPolicy(in)
		if err != nil {
			actualIAPP = "ERROR"
			passed = false
		} else {
			actualIAPP = dec.IAPPStrategy
			ruleID = dec.RuleID
			if actualIAPP != sc.ExpectIAPP {
				passed = false
			}
			if sc.ExpectRule != "" && dec.RuleID != sc.ExpectRule {
				passed = false
			}
		}
	}
	if sc.ExpectDAPP != "" {
		dec, err := coord.EvaluateDataPolicy(in)
		if err != nil {
			actualDAPP = "ERROR"
			passed = false
		} else {
			actualDAPP = dec.DAPPStrategy
			if ruleID == "" {
				ruleID = dec.RuleID
			}
			if actualDAPP != sc.ExpectDAPP {
				passed = false
			}
			if sc.ExpectRule != "" && dec.RuleID != sc.ExpectRule {
				passed = false
			}
		}
	}

	return resultRow{
		Experiment: sc.Experiment, ScenarioID: sc.ID,
		S: state.Vector.S, M: state.Vector.M, R: state.Vector.R,
		D: state.Vector.D, L: state.Vector.L, StateKey: state.StateKey,
		ExpectIAPP: sc.ExpectIAPP, ExpectDAPP: sc.ExpectDAPP,
		ActualIAPP: actualIAPP, ActualDAPP: actualDAPP,
		RuleID: ruleID, ExpectRule: sc.ExpectRule, Passed: passed,
		ChaincodeRedeploy: "否", Notes: sc.Notes,
	}
}

func runHotUpdateExperiment() ([]resultRow, float64, error) {
	before, err := reasoning.NewDefaultCoordinator()
	if err != nil {
		return nil, 0, err
	}

	modified := buildHotUpdateRuleSet()
	tmp, err := os.CreateTemp("", "adaptive_rules_*.yaml")
	if err != nil {
		return nil, 0, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	enc := yaml.NewEncoder(tmp)
	if err := enc.Encode(modified); err != nil {
		tmp.Close()
		return nil, 0, err
	}
	tmp.Close()

	start := time.Now()
	after, err := reasoning.NewCoordinatorFromFile(tmpPath)
	loadMs := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return nil, 0, err
	}

	rows := make([]resultRow, 0, 2)

	// E3-01 IAPP hot update
	iappIn := context.ContextInput{Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND"}
	state := context.NewContextAwarenessModule().Capture(iappIn)
	beforeDec, _ := before.EvaluateIdentityPolicy(iappIn)
	afterDec, err := after.EvaluateIdentityPolicy(iappIn)
	if err != nil {
		return nil, loadMs, err
	}
	iappPassed := afterDec.IAPPStrategy == reasoning.IAPPAnonymous &&
		beforeDec.IAPPStrategy == reasoning.IAPPPseudonym &&
		afterDec.IAPPStrategy != beforeDec.IAPPStrategy
	rows = append(rows, resultRow{
		Experiment: exp3, ScenarioID: "E3-01",
		S: state.Vector.S, M: state.Vector.M, R: state.Vector.R, D: state.Vector.D, L: state.Vector.L,
		StateKey: state.StateKey,
		ExpectIAPP: reasoning.IAPPAnonymous,
		BeforeIAPP: beforeDec.IAPPStrategy, AfterIAPP: afterDec.IAPPStrategy,
		ActualIAPP: afterDec.IAPPStrategy,
		RuleID: afterDec.RuleID, ExpectRule: "rev_db_author_anonymous_hot",
		Passed: iappPassed, HotUpdateMs: loadMs,
		ChaincodeRedeploy: "否",
		Notes: "IAPP: PSEUDONYMOUS→ANONYMOUS (YAML only)",
	})

	// E3-02 DAPP hot update
	dappIn := context.ContextInput{Phase: "REVIEW", DataType: "SUPPLEMENTARY_DATA", SecurityLevel: 2}
	state2 := context.NewContextAwarenessModule().Capture(dappIn)
	beforeD, _ := before.EvaluateDataPolicy(dappIn)
	afterD, err := after.EvaluateDataPolicy(dappIn)
	if err != nil {
		return nil, loadMs, err
	}
	dappPassed := afterD.DAPPStrategy == reasoning.DAPPMPC &&
		beforeD.DAPPStrategy == reasoning.DAPPPRE &&
		afterD.DAPPStrategy != beforeD.DAPPStrategy
	rows = append(rows, resultRow{
		Experiment: exp3, ScenarioID: "E3-02",
		S: state2.Vector.S, M: state2.Vector.M, R: state2.Vector.R, D: state2.Vector.D, L: state2.Vector.L,
		StateKey: state2.StateKey,
		ExpectDAPP: reasoning.DAPPMPC,
		BeforeDAPP: beforeD.DAPPStrategy, AfterDAPP: afterD.DAPPStrategy,
		ActualDAPP: afterD.DAPPStrategy,
		RuleID: afterD.RuleID, ExpectRule: "rev_supp_l2_mpc",
		Passed: dappPassed, HotUpdateMs: loadMs,
		ChaincodeRedeploy: "否",
		Notes: "DAPP: PRE→MPC (YAML only)",
	})

	return rows, loadMs, nil
}

func buildHotUpdateRuleSet() *reasoning.RuleSet {
	rs := reasoning.DefaultRuleSet()
	out := &reasoning.RuleSet{Version: rs.Version + "-hot", Rules: make([]reasoning.Rule, 0, len(rs.Rules)+2)}
	for _, r := range rs.Rules {
		if r.ID == "rev_db_author_pseudo" {
			r.Output.IAPPStrategy = reasoning.IAPPAnonymous
			r.ID = "rev_db_author_anonymous_hot"
			r.Description = "热更新：双盲作者改为匿名"
		}
		if r.ID == "rev_supp_l2" {
			r.Output.DAPPStrategy = reasoning.DAPPMPC
			r.ID = "rev_supp_l2_mpc"
			r.Priority = 25
			r.Description = "热更新：补充数据L2改为MPC"
		}
		out.Rules = append(out.Rules, r)
	}
	return out
}

func computeSummary(rows []resultRow, hotMs float64) summaryMetrics {
	total := len(rows)
	passed := 0
	for _, r := range rows {
		if r.Passed {
			passed++
		}
	}

	exp1Total, exp1Pass := 0, 0
	exp2Total, exp2Pass := 0, 0
	exp3IAPPChanged, exp3DAPPChanged := false, false
	stateKeys := map[string]bool{}
	exp1Keys := map[string]string{} // r -> stateKey

	for _, r := range rows {
		if r.StateKey != "" {
			stateKeys[r.StateKey] = true
		}
		switch r.Experiment {
		case exp1:
			exp1Total++
			if r.Passed {
				exp1Pass++
			}
			if r.R != "" && r.R != "*" {
				exp1Keys[r.R] = r.StateKey
			}
		case exp2:
			exp2Total++
			if r.Passed {
				exp2Pass++
			}
		case exp3:
			if r.ScenarioID == "E3-01" && r.BeforeIAPP != r.AfterIAPP {
				exp3IAPPChanged = true
			}
			if r.ScenarioID == "E3-02" && r.BeforeDAPP != r.AfterDAPP {
				exp3DAPPChanged = true
			}
		}
	}

	// Context distinguish: Exp1 keys all different
	distinguishPairs := 0
	distinguishOK := 0
	keys := make([]string, 0, len(exp1Keys))
	for _, k := range exp1Keys {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			distinguishPairs++
			if keys[i] != keys[j] {
				distinguishOK++
			}
		}
	}
	distinguishRate := 1.0
	if distinguishPairs > 0 {
		distinguishRate = float64(distinguishOK) / float64(distinguishPairs)
	}

	coverageTotal := 0
	coveragePass := 0
	for _, r := range rows {
		if r.Experiment == expCoverIAPP || r.Experiment == expCoverDAPP {
			coverageTotal++
			if r.Passed {
				coveragePass++
			}
		}
	}
	coverageRate := 1.0
	if coverageTotal > 0 {
		coverageRate = float64(coveragePass) / float64(coverageTotal)
	}

	consistency := 0.0
	if total > 0 {
		consistency = float64(passed) / float64(total)
	}
	exp1Rate := 1.0
	if exp1Total > 0 {
		exp1Rate = float64(exp1Pass) / float64(exp1Total)
	}
	exp2Rate := 1.0
	if exp2Total > 0 {
		exp2Rate = float64(exp2Pass) / float64(exp2Total)
	}

	return summaryMetrics{
		TotalScenarios:     total,
		PassedScenarios:    passed,
		CoverageTotal:      coverageTotal,
		CoveragePassed:     coveragePass,
		CoverageRate:       coverageRate,
		ConsistencyRate:    consistency,
		ContextDistinguish: distinguishRate,
		Exp1Consistency:    exp1Rate,
		Exp2Consistency:    exp2Rate,
		Exp3IAPPChanged:    exp3IAPPChanged,
		Exp3DAPPChanged:    exp3DAPPChanged,
		HotUpdateLoadMs:    hotMs,
		ChaincodeRedeploy:  "否",
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
	}
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func writeSummaryJSON(path string, s summaryMetrics) error {
	return writeJSON(path, s)
}

func writeCSV(path string, rows []resultRow, summary summaryMetrics) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{
		"experiment", "scenario_id", "s", "m", "r", "d", "l", "state_key",
		"expect_iapp", "actual_iapp", "before_iapp", "after_iapp",
		"expect_dapp", "actual_dapp", "before_dapp", "after_dapp",
		"rule_id", "expect_rule", "passed", "hot_update_ms", "chaincode_redeploy", "notes",
	})
	for _, r := range rows {
		_ = w.Write([]string{
			r.Experiment, r.ScenarioID, r.S, r.M, r.R, r.D, r.L, r.StateKey,
			r.ExpectIAPP, r.ActualIAPP, r.BeforeIAPP, r.AfterIAPP,
			r.ExpectDAPP, r.ActualDAPP, r.BeforeDAPP, r.AfterDAPP,
			r.RuleID, r.ExpectRule, boolStr(r.Passed),
			fmt.Sprintf("%.3f", r.HotUpdateMs), r.ChaincodeRedeploy, r.Notes,
		})
	}

	_ = w.Write([]string{})
	_ = w.Write([]string{"--- Summary Metrics ---"})
	_ = w.Write([]string{"metric", "value"})
	_ = w.Write([]string{"total_scenarios", fmt.Sprintf("%d", summary.TotalScenarios)})
	_ = w.Write([]string{"passed_scenarios", fmt.Sprintf("%d", summary.PassedScenarios)})
	_ = w.Write([]string{"coverage_total", fmt.Sprintf("%d", summary.CoverageTotal)})
	_ = w.Write([]string{"coverage_passed", fmt.Sprintf("%d", summary.CoveragePassed)})
	_ = w.Write([]string{"coverage_rate", fmt.Sprintf("%.4f", summary.CoverageRate)})
	_ = w.Write([]string{"consistency_rate", fmt.Sprintf("%.4f", summary.ConsistencyRate)})
	_ = w.Write([]string{"context_distinguish_rate", fmt.Sprintf("%.4f", summary.ContextDistinguish)})
	_ = w.Write([]string{"exp1_consistency_rate", fmt.Sprintf("%.4f", summary.Exp1Consistency)})
	_ = w.Write([]string{"exp2_consistency_rate", fmt.Sprintf("%.4f", summary.Exp2Consistency)})
	_ = w.Write([]string{"exp3_iapp_changed", boolStr(summary.Exp3IAPPChanged)})
	_ = w.Write([]string{"exp3_dapp_changed", boolStr(summary.Exp3DAPPChanged)})
	_ = w.Write([]string{"hot_update_load_ms", fmt.Sprintf("%.3f", summary.HotUpdateLoadMs)})
	_ = w.Write([]string{"chaincode_redeploy", summary.ChaincodeRedeploy})
	return nil
}

func writeLaTeX(path string, rows []resultRow, summary summaryMetrics) error {
	var b strings.Builder

	b.WriteString("% Auto-generated by cmd/adaptive_benchmark — paste into thesis\n")
	b.WriteString("\\begin{table}[htbp]\n\\centering\n")
	b.WriteString("\\caption{身份与数据保护自适应性实验结果（实验一--三及规则覆盖）}\n")
	b.WriteString("\\label{tab:adaptive-benchmark}\n")
	b.WriteString("\\small\n\\begin{tabular}{llcccccccccc}\n\\hline\n")
	b.WriteString("实验 & 场景 & $s$ & $m$ & $r$ & $d$ & $l$ & 期望IAPP & 实际IAPP & 期望DAPP & 实际DAPP & 通过 \\\\\n\\hline\n")

	for _, r := range rows {
		if r.Experiment != exp1 && r.Experiment != exp2 && r.Experiment != exp3 {
			continue
		}
		expShort := expLabelShort(r.Experiment)
		eIAPP := latexCell(r.ExpectIAPP, r.BeforeIAPP, r.AfterIAPP, "iapp")
		aIAPP := latexActual(r.ActualIAPP, r.BeforeIAPP, r.AfterIAPP, "iapp")
		eDAPP := latexCell(r.ExpectDAPP, r.BeforeDAPP, r.AfterDAPP, "dapp")
		aDAPP := latexActual(r.ActualDAPP, r.BeforeDAPP, r.AfterDAPP, "dapp")
		b.WriteString(fmt.Sprintf("%s & %s & %s & %s & %s & %s & %s & %s & %s & %s & %s & %s \\\\\n",
			expShort, texEsc(r.ScenarioID),
			texEsc(r.S), texEsc(r.M), texEsc(r.R), texEsc(r.D), texEsc(r.L),
			eIAPP, aIAPP, eDAPP, aDAPP, boolLaTeX(r.Passed),
		))
	}
	b.WriteString("\\hline\n\\end{tabular}\n\\end{table}\n\n")

	// Summary metrics table
	b.WriteString("\\begin{table}[htbp]\n\\centering\n")
	b.WriteString("\\caption{自适应性评价指标汇总}\n")
	b.WriteString("\\label{tab:adaptive-metrics}\n")
	b.WriteString("\\begin{tabular}{ll}\n\\hline\n")
	b.WriteString("指标 & 结果 \\\\\n\\hline\n")
	b.WriteString(fmt.Sprintf("场景覆盖率 & %.1f\\%% (%d/%d IAPP+DAPP规则覆盖) \\\\\n",
		summary.CoverageRate*100, summary.CoveragePassed, summary.CoverageTotal))
	b.WriteString(fmt.Sprintf("推理一致性 & %.1f\\%% (%d/%d) \\\\\n",
		summary.ConsistencyRate*100, summary.PassedScenarios, summary.TotalScenarios))
	b.WriteString(fmt.Sprintf("上下文区分度（实验一） & %.1f\\%% \\\\\n", summary.ContextDistinguish*100))
	b.WriteString(fmt.Sprintf("实验一一致性 & %.1f\\%% \\\\\n", summary.Exp1Consistency*100))
	b.WriteString(fmt.Sprintf("实验二一致性 & %.1f\\%% \\\\\n", summary.Exp2Consistency*100))
	b.WriteString(fmt.Sprintf("实验三 IAPP 热更新 & %s \\\\\n", boolLaTeX(summary.Exp3IAPPChanged)))
	b.WriteString(fmt.Sprintf("实验三 DAPP 热更新 & %s \\\\\n", boolLaTeX(summary.Exp3DAPPChanged)))
	b.WriteString(fmt.Sprintf("规则热更新加载耗时 & %.3f\\,ms \\\\\n", summary.HotUpdateLoadMs))
	b.WriteString(fmt.Sprintf("Chaincode 重新部署 & %s \\\\\n", texEsc(summary.ChaincodeRedeploy)))
	b.WriteString("\\hline\n\\end{tabular}\n\\end{table}\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func expLabelShort(exp string) string {
	switch exp {
	case exp1:
		return "Exp-1"
	case exp2:
		return "Exp-2"
	case exp3:
		return "Exp-3"
	default:
		return texEsc(exp)
	}
}

func latexCell(expect, before, after, kind string) string {
	if before != "" && after != "" {
		if kind == "iapp" {
			return fmt.Sprintf("%s\\textrightarrow{}%s", texEsc(before), texEsc(after))
		}
		return fmt.Sprintf("%s\\textrightarrow{}%s", texEsc(before), texEsc(after))
	}
	return texEsc(expect)
}

func latexActual(actual, before, after, _ string) string {
	if before != "" && after != "" {
		return fmt.Sprintf("%s\\textrightarrow{}%s", texEsc(before), texEsc(after))
	}
	return texEsc(actual)
}

func texEsc(s string) string {
	if s == "" {
		return "---"
	}
	r := strings.NewReplacer("_", "\\_", "%", "\\%", "&", "\\&")
	return r.Replace(s)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func boolLaTeX(b bool) string {
	if b {
		return "是"
	}
	return "否"
}
