package data_policy

import (
	"github.com/tap-thesis/privacy-protection-data/pkg/types"
	"fmt"
)

// RubricPolicyKeys 参与敏感性扰动的策略类型（与 rubricScore / GetPolicyType 一致）。
var RubricPolicyKeys = []string{
	"ECDH_HKDF",
	"SSS",
	"PROXY_REENCRYPTION",
	"MPC",
	"PUBLIC",
}

// DefaultRubricWeights 与 security_experiment_test.go 中 rubricScore 默认值一致。
func DefaultRubricWeights() map[string]float64 {
	return map[string]float64{
		"ECDH_HKDF":           3.0,
		"SSS":                 5.0,
		"PROXY_REENCRYPTION": 4.2,
		"MPC":                 5.5,
		"PUBLIC":              1.0,
	}
}

func cloneRubricWeights(src map[string]float64) map[string]float64 {
	dst := make(map[string]float64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func rubricLookup(policyType string, w map[string]float64) float64 {
	if v, ok := w[policyType]; ok {
		return v
	}
	return 2.0
}

// SumAdaptiveRubric 在给定权重向量下对 securityExperimentWorkflow 求和。
func SumAdaptiveRubric(m *EnhancedDataPolicyManager, steps []workflowStep, w map[string]float64) float64 {
	var total float64
	for _, s := range steps {
		pol, err := m.GetEncryptionPolicyWithLevel(s.phase, s.dt, s.level)
		if err != nil {
			continue
		}
		total += rubricLookup(pol.GetPolicyType(), w)
	}
	return total
}

// SumB1Rubric B1：每一步均按 ECDH_HKDF 计分。
func SumB1Rubric(nSteps int, w map[string]float64) float64 {
	return float64(nSteps) * rubricLookup("ECDH_HKDF", w)
}

// SumB2Rubric B2：与 security_experiment_test 一致——除「出版·消息」为 PUBLIC 外均为 ECDH。
func SumB2Rubric(steps []workflowStep, w map[string]float64) float64 {
	var total float64
	for _, s := range steps {
		if s.phase == types.PhasePublication && s.dt == string(types.DataTypeMessage) {
			total += rubricLookup("PUBLIC", w)
			continue
		}
		total += rubricLookup("ECDH_HKDF", w)
	}
	return total
}

// OrderingHolds 自适应总分是否同时严格大于 B1 与 B2。
func OrderingHolds(adaptive, b1, b2 float64) bool {
	return adaptive > b1 && adaptive > b2
}

// PerturbOneKey 复制 base 后将 key 乘以 factor，其余不变。
func PerturbOneKey(base map[string]float64, key string, factor float64) map[string]float64 {
	out := cloneRubricWeights(base)
	out[key] *= factor
	return out
}

// JointTiltWeights 联合扰动：抬高 ECDH（有利 B1/B2）、压低其余策略权重（不利自适应剖面）。
// tilt ∈ [0,1)：ECDH *= 1+tilt，其余 *= 1-tilt。
func JointTiltWeights(base map[string]float64, tilt float64) map[string]float64 {
	out := cloneRubricWeights(base)
	for k, v := range out {
		if k == "ECDH_HKDF" {
			out[k] = v * (1 + tilt)
		} else {
			out[k] = v * (1 - tilt)
		}
	}
	return out
}

// SensitivityCase 记录单次扰动下的得分与排序是否成立（便于日志 / 论文制表）。
type SensitivityCase struct {
	Label    string
	Adaptive float64
	B1       float64
	B2       float64
	Holds    bool
}

// ScanUnivariatePerturbations 对每种策略权重单独乘以 (1±fraction)，返回全部用例。
func ScanUnivariatePerturbations(m *EnhancedDataPolicyManager, base map[string]float64, fraction float64) []SensitivityCase {
	steps := securityExperimentWorkflow
	n := len(steps)
	var cases []SensitivityCase
	for _, key := range RubricPolicyKeys {
		for _, sign := range []float64{-1.0, 1.0} {
			factor := 1 + sign*fraction
			label := fmt.Sprintf("%s×%.4g", key, factor)
			w := PerturbOneKey(base, key, factor)
			ad := SumAdaptiveRubric(m, steps, w)
			b1 := SumB1Rubric(n, w)
			b2 := SumB2Rubric(steps, w)
			cases = append(cases, SensitivityCase{label, ad, b1, b2, OrderingHolds(ad, b1, b2)})
		}
	}
	return cases
}
