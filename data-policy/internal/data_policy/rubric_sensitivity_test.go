package data_policy

import (
	"testing"
)

// TestRubricSensitivity_Univariate10And20 单变量扰动：每次只改变一种策略权重 ±10%、±20%，
// 验证自适应总分仍严格大于 B1、B2（支撑论文「权重主观性」下的稳健性叙述）。
func TestRubricSensitivity_Univariate10And20(t *testing.T) {
	m := NewEnhancedDataPolicyManager()
	base := DefaultRubricWeights()
	steps := securityExperimentWorkflow
	n := len(steps)

	ad0 := SumAdaptiveRubric(m, steps, base)
	b10 := SumB1Rubric(n, base)
	b20 := SumB2Rubric(steps, base)
	if !OrderingHolds(ad0, b10, b20) {
		t.Fatalf("base ordering broken: ad=%.4f b1=%.4f b2=%.4f", ad0, b10, b20)
	}

	for _, frac := range []float64{0.10, 0.20} {
		cases := ScanUnivariatePerturbations(m, base, frac)
		for _, c := range cases {
			if !c.Holds {
				t.Fatalf("univariate sensitivity failed (%s): ad=%.4f b1=%.4f b2=%.4f", c.Label, c.Adaptive, c.B1, c.B2)
			}
		}
		t.Logf("±%.0f%% univariate: all %d cases preserve adaptive>B1 and adaptive>B2", frac*100, len(cases))
	}
	t.Logf("baseline scores: adaptive=%.2f B1=%.2f B2=%.2f", ad0, b10, b20)
}

// TestRubricSensitivity_JointTiltModerate 联合扰动（不利自适应）：ECDH 权重上浮、其余策略同比例下浮。
// 适度 tilt 下排序仍应成立；过大 tilt 可能反转——测试记录临界区间供论文讨论。
func TestRubricSensitivity_JointTiltModerate(t *testing.T) {
	m := NewEnhancedDataPolicyManager()
	base := DefaultRubricWeights()
	steps := securityExperimentWorkflow
	n := len(steps)

	for _, tilt := range []float64{0.05, 0.08, 0.10, 0.12} {
		w := JointTiltWeights(base, tilt)
		ad := SumAdaptiveRubric(m, steps, w)
		b1 := SumB1Rubric(n, w)
		b2 := SumB2Rubric(steps, w)
		if !OrderingHolds(ad, b1, b2) {
			t.Fatalf("joint tilt %.2f broke ordering: ad=%.4f b1=%.4f b2=%.4f", tilt, ad, b1, b2)
		}
		t.Logf("joint tilt %+d%% ECDH / -%d%% others: adaptive=%.4f B1=%.4f B2=%.4f OK",
			int(tilt*100+0.5), int(tilt*100+0.5), ad, b1, b2)
	}
}

// TestRubricSensitivity_JointTiltBreakEven 扫描联合倾斜强度，输出排序相对 B1 首次失效的近似临界点（论文可引用为敏感性边界）。
func TestRubricSensitivity_JointTiltBreakEven(t *testing.T) {
	m := NewEnhancedDataPolicyManager()
	base := DefaultRubricWeights()
	steps := securityExperimentWorkflow
	n := len(steps)

	var firstFail float64 = -1
	for step := 0; step <= 250; step++ {
		tilt := float64(step) / 1000.0 // 0.000 .. 0.250
		w := JointTiltWeights(base, tilt)
		ad := SumAdaptiveRubric(m, steps, w)
		b1 := SumB1Rubric(n, w)
		b2 := SumB2Rubric(steps, w)
		if !OrderingHolds(ad, b1, b2) {
			firstFail = tilt
			t.Logf("ordering breaks at joint tilt tilt≈%.3f (ECDH×(1+tilt), others×(1-tilt)): adaptive=%.4f B1=%.4f B2=%.4f",
				tilt, ad, b1, b2)
			break
		}
	}
	if firstFail < 0 {
		t.Fatal("expected some tilt to break ordering within [0,0.25]")
	}
	// 联合扰动在临界点附近反转排序是预期现象，测试成功意味着找到了报告用的边界。
	t.Logf("for moderate tilts below %.3f, adaptive>B1 and adaptive>B2 still hold under this joint stress model", firstFail)
}