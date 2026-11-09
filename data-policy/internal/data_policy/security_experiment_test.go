package data_policy

import (
	"github.com/tap-thesis/privacy-protection-data/pkg/types"
	"bytes"
	"testing"
)

// rubricScore 将策略类型映射为可比较的「综合保密强度」指标（论文可用作定性量纲一致的综合分）。
// 说明：非比特强度；体现阈值体制、代理重加密能力及公开面的刻意降级。
func rubricScore(policyType string) float64 {
	switch policyType {
	case "ECDH_HKDF":
		return 3.0
	case "SSS":
		return 5.0
	case "PROXY_REENCRYPTION":
		return 4.2
	case "MPC":
		return 5.5
	case "PUBLIC":
		return 1.0
	default:
		return 2.0
	}
}

func sumRubricForWorkflow(m *EnhancedDataPolicyManager, steps []workflowStep, forceUniformECDH bool) float64 {
	var total float64
	for _, s := range steps {
		var pt string
		if forceUniformECDH {
			pt = "ECDH_HKDF"
		} else {
			pol, err := m.GetEncryptionPolicyWithLevel(s.phase, s.dt, s.level)
			if err != nil {
				continue
			}
			pt = pol.GetPolicyType()
		}
		total += rubricScore(pt)
	}
	return total
}

// TestSecurityScore_AdaptiveExceedsUniformECDH
// 基线 B1：经典端到端方案——全流程假设仅使用 ECDH+AEAD（Uniform ECDH）。
// 本机制：按阶段/数据类型/安全级别切换 ECDH / SSS / PRE / MPC / PUBLIC。
func TestSecurityScore_AdaptiveExceedsUniformECDH(t *testing.T) {
	m := NewEnhancedDataPolicyManager()
	proposed := sumRubricForWorkflow(m, securityExperimentWorkflow, false)
	baseline := sumRubricForWorkflow(m, securityExperimentWorkflow, true)
	if proposed <= baseline {
		t.Fatalf("期望自适应机制综合保密分高于均匀 ECDH：proposed=%.2f baseline=%.2f", proposed, baseline)
	}
	t.Logf("综合保密分（实验剖面）：自适应=%.2f，均匀ECDH基线=%.2f，差值=%.2f", proposed, baseline, proposed-baseline)
}

// TestSecurityScore_AdaptiveExceedsPhaseStaticLevel1
// 基线 B2：仅按阶段固定策略且始终 Level1（无 PRE/MPC/SSS 升级路径）。
func TestSecurityScore_AdaptiveExceedsPhaseStaticLevel1(t *testing.T) {
	m := NewEnhancedDataPolicyManager()
	stepsL1 := make([]workflowStep, len(securityExperimentWorkflow))
	copy(stepsL1, securityExperimentWorkflow)
	for i := range stepsL1 {
		stepsL1[i].level = types.DataSecLevel1
	}
	var phaseStatic float64
	for _, s := range stepsL1 {
		var pt string
		switch s.phase {
		case types.PhaseSubmission, types.PhaseReview:
			pt = "ECDH_HKDF"
		case types.PhasePublication:
			if s.dt == string(types.DataTypeMessage) {
				pt = "PUBLIC"
			} else {
				pt = "ECDH_HKDF"
			}
		}
		phaseStatic += rubricScore(pt)
	}
	proposed := sumRubricForWorkflow(m, securityExperimentWorkflow, false)
	if proposed <= phaseStatic {
		t.Fatalf("期望自适应 Level2/3 剖面高于阶段静态 Level1：proposed=%.2f phaseStatic=%.2f", proposed, phaseStatic)
	}
	t.Logf("综合保密分：自适应(Level2/3)=%.2f，阶段静态 Level1=%.2f", proposed, phaseStatic)
}

func TestECDH_WrongParticipantCannotDecrypt(t *testing.T) {
	p := NewECDHEncryptionPolicy()
	participants := []string{"author", "editor"}
	plain := []byte("manuscript-under-review")
	ct, meta, err := p.Encrypt(plain, participants)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Decrypt(ct, meta, "reviewer-not-in-participants")
	if err == nil {
		t.Fatal("非参与者应无法解密")
	}
	pt, err := p.Decrypt(ct, meta, "author")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatal("参与者解密结果不一致")
	}
}

func TestSSS_DecryptFailsBelowThreshold(t *testing.T) {
	p := NewSSSEncryptionPolicy()
	participants := []string{"r1", "r2", "r3", "r4", "r5"}
	plain := []byte("shared-secret-manuscript-key")
	ct, meta, err := p.Encrypt(plain, participants)
	if err != nil {
		t.Fatal(err)
	}
	th := int(meta[participants[0]][0])
	if th < 2 {
		t.Fatalf("期望阈值>=2，得到 %d", th)
	}
	trunc := make(map[string][]byte, th-1)
	for i := 0; i < th-1 && i < len(participants); i++ {
		trunc[participants[i]] = meta[participants[i]]
	}
	_, err = p.Decrypt(ct, trunc, participants[0])
	if err == nil {
		t.Fatal("分享数低于阈值时应无法恢复 AES 密钥")
	}
}
