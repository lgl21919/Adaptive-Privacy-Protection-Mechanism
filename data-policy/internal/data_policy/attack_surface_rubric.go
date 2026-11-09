package data_policy

import (
	"fmt"
	"strings"

	"github.com/tap-thesis/privacy-protection-data/pkg/types"
)

// BaselineProfile 对比剖面：B1 均匀 ECDH、B2 阶段静态、Adaptive 自适应 IAPP+DAPP。
type BaselineProfile string

const (
	ProfileB1UniformECDH  BaselineProfile = "B1"
	ProfileB2PhaseStatic  BaselineProfile = "B2"
	ProfileAdaptive       BaselineProfile = "Adaptive"
)

// AttackVectorID 固定八步工作流下的定性攻击向量标识。
type AttackVectorID string

const (
	AttackSinglePointKey      AttackVectorID = "single_point_key"
	AttackReviewerCollusion   AttackVectorID = "reviewer_collusion"
	AttackInsiderEditor       AttackVectorID = "insider_editor"
	AttackPREDelegate         AttackVectorID = "pre_delegate"
)

// AttackSurfaceEntry 单条攻击面的定性描述与定量缓解分（1=最差，5=最佳；0=不适用）。
type AttackSurfaceEntry struct {
	ID           AttackVectorID
	Vector       string // 论文表头 Attack Vector
	B1Qual       string
	B2Qual       string
	AdaptiveQual string
	B1Score      float64 // 0 = N/A，不参与加总
	B2Score      float64
	AdaptiveScore float64
	Notes        string
}

// DefaultAttackSurfaceRubric 八步工作流下的攻击面 rubric（定性 + 定量）。
// 定量分用于与既有 DefaultRubricWeights 敏感性实验并列，不构成比特级安全证明。
func DefaultAttackSurfaceRubric() []AttackSurfaceEntry {
	return []AttackSurfaceEntry{
		{
			ID:           AttackSinglePointKey,
			Vector:       "Single-point key compromise",
			B1Qual:       "Full plaintext access at any stage",
			B2Qual:       "Full plaintext access at any stage",
			AdaptiveQual: "Partial (only current stage)",
			B1Score:      1.0,
			B2Score:      1.0,
			AdaptiveScore: 3.0,
			Notes:        "Adaptive 分阶段密钥与级别升级缩小 blast radius",
		},
		{
			ID:           AttackReviewerCollusion,
			Vector:       "Compromised reviewer collusion",
			B1Qual:       "Can read all manuscripts",
			B2Qual:       "Can read all manuscripts",
			AdaptiveQual: "Restricted (SSS threshold)",
			B1Score:      1.0,
			B2Score:      1.0,
			AdaptiveScore: 4.0,
			Notes:        "REVIEW 稿件/建议步启用 SSS/MPC 阈值体制",
		},
		{
			ID:           AttackInsiderEditor,
			Vector:       "Insider editor targeting author list",
			B1Qual:       "Always sees real identity",
			B2Qual:       "Always sees real identity",
			AdaptiveQual: "Prevented (anonymous mode)",
			B1Score:      1.0,
			B2Score:      1.0,
			AdaptiveScore: 5.0,
			Notes:        "IAPP 双盲审稿下作者/审稿人伪名或匿名",
		},
		{
			ID:           AttackPREDelegate,
			Vector:       "Compromised proxy re-encryption delegate",
			B1Qual:       "N/A",
			B2Qual:       "N/A",
			AdaptiveQual: "Limited (delegated scope)",
			B1Score:      0.0,
			B2Score:      0.0,
			AdaptiveScore: 3.0,
			Notes:        "仅 Adaptive 暴露 PRE 面；B1/B2 无代理面故 N/A",
		},
	}
}

// SumAttackSurfaceScore 对指定剖面求缓解分总和（跳过 N/A 即 score=0 项）。
func SumAttackSurfaceScore(entries []AttackSurfaceEntry, profile BaselineProfile) float64 {
	var total float64
	for _, e := range entries {
		switch profile {
		case ProfileB1UniformECDH:
			total += e.B1Score
		case ProfileB2PhaseStatic:
			total += e.B2Score
		case ProfileAdaptive:
			total += e.AdaptiveScore
		}
	}
	return total
}

// SumSharedAttackSurfaceScore 仅对 B1/B2/Adaptive 均适用的攻击向量求和（排除 PRE _delegate）。
func SumSharedAttackSurfaceScore(entries []AttackSurfaceEntry, profile BaselineProfile) float64 {
	var total float64
	for _, e := range entries {
		if e.ID == AttackPREDelegate {
			continue
		}
		switch profile {
		case ProfileB1UniformECDH:
			total += e.B1Score
		case ProfileB2PhaseStatic:
			total += e.B2Score
		case ProfileAdaptive:
			total += e.AdaptiveScore
		}
	}
	return total
}

// AttackSurfaceOrderingHolds Adaptive 攻击面缓解分是否同时严格大于 B1 与 B2。
func AttackSurfaceOrderingHolds(adaptive, b1, b2 float64) bool {
	return adaptive > b1 && adaptive > b2
}

// PolicyAttackMitigationWeights 策略类型对攻击面的边际缓解贡献（与保密强度 rubric 正交维度）。
// 用于八步工作流上解释「为何 Adaptive 剖面在攻击面维度得分更高」。
func PolicyAttackMitigationWeights() map[string]float64 {
	return map[string]float64{
		"ECDH_HKDF":           1.0, // 基线：单点密钥暴露面大
		"SSS":                 2.5, // 阈值化，抑制审稿人串谋
		"PROXY_REENCRYPTION": 1.8, // 功能性换取委托攻击面
		"MPC":                 3.0, // 最终建议强隔离
		"PUBLIC":              0.5, // 刻意公开面
	}
}

// SumWorkflowAttackExposure 沿八步工作流累计「暴露度」= Σ(5 - mitigation(policy))，越低越好。
// 与 SumAdaptiveRubric（保密强度越高越好）互补：本函数从攻击面视角衡量残余暴露。
func SumWorkflowAttackExposure(steps []workflowStep, profile BaselineProfile, m *EnhancedDataPolicyManager) float64 {
	mit := PolicyAttackMitigationWeights()
	var exposure float64
	maxMit := 5.0

	for _, s := range steps {
		pt := policyTypeForProfile(s, profile, m)
		mval, ok := mit[pt]
		if !ok {
			mval = 1.0
		}
		exposure += maxMit - mval
	}
	return exposure
}

func policyTypeForProfile(s workflowStep, profile BaselineProfile, m *EnhancedDataPolicyManager) string {
	switch profile {
	case ProfileB1UniformECDH:
		return "ECDH_HKDF"
	case ProfileB2PhaseStatic:
		if s.phase == types.PhasePublication && s.dt == string(types.DataTypeMessage) {
			return "PUBLIC"
		}
		return "ECDH_HKDF"
	case ProfileAdaptive:
		pol, err := m.GetEncryptionPolicyWithLevel(s.phase, s.dt, s.level)
		if err != nil {
			return "ECDH_HKDF"
		}
		return pol.GetPolicyType()
	default:
		return "ECDH_HKDF"
	}
}

// AttackSurfaceReport 论文/导出用汇总。
type AttackSurfaceReport struct {
	Entries           []AttackSurfaceEntry
	B1Total           float64
	B2Total           float64
	AdaptiveTotal     float64
	B1Shared          float64
	B2Shared          float64
	AdaptiveShared    float64
	B1Exposure        float64
	B2Exposure        float64
	AdaptiveExposure  float64
	OrderingHolds     bool
	WorkflowStepCount int
}

// BuildAttackSurfaceReport 生成固定八步工作流下的攻击面 rubric 报告。
func BuildAttackSurfaceReport(m *EnhancedDataPolicyManager) AttackSurfaceReport {
	entries := DefaultAttackSurfaceRubric()
	steps := securityExperimentWorkflow
	b1 := SumAttackSurfaceScore(entries, ProfileB1UniformECDH)
	b2 := SumAttackSurfaceScore(entries, ProfileB2PhaseStatic)
	ad := SumAttackSurfaceScore(entries, ProfileAdaptive)
	return AttackSurfaceReport{
		Entries:           entries,
		B1Total:           b1,
		B2Total:           b2,
		AdaptiveTotal:     ad,
		B1Shared:          SumSharedAttackSurfaceScore(entries, ProfileB1UniformECDH),
		B2Shared:          SumSharedAttackSurfaceScore(entries, ProfileB2PhaseStatic),
		AdaptiveShared:    SumSharedAttackSurfaceScore(entries, ProfileAdaptive),
		B1Exposure:        SumWorkflowAttackExposure(steps, ProfileB1UniformECDH, m),
		B2Exposure:        SumWorkflowAttackExposure(steps, ProfileB2PhaseStatic, m),
		AdaptiveExposure:  SumWorkflowAttackExposure(steps, ProfileAdaptive, m),
		OrderingHolds:     AttackSurfaceOrderingHolds(ad, b1, b2),
		WorkflowStepCount: len(steps),
	}
}

// ExportAttackSurfaceLaTeX 导出论文用 LaTeX（定性攻击面对比表 + 定量 rubric 表）。
func ExportAttackSurfaceLaTeX(report AttackSurfaceReport) string {
	var b strings.Builder
	b.WriteString("% Attack-surface rubric — auto-generated\n")
	b.WriteString("\\begin{table}[htbp]\n\\centering\n")
	b.WriteString("\\caption{Qualitative attack surface comparison under the fixed eight-step workflow.}\n")
	b.WriteString("\\label{tab:attack-surface-qualitative}\n")
	b.WriteString("\\small\n\\begin{tabular}{p{0.28\\linewidth}p{0.20\\linewidth}p{0.20\\linewidth}p{0.22\\linewidth}}\n\\hline\n")
	b.WriteString("Attack Vector & B1 (Uniform ECDH) & B2 (Phase-Static) & Adaptive \\\\\n\\hline\n")
	for _, e := range report.Entries {
		b.WriteString(fmt.Sprintf("%s & %s & %s & %s \\\\\n",
			texEscapeAS(e.Vector), texEscapeAS(e.B1Qual), texEscapeAS(e.B2Qual), texEscapeAS(e.AdaptiveQual)))
	}
	b.WriteString("\\hline\n\\end{tabular}\n\\end{table}\n\n")

	b.WriteString("\\begin{table}[htbp]\n\\centering\n")
	b.WriteString("\\caption{Quantitative attack-surface mitigation rubric (higher is better; N/A scored as 0).}\n")
	b.WriteString("\\label{tab:attack-surface-quantitative}\n")
	b.WriteString("\\begin{tabular}{lccc}\n\\hline\n")
	b.WriteString("Attack Vector & B1 & B2 & Adaptive \\\\\n\\hline\n")
	for _, e := range report.Entries {
		b.WriteString(fmt.Sprintf("%s & %s & %s & %s \\\\\n",
			texEscapeAS(e.Vector), scoreCellAS(e.B1Score), scoreCellAS(e.B2Score), scoreCellAS(e.AdaptiveScore)))
	}
	b.WriteString("\\hline\n")
	b.WriteString(fmt.Sprintf("Total (all vectors) & %.0f & %.0f & %.0f \\\\\n", report.B1Total, report.B2Total, report.AdaptiveTotal))
	b.WriteString(fmt.Sprintf("Total (shared vectors) & %.0f & %.0f & %.0f \\\\\n", report.B1Shared, report.B2Shared, report.AdaptiveShared))
	b.WriteString(fmt.Sprintf("Workflow exposure index ($\\downarrow$) & %.1f & %.1f & %.1f \\\\\n",
		report.B1Exposure, report.B2Exposure, report.AdaptiveExposure))
	b.WriteString("\\hline\n\\end{tabular}\n\\end{table}\n")
	return b.String()
}

func scoreCellAS(s float64) string {
	if s <= 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.0f", s)
}

func texEscapeAS(s string) string {
	r := strings.NewReplacer("_", "\\_", "&", "\\&", "%", "\\%")
	return r.Replace(s)
}

// ExportLegacyRubricLaTeX 保留既有保密强度 rubric 权重表（论文原有表格）。
func ExportLegacyRubricLaTeX(w map[string]float64) string {
	if w == nil {
		w = DefaultRubricWeights()
	}
	var b strings.Builder
	b.WriteString("\\begin{table}[htbp]\n\\centering\n")
	b.WriteString("\\caption{Legacy confidentiality rubric weights (unchanged; sensitivity analysis in \\S\\ref{sec:rubric-sensitivity}).}\n")
	b.WriteString("\\label{tab:legacy-rubric-weights}\n")
	b.WriteString("\\begin{tabular}{lc}\n\\hline\n")
	b.WriteString("Policy Type & Weight \\\\\n\\hline\n")
	for _, k := range RubricPolicyKeys {
		b.WriteString(fmt.Sprintf("%s & %.1f \\\\\n", texEscapeAS(k), w[k]))
	}
	b.WriteString("\\hline\n\\end{tabular}\n\\end{table}\n")
	return b.String()
}
