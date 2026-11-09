package data_policy

import "github.com/tap-thesis/privacy-protection-data/pkg/types"

// workflowStep 描述实验中比较的「阶段 × 数据类型 × 安全级别」三元组。
type workflowStep struct {
	phase types.PublishingPhase
	dt    string
	level types.DataSecurityLevel
}

// securityExperimentWorkflow 典型高安全实验剖面（与 security_experiment_test.go 一致）。
var securityExperimentWorkflow = []workflowStep{
	{types.PhaseSubmission, DataTypeManuscript, types.DataSecLevel2},
	{types.PhaseSubmission, DataTypeMessage, types.DataSecLevel2},
	{types.PhaseReview, DataTypeManuscript, types.DataSecLevel2},
	{types.PhaseReview, DataTypeSupplementaryData, types.DataSecLevel2},
	{types.PhaseReview, DataTypeMessage, types.DataSecLevel2},
	{types.PhaseReview, DataTypeFinalRecommendation, types.DataSecLevel3},
	{types.PhasePublication, DataTypeManuscript, types.DataSecLevel2},
	{types.PhasePublication, DataTypeMessage, types.DataSecLevel0},
}

// SecurityWorkflowStep 导出供性能基准使用的 workflow 一步（阶段 × 数据类型 × 级别）。
type SecurityWorkflowStep struct {
	Phase    types.PublishingPhase
	DataType string
	Level    types.DataSecurityLevel
}

// SecurityExperimentWorkflowSteps 返回固定 8 步安全实验剖面（与 rubric 实验一致）。
func SecurityExperimentWorkflowSteps() []SecurityWorkflowStep {
	out := make([]SecurityWorkflowStep, len(securityExperimentWorkflow))
	for i, s := range securityExperimentWorkflow {
		out[i] = SecurityWorkflowStep{Phase: s.phase, DataType: s.dt, Level: s.level}
	}
	return out
}
