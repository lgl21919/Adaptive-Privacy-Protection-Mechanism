package main

import (
	"github.com/tap-thesis/privacy-protection-data/internal/data_policy"
	"github.com/tap-thesis/privacy-protection-data/pkg/types"
	"fmt"
	"strings"
	"time"
)

const manuscriptPayloadBytes = 64 * 1024 // 64 KB，对应论文 Table crypto-latency 大载荷行

// PerformanceStats 性能统计结构
type PerformanceStats struct {
	TotalOps      int           // 总操作次数
	SuccessOps    int           // 成功次数
	FailedOps     int           // 失败次数
	TotalDuration time.Duration // 总耗时
	MinDuration   time.Duration // 最小耗时
	MaxDuration   time.Duration // 最大耗时
	Durations     []time.Duration // 所有操作的耗时记录
}

func main() {
	fmt.Println("=== 学术出版系统 - 数据保护策略测试与性能评估 ===")
	fmt.Println()

	// 初始化数据保护策略管理器
	dataPolicyManager := data_policy.NewEnhancedDataPolicyManager()

	// 显示已注册的策略信息
	showRegisteredPolicies()

	// 测试已注册的策略组合
	fmt.Println("=== 测试已注册的策略组合 ===")
	testRegisteredPolicyCombinations(dataPolicyManager)

	// 性能测试
	fmt.Println("\n=== 性能测试（默认载荷 ~80B）===")
	performanceTest(dataPolicyManager)

	// 64KB 稿件载荷（论文表格：ECDH / SSS）
	fmt.Println("\n=== 性能测试（64KB 稿件载荷，Enc+Dec 往返）===")
	performanceTest64KBManuscript(dataPolicyManager)

	// 工作流集成开销（Adaptive vs B1/B2）
	fmt.Println("\n=== 工作流集成开销测试（8 步剖面，Enc+Dec 累计）===")
	performanceTestWorkflow(dataPolicyManager)

	// 大规模：参与者数 n 扩展（64KB 稿件）
	fmt.Println("\n=== 大规模测试（64KB 稿件，n 扩展）===")
	performanceTestScaleN(dataPolicyManager)

	// 策略获取性能测试
	fmt.Println("\n=== 策略获取性能测试 ===")
	policyRetrievalPerformanceTest(dataPolicyManager)
}

// showRegisteredPolicies 显示已注册的策略信息
func showRegisteredPolicies() {
	fmt.Println("=== 已注册的数据保护策略 ===")
	fmt.Println("根据 DataPolicyManager.go 中的配置，已注册的策略组合如下：")
	fmt.Println()
	fmt.Println("提交阶段 (SUBMISSION):")
	fmt.Println("  - Manuscript: Level 1 (ECDH), Level 2 (SSS)")
	fmt.Println("  - Message: Level 1 (ECDH), Level 2 (PRE)")
	fmt.Println("  - EncryptionKey: Level 1 (PRE)")
	fmt.Println()
	fmt.Println("审稿阶段 (REVIEW):")
	fmt.Println("  - Manuscript: Level 1 (ECDH), Level 2 (SSS)")
	fmt.Println("  - SupplementaryData: Level 1 (ECDH), Level 2 (PRE)")
	fmt.Println("  - Message: Level 1 (ECDH), Level 2 (PRE)")
	fmt.Println("  - FinalRecommendation: Level 1 (ECDH), Level 2 (PRE), Level 3 (MPC)")
	fmt.Println("  - EncryptionKey: Level 1 (PRE)")
	fmt.Println()
	fmt.Println("出版阶段 (PUBLICATION):")
	fmt.Println("  - Manuscript: Level 1 (ECDH), Level 2 (SSS)")
	fmt.Println("  - Message: Level 0 (Public)")
	fmt.Println("  - EncryptionKey: Level 1 (PRE)")
	fmt.Println()
}

// testRegisteredPolicyCombinations 测试已注册的策略组合
func testRegisteredPolicyCombinations(manager *data_policy.EnhancedDataPolicyManager) {
	// 根据 DataPolicyManager.go 中注册的策略，定义测试用例
	testCases := []struct {
		name     string
		phase    types.PublishingPhase
		dataType string
		level    types.DataSecurityLevel
	}{
		// 提交阶段
		{"提交阶段-Manuscript-Level1", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel1},
		{"提交阶段-Manuscript-Level2", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{"提交阶段-Message-Level1", types.PhaseSubmission, data_policy.DataTypeMessage, types.DataSecLevel1},
		{"提交阶段-Message-Level2", types.PhaseSubmission, data_policy.DataTypeMessage, types.DataSecLevel2},
		{"提交阶段-EncryptionKey-Level1", types.PhaseSubmission, data_policy.DataTypeEncryptionKey, types.DataSecLevel1},
		
		// 审稿阶段
		{"审稿阶段-Manuscript-Level1", types.PhaseReview, data_policy.DataTypeManuscript, types.DataSecLevel1},
		{"审稿阶段-Manuscript-Level2", types.PhaseReview, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{"审稿阶段-SupplementaryData-Level1", types.PhaseReview, data_policy.DataTypeSupplementaryData, types.DataSecLevel1},
		{"审稿阶段-SupplementaryData-Level2", types.PhaseReview, data_policy.DataTypeSupplementaryData, types.DataSecLevel2},
		{"审稿阶段-Message-Level1", types.PhaseReview, data_policy.DataTypeMessage, types.DataSecLevel1},
		{"审稿阶段-Message-Level2", types.PhaseReview, data_policy.DataTypeMessage, types.DataSecLevel2},
		{"审稿阶段-FinalRecommendation-Level1", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel1},
		{"审稿阶段-FinalRecommendation-Level2", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel2},
		{"审稿阶段-FinalRecommendation-Level3", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel3},
		{"审稿阶段-EncryptionKey-Level1", types.PhaseReview, data_policy.DataTypeEncryptionKey, types.DataSecLevel1},
		
		// 出版阶段
		{"出版阶段-Manuscript-Level1", types.PhasePublication, data_policy.DataTypeManuscript, types.DataSecLevel1},
		{"出版阶段-Manuscript-Level2", types.PhasePublication, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{"出版阶段-Message-Level0", types.PhasePublication, data_policy.DataTypeMessage, types.DataSecLevel0},
		{"出版阶段-EncryptionKey-Level1", types.PhasePublication, data_policy.DataTypeEncryptionKey, types.DataSecLevel1},
	}
	
	totalCombinations := len(testCases)
	successCount := 0
	failCount := 0
	
	fmt.Println("开始测试已注册的策略组合...")
	fmt.Println(strings.Repeat("=", 80))
	
	for _, testCase := range testCases {
		// 获取策略
		policy, err := manager.GetEncryptionPolicyWithLevel(testCase.phase, testCase.dataType, testCase.level)
		
		if err != nil {
			fmt.Printf("[失败] %-40s | Error: %v\n", testCase.name, err)
			failCount++
			continue
		}
		
		policyType := policy.GetPolicyType()
		fmt.Printf("[成功] %-40s | Policy: %s\n", testCase.name, policyType)
		successCount++
	}
	
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\n测试结果统计:\n")
	fmt.Printf("  总组合数: %d\n", totalCombinations)
	fmt.Printf("  成功数: %d\n", successCount)
	fmt.Printf("  失败数: %d\n", failCount)
	fmt.Printf("  成功率: %.2f%%\n", float64(successCount)/float64(totalCombinations)*100)
}

// makeTestPayload 生成指定字节的测试载荷；size<=0 时使用默认短字符串（约 80B）。
func makeTestPayload(size int) []byte {
	if size <= 0 {
		return []byte("这是一段测试数据，用于性能测试。This is test data for performance testing.")
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	return payload
}

// performanceTest64KBManuscript 64KB 载荷下 ECDH（Level1）与 SSS（Level2）专项测试。
func performanceTest64KBManuscript(manager *data_policy.EnhancedDataPolicyManager) {
	testData := makeTestPayload(manuscriptPayloadBytes)
	participants := []string{"participant1", "participant2", "participant3"}
	fmt.Printf("载荷大小: %d bytes (64 KB)\n", len(testData))

	cases := []struct {
		name       string
		phase      types.PublishingPhase
		dataType   string
		level      types.DataSecurityLevel
		iterations int
	}{
		{"64KB-稿件-ECDH-Level1 [ECDH_HKDF]", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel1, 100},
		{"64KB-稿件-SSS-Level2 [SSS]", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel2, 100},
	}

	for _, tc := range cases {
		fmt.Printf("\n执行测试用例: %s\n", tc.name)
		stats := runPerformanceTest(manager, tc.phase, tc.dataType, tc.level, tc.iterations, testData, participants)
		printPerformanceReport(tc.name, stats, len(testData))
	}
}

// performanceTest 性能测试
func performanceTest(manager *data_policy.EnhancedDataPolicyManager) {
	// 测试用例配置
	testCases := []struct {
		name       string
		phase      types.PublishingPhase
		dataType   string
		level      types.DataSecurityLevel
		iterations int
	}{
		{"提交阶段-稿件-Level1", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel1, 100},
		{"提交阶段-稿件-Level2", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel2, 100},
		{"提交阶段-消息-Level1", types.PhaseSubmission, data_policy.DataTypeMessage, types.DataSecLevel1, 100},
		{"提交阶段-消息-Level2", types.PhaseSubmission, data_policy.DataTypeMessage, types.DataSecLevel2, 100},
		{"提交阶段-密钥-Level1", types.PhaseSubmission, data_policy.DataTypeEncryptionKey, types.DataSecLevel1, 100},
		{"审稿阶段-稿件-Level1", types.PhaseReview, data_policy.DataTypeManuscript, types.DataSecLevel1, 100},
		{"审稿阶段-稿件-Level2", types.PhaseReview, data_policy.DataTypeManuscript, types.DataSecLevel2, 100},
		{"审稿阶段-补充数据-Level1", types.PhaseReview, data_policy.DataTypeSupplementaryData, types.DataSecLevel1, 100},
		{"审稿阶段-补充数据-Level2", types.PhaseReview, data_policy.DataTypeSupplementaryData, types.DataSecLevel2, 100},
		{"审稿阶段-消息-Level1", types.PhaseReview, data_policy.DataTypeMessage, types.DataSecLevel1, 100},
		{"审稿阶段-消息-Level2", types.PhaseReview, data_policy.DataTypeMessage, types.DataSecLevel2, 100},
		{"审稿阶段-最终建议-Level1", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel1, 100},
		{"审稿阶段-最终建议-Level2", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel2, 100},
		{"审稿阶段-最终建议-Level3", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel3, 100},
		{"审稿阶段-密钥-Level1", types.PhaseReview, data_policy.DataTypeEncryptionKey, types.DataSecLevel1, 100},
		{"出版阶段-稿件-Level1", types.PhasePublication, data_policy.DataTypeManuscript, types.DataSecLevel1, 100},
		{"出版阶段-稿件-Level2", types.PhasePublication, data_policy.DataTypeManuscript, types.DataSecLevel2, 100},
		{"出版阶段-消息-Level0", types.PhasePublication, data_policy.DataTypeMessage, types.DataSecLevel0, 100},
		{"出版阶段-密钥-Level1", types.PhasePublication, data_policy.DataTypeEncryptionKey, types.DataSecLevel1, 100},
	}
	
	// 测试数据（默认短载荷）
	testData := makeTestPayload(0)
	participants := []string{"participant1", "participant2", "participant3"}
	
	// 执行所有测试用例
	for _, testCase := range testCases {
		fmt.Printf("\n执行测试用例: %s\n", testCase.name)
		stats := runPerformanceTest(manager, testCase.phase, testCase.dataType, testCase.level, 
			testCase.iterations, testData, participants)
		printPerformanceReport(testCase.name, stats, len(testData))
	}
}

// runPerformanceTest 执行单个性能测试
func runPerformanceTest(manager *data_policy.EnhancedDataPolicyManager, 
	phase types.PublishingPhase, dataType string, level types.DataSecurityLevel,
	iterations int, testData []byte, participants []string) *PerformanceStats {
	
	stats := &PerformanceStats{
		TotalOps:    iterations,
		MinDuration: time.Hour, // 初始化为一个很大的值
		MaxDuration: 0,
		Durations:   make([]time.Duration, 0, iterations),
	}
	
	totalStartTime := time.Now()
	
	for i := 0; i < iterations; i++ {
		opStart := time.Now()
		
		// 获取策略
		policy, err := manager.GetEncryptionPolicyWithLevel(phase, dataType, level)
		if err != nil {
			stats.FailedOps++
			continue
		}
		
		// 加密数据
		encryptedData, metadata, err := manager.EncryptDataWithLevel(testData, phase, dataType, participants, level)
		if err != nil {
			stats.FailedOps++
			continue
		}
		
		// 解密数据（使用第一个参与者，使用相同的安全级别）
		if len(participants) > 0 {
			_, err = manager.DecryptDataWithLevel(encryptedData, metadata, phase, dataType, participants[0], level)
			if err != nil {
				stats.FailedOps++
				continue
			}
		}
		
		// 验证策略类型
		policyType := policy.GetPolicyType()
		if policyType == "" {
			stats.FailedOps++
			continue
		}
		
		opDuration := time.Since(opStart)
		stats.Durations = append(stats.Durations, opDuration)
		
		if opDuration < stats.MinDuration {
			stats.MinDuration = opDuration
		}
		if opDuration > stats.MaxDuration {
			stats.MaxDuration = opDuration
		}
		
		stats.SuccessOps++
	}
	
	stats.TotalDuration = time.Since(totalStartTime)
	
	return stats
}

// printPerformanceReport 打印性能测试报告
func printPerformanceReport(testCaseName string, stats *PerformanceStats, payloadBytes int) {
	successRate := 0.0
	if stats.TotalOps > 0 {
		successRate = float64(stats.SuccessOps) / float64(stats.TotalOps) * 100
	}
	
	avgDuration := time.Duration(0)
	if len(stats.Durations) > 0 {
		var sum time.Duration
		for _, d := range stats.Durations {
			sum += d
		}
		avgDuration = sum / time.Duration(len(stats.Durations))
	}
	
	fmt.Printf("\n【%s】性能测试报告\n", testCaseName)
	fmt.Println("=============================")
	fmt.Printf("载荷大小:     %d bytes\n", payloadBytes)
	fmt.Printf("总操作次数:   %d\n", stats.TotalOps)
	fmt.Printf("成功次数:     %d\n", stats.SuccessOps)
	fmt.Printf("失败次数:     %d\n", stats.FailedOps)
	fmt.Printf("成功率:       %.2f%%\n", successRate)
	fmt.Println("响应时间统计:")
	fmt.Printf("  总耗时:     %v\n", stats.TotalDuration)
	fmt.Printf("  平均耗时:   %v\n", avgDuration)
	fmt.Printf("  最小耗时:   %v\n", stats.MinDuration)
	fmt.Printf("  最大耗时:   %v\n", stats.MaxDuration)
	fmt.Printf("总经过时间:   %v\n", stats.TotalDuration)
	fmt.Println("=============================")
}

// policyRetrievalPerformanceTest 策略获取性能测试（所有策略组合合并为一个测试用例）
func policyRetrievalPerformanceTest(manager *data_policy.EnhancedDataPolicyManager) {
	// 测试用例配置（与加密测试保持一致）
	testCases := []struct {
		name     string
		phase    types.PublishingPhase
		dataType string
		level    types.DataSecurityLevel
	}{
		{"提交阶段-稿件-Level1", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel1},
		{"提交阶段-稿件-Level2", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{"提交阶段-消息-Level1", types.PhaseSubmission, data_policy.DataTypeMessage, types.DataSecLevel1},
		{"提交阶段-消息-Level2", types.PhaseSubmission, data_policy.DataTypeMessage, types.DataSecLevel2},
		{"提交阶段-密钥-Level1", types.PhaseSubmission, data_policy.DataTypeEncryptionKey, types.DataSecLevel1},
		{"审稿阶段-稿件-Level1", types.PhaseReview, data_policy.DataTypeManuscript, types.DataSecLevel1},
		{"审稿阶段-稿件-Level2", types.PhaseReview, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{"审稿阶段-补充数据-Level1", types.PhaseReview, data_policy.DataTypeSupplementaryData, types.DataSecLevel1},
		{"审稿阶段-补充数据-Level2", types.PhaseReview, data_policy.DataTypeSupplementaryData, types.DataSecLevel2},
		{"审稿阶段-消息-Level1", types.PhaseReview, data_policy.DataTypeMessage, types.DataSecLevel1},
		{"审稿阶段-消息-Level2", types.PhaseReview, data_policy.DataTypeMessage, types.DataSecLevel2},
		{"审稿阶段-最终建议-Level1", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel1},
		{"审稿阶段-最终建议-Level2", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel2},
		{"审稿阶段-最终建议-Level3", types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel3},
		{"审稿阶段-密钥-Level1", types.PhaseReview, data_policy.DataTypeEncryptionKey, types.DataSecLevel1},
		{"出版阶段-稿件-Level1", types.PhasePublication, data_policy.DataTypeManuscript, types.DataSecLevel1},
		{"出版阶段-稿件-Level2", types.PhasePublication, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{"出版阶段-消息-Level0", types.PhasePublication, data_policy.DataTypeMessage, types.DataSecLevel0},
		{"出版阶段-密钥-Level1", types.PhasePublication, data_policy.DataTypeEncryptionKey, types.DataSecLevel1},
	}
	
	// 每个策略组合的迭代次数
	iterationsPerCase := 100
	
	// 初始化统计信息
	stats := &PerformanceStats{
		TotalOps:    len(testCases) * iterationsPerCase,
		MinDuration: time.Hour, // 初始化为一个很大的值
		MaxDuration: 0,
		Durations:   make([]time.Duration, 0, len(testCases)*iterationsPerCase),
	}
	
	totalStartTime := time.Now()
	
	fmt.Printf("执行策略获取性能测试（共 %d 个策略组合，每个组合 %d 次迭代）...\n", len(testCases), iterationsPerCase)
	
	// 遍历所有测试用例，执行策略获取操作
	for _, testCase := range testCases {
		for i := 0; i < iterationsPerCase; i++ {
			opStart := time.Now()
			
			// 获取策略
			policy, err := manager.GetEncryptionPolicyWithLevel(testCase.phase, testCase.dataType, testCase.level)
			if err != nil {
				stats.FailedOps++
				continue
			}
			
			// 验证策略类型
			policyType := policy.GetPolicyType()
			if policyType == "" {
				stats.FailedOps++
				continue
			}
			
			opDuration := time.Since(opStart)
			stats.Durations = append(stats.Durations, opDuration)
			
			if opDuration < stats.MinDuration {
				stats.MinDuration = opDuration
			}
			if opDuration > stats.MaxDuration {
				stats.MaxDuration = opDuration
			}
			
			stats.SuccessOps++
		}
	}
	
	stats.TotalDuration = time.Since(totalStartTime)
	
	// 打印统一的性能报告
	printPerformanceReport("策略获取性能测试（所有策略组合）", stats, 0)
}

// securityWorkflowStep 8 步安全实验剖面中的一步（与 internal/data_policy/security_experiment_workflow.go 一致）。
type securityWorkflowStep struct {
	phase    types.PublishingPhase
	dataType string
	level    types.DataSecurityLevel
}

func securityExperimentWorkflowSteps() []securityWorkflowStep {
	return []securityWorkflowStep{
		{types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{types.PhaseSubmission, data_policy.DataTypeMessage, types.DataSecLevel2},
		{types.PhaseReview, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{types.PhaseReview, data_policy.DataTypeSupplementaryData, types.DataSecLevel2},
		{types.PhaseReview, data_policy.DataTypeMessage, types.DataSecLevel2},
		{types.PhaseReview, data_policy.DataTypeFinalRecommendation, types.DataSecLevel3},
		{types.PhasePublication, data_policy.DataTypeManuscript, types.DataSecLevel2},
		{types.PhasePublication, data_policy.DataTypeMessage, types.DataSecLevel0},
	}
}

// workflowPerfMode 工作流性能测试模式（与 security_experiment_test 基线 B1/B2 对齐）。
type workflowPerfMode int

const (
	workflowModeAdaptive workflowPerfMode = iota
	workflowModeB1UniformECDH
	workflowModeB2PhaseStaticL1
)

func makeParticipants(n int) []string {
	participants := make([]string, n)
	for i := 0; i < n; i++ {
		participants[i] = fmt.Sprintf("participant%d", i+1)
	}
	return participants
}

func avgDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum / time.Duration(len(durations))
}

// resolveWorkflowEncParams 将 workflow 一步映射为 Enc+Dec 使用的 (phase, dataType, level)。
func resolveWorkflowEncParams(step securityWorkflowStep, mode workflowPerfMode) (types.PublishingPhase, string, types.DataSecurityLevel) {
	switch mode {
	case workflowModeAdaptive:
		return step.phase, step.dataType, step.level
	case workflowModeB2PhaseStaticL1:
		return step.phase, step.dataType, types.DataSecLevel1
	case workflowModeB1UniformECDH:
		// 出版阶段 Message 仅注册 PUBLIC；均匀 ECDH 基线改用提交阶段 Message L1。
		if step.phase == types.PhasePublication && step.dataType == data_policy.DataTypeMessage {
			return types.PhaseSubmission, step.dataType, types.DataSecLevel1
		}
		return step.phase, step.dataType, types.DataSecLevel1
	default:
		return step.phase, step.dataType, step.level
	}
}

// runSingleEncDecRoundTrip 单次 Enc+Dec 往返；成功返回耗时，失败返回 error。
func runSingleEncDecRoundTrip(manager *data_policy.EnhancedDataPolicyManager,
	phase types.PublishingPhase, dataType string, level types.DataSecurityLevel,
	testData []byte, participants []string) (time.Duration, error) {

	start := time.Now()

	policy, err := manager.GetEncryptionPolicyWithLevel(phase, dataType, level)
	if err != nil {
		return 0, err
	}

	encryptedData, metadata, err := manager.EncryptDataWithLevel(testData, phase, dataType, participants, level)
	if err != nil {
		return 0, err
	}

	if len(participants) == 0 {
		return 0, fmt.Errorf("no participants")
	}

	_, err = manager.DecryptDataWithLevel(encryptedData, metadata, phase, dataType, participants[0], level)
	if err != nil {
		return 0, err
	}

	if policy.GetPolicyType() == "" {
		return 0, fmt.Errorf("empty policy type")
	}

	return time.Since(start), nil
}

// runWorkflowOnce 执行完整 8 步 workflow 一次，返回各步耗时之和。
func runWorkflowOnce(manager *data_policy.EnhancedDataPolicyManager,
	steps []securityWorkflowStep, mode workflowPerfMode,
	testData []byte, participants []string) (time.Duration, error) {

	var total time.Duration
	for _, step := range steps {
		phase, dataType, level := resolveWorkflowEncParams(step, mode)
		d, err := runSingleEncDecRoundTrip(manager, phase, dataType, level, testData, participants)
		if err != nil {
			return 0, fmt.Errorf("step %s/%s level %d: %w", phase, dataType, level, err)
		}
		total += d
	}
	return total, nil
}

// runWorkflowBenchmark 重复执行 workflow iterations 次。
func runWorkflowBenchmark(manager *data_policy.EnhancedDataPolicyManager,
	steps []securityWorkflowStep, mode workflowPerfMode,
	iterations int, testData []byte, participants []string) *PerformanceStats {

	stats := &PerformanceStats{
		TotalOps:    iterations,
		MinDuration: time.Hour,
		Durations:   make([]time.Duration, 0, iterations),
	}

	for i := 0; i < iterations; i++ {
		d, err := runWorkflowOnce(manager, steps, mode, testData, participants)
		if err != nil {
			stats.FailedOps++
			fmt.Printf("  [失败] iteration %d: %v\n", i+1, err)
			continue
		}
		stats.Durations = append(stats.Durations, d)
		if d < stats.MinDuration {
			stats.MinDuration = d
		}
		if d > stats.MaxDuration {
			stats.MaxDuration = d
		}
		stats.SuccessOps++
	}

	return stats
}

// performanceTestWorkflow 8 步 workflow 累计 Enc+Dec：Adaptive vs B1 vs B2。
func performanceTestWorkflow(manager *data_policy.EnhancedDataPolicyManager) {
	steps := securityExperimentWorkflowSteps()
	testData := makeTestPayload(0)
	participants := makeParticipants(3)
	const iterations = 100

	modes := []struct {
		name string
		mode workflowPerfMode
	}{
		{"Adaptive（自适应 8 步剖面）", workflowModeAdaptive},
		{"B1（均匀 ECDH，全程 Level1）", workflowModeB1UniformECDH},
		{"B2（阶段静态 Level1）", workflowModeB2PhaseStaticL1},
	}

	fmt.Printf("载荷: %d bytes | 参与者 n=3 | 每模式 %d 次完整 workflow\n", len(testData), iterations)
	fmt.Println(strings.Repeat("-", 80))

	var adaptiveMean time.Duration
	for _, m := range modes {
		stats := runWorkflowBenchmark(manager, steps, m.mode, iterations, testData, participants)
		mean := avgDuration(stats.Durations)
		if m.mode == workflowModeAdaptive {
			adaptiveMean = mean
		}
		fmt.Printf("%-32s | 成功 %d/%d | T_wf mean: %v (%.3f ms) | min: %v | max: %v\n",
			m.name, stats.SuccessOps, stats.TotalOps, mean, float64(mean)/float64(time.Millisecond),
			stats.MinDuration, stats.MaxDuration)
	}

	fmt.Println(strings.Repeat("-", 80))
	fmt.Println("论文 Table integration-overhead-min (a) 填入 T_wf mean (ms) 列")
	if adaptiveMean > 0 {
		fmt.Printf("Adaptive 相对 B1 增量 ΔT_int = T_adap - T_B1（负值表示自适应链下更省）\n")
	}
}

// performanceTestScaleN 64KB 稿件 Enc+Dec 随参与者数 n 扩展（ECDH L1 / SSS L2）。
func performanceTestScaleN(manager *data_policy.EnhancedDataPolicyManager) {
	testData := makeTestPayload(manuscriptPayloadBytes)
	const iterations = 100

	cases := []struct {
		name     string
		phase    types.PublishingPhase
		dataType string
		level    types.DataSecurityLevel
	}{
		{"ECDH [64KB Manuscript L1]", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel1},
		{"SSS [64KB Manuscript L2]", types.PhaseSubmission, data_policy.DataTypeManuscript, types.DataSecLevel2},
	}

	fmt.Printf("载荷: %d bytes (64 KB) | 每配置 %d 次 Enc+Dec\n", len(testData), iterations)
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-28s | n=3 (ms) | n=5 (ms) | n=7 (ms)\n", "Primitive")

	for _, tc := range cases {
		var means []float64
		for _, n := range []int{3, 5, 7} {
			participants := makeParticipants(n)
			stats := runPerformanceTest(manager, tc.phase, tc.dataType, tc.level, iterations, testData, participants)
			mean := avgDuration(stats.Durations)
			means = append(means, float64(mean)/float64(time.Millisecond))
		}
		fmt.Printf("%-28s | %8.3f | %8.3f | %8.3f\n", tc.name, means[0], means[1], means[2])
	}

	fmt.Println(strings.Repeat("-", 80))
	fmt.Println("论文 Table integration-overhead-min (b) 填入 ECDH / SSS 行")
}
