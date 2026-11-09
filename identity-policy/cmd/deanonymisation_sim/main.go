package main

import (
	"github.com/tap-thesis/privacy-protection-identity/internal/db"
	"github.com/tap-thesis/privacy-protection-identity/internal/utils"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	fmt.Println("=== 去匿名化攻击模拟（Simulated Deanonymisation Attacks）===")
	fmt.Println("场景：元数据关联（机构/邮箱域/组合泄露）、审稿阶段双盲↔单盲跨模式关联（审稿人）")
	fmt.Println()

	dbPath, err := resolveDBPath()
	if err != nil {
		log.Fatalf("定位数据库失败: %v", err)
	}
	fmt.Printf("使用数据库: %s\n\n", dbPath)

	if _, err := db.InitDB(dbPath); err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer db.CloseDB()

	realResults, synthRows, err := utils.RunDeanonymisationSimulationFromDB(true)
	if err != nil {
		log.Fatalf("模拟失败: %v", err)
	}

	fmt.Println("--- A. 基于真实库：双盲审稿人队列（REVIEW + DOUBLE_BLIND + REVIEWER）---")
	cohortPrinted := false
	for _, r := range realResults {
		if isCrossPhaseScenario(r.Scenario) {
			continue
		}
		cohortPrinted = true
		printAttackResult(r)
	}
	if !cohortPrinted {
		fmt.Println("（无双盲审稿人记录：元数据攻击统计为空。可先在 users 表写入 REVIEW/DOUBLE_BLIND/REVIEWER 样本。）")
	}

	fmt.Println("--- B. 基于真实库：审稿阶段跨模式侧信道（双盲↔单盲，仅审稿人；链下ID/链上身份/阶段伪名）---")
	for _, r := range realResults {
		if isCrossPhaseScenario(r.Scenario) {
			printAttackResult(r)
		}
	}

	fmt.Println("--- C. 合成模拟 + 真实库对照：机构×域名组合下的元数据碰撞 ---")
	fmt.Println("说明：前 3 行为蒙特卡洛（随机 institution_slot×domain_slot）；")
	fmt.Println("第 4 行为真实库双盲审稿人队列，按组合元数据键（与 METADATA_COMBINED_LEAK 一致）做一次统计；")
	fmt.Println("「机构槽位数」「域名槽位数」在真实库行中表示该队列内互异非空的机构键 / 域名键个数。")
	fmt.Println()
	fmt.Println("审稿人数 | 机构槽位数 | 域名槽位数 | 平均去匿名率% | 平均歧义率% | 平均候选集大小 | 数据来源")
	for _, row := range synthRows {
		src := "蒙特卡洛"
		if row.Source == utils.SynthRowSourceRealDBCombined {
			src = "真实库"
		}
		fmt.Printf("%9d | %11d | %11d | %13.2f | %11.2f | %17.3f | %s\n",
			row.NumReviewers, row.NumInstitutionSlots, row.NumDomainSlots,
			row.AvgDeanonymRate, row.AvgAmbiguousRate, row.AvgAvgCandidates, src)
	}

	fmt.Println()
	fmt.Println("结果解读：机构/域名槽位越少，元数据碰撞后唯一识别比例越高，匿名性越弱；")
	fmt.Println("跨模式关联率反映同一审稿人标识若在双盲与单盲两种审稿模式下均可观测并一致，则存在跨模式去匿名风险。")
}

func printAttackResult(r utils.DeanonymisationAttackResult) {
	fmt.Printf("场景: %s\n", r.Scenario)
	fmt.Printf("  队列: %s | 队列大小=%d\n", r.CohortDescription, r.CohortSize)
	fmt.Printf("  有效评估目标=%d | 唯一缩小(候选=1)=%d | 歧义(候选>1)=%d | 无元数据信号=%d\n",
		r.EvaluatedTargets, r.UniqueMatchCount, r.AmbiguousCount, r.NoSignalCount)
	if r.EvaluatedTargets > 0 {
		fmt.Printf("  队列内去匿名成功率: %.2f%% | 歧义比例: %.2f%% | 平均候选集大小: %.3f\n",
			r.DeanonymisationRate, r.AmbiguousRate, r.AvgCandidateSetSize)
	} else if !isCrossPhaseScenario(r.Scenario) {
		fmt.Println("  （无带元数据的评估目标）")
	}
	if isCrossPhaseScenario(r.Scenario) && r.CohortSize > 0 {
		fmt.Printf("  双盲侧互异键中可在单盲侧再次观测的比例: %.2f%% (%d/%d)\n",
			r.DeanonymisationRate, r.UniqueMatchCount, r.CohortSize)
	}
	fmt.Println()
}

func isCrossPhaseScenario(s utils.AttackScenarioName) bool {
	return s == utils.ScenarioCrossPhaseLinkage ||
		s == utils.ScenarioCrossPhaseOnChainIdentity ||
		s == utils.ScenarioCrossPhasePhasePseudonym
}

func resolveDBPath() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("获取当前目录失败: %w", err)
	}
	candidates := []string{
		filepath.Join(wd, "cmd", "identity_manager", "academic_publishing.db"),
		filepath.Join(wd, "identity_manager", "academic_publishing.db"),
		filepath.Join(wd, "..", "identity_manager", "academic_publishing.db"),
		filepath.Join(wd, "academic_publishing.db"),
	}
	for _, p := range candidates {
		abs, absErr := filepath.Abs(p)
		if absErr != nil {
			continue
		}
		if stat, statErr := os.Stat(abs); statErr == nil && !stat.IsDir() {
			return abs, nil
		}
	}
	fallback := candidates[0]
	absFallback, absErr := filepath.Abs(fallback)
	if absErr != nil {
		return "", fmt.Errorf("解析数据库路径失败: %w", absErr)
	}
	if mkErr := os.MkdirAll(filepath.Dir(absFallback), 0755); mkErr != nil {
		return "", fmt.Errorf("创建数据库目录失败: %w", mkErr)
	}
	return absFallback, nil
}
