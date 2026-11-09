package main

import (
	"github.com/tap-thesis/privacy-protection-identity/internal/db"
	"github.com/tap-thesis/privacy-protection-identity/internal/utils"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	fmt.Println("=== 匿名集大小测量实验（Quantifying Anonymity）===")

	dbPath, err := resolveDBPath()
	if err != nil {
		log.Fatalf("定位数据库失败: %v", err)
	}
	fmt.Printf("使用数据库: %s\n", dbPath)

	_, err = db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer db.CloseDB()

	const threshold = 50
	const collapsePseudonyms = true

	report, err := utils.MeasureAnonymitySetSizes(threshold, collapsePseudonyms)
	if err != nil {
		log.Fatalf("计算匿名集失败: %v", err)
	}

	if len(report.Scenarios) == 0 {
		fmt.Println("未发现可用于统计的投稿/审稿阶段用户数据。")
		fmt.Println("请先运行身份管理流程生成 users 数据，例如：go run ./cmd/identity_manager")
		return
	}

	fmt.Printf("\n阈值设置: 匿名集大小 >= %d\n", threshold)
	fmt.Printf("统计口径: 在匿名/伪名可见场景下，将用户视作不可区分（collapsePseudonyms=%v）\n", collapsePseudonyms)
	fmt.Println("\n分场景统计结果：")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("阶段 | 审稿模式 | 角色 | 样本数 | 等价类数 | 最小匿名集 | 平均匿名集 | 最大匿名集 | 阈值通过率 | 是否整体达标")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, s := range report.Scenarios {
		tc := s.ThresholdCheck
		fmt.Printf("%s | %s | %s | %d | %d | %d | %.2f | %d | %.2f%% | %v\n",
			s.Phase, s.ReviewMode, s.Role, s.Population, s.EquivalenceGroups,
			tc.MinSetSize, tc.AvgSetSize, tc.MaxSetSize, tc.PassRate, tc.Passed)
	}

	fmt.Println("\n重点检查（双盲评审-审稿人）：")
	found := false
	for _, s := range report.Scenarios {
		phase := strings.ToUpper(strings.TrimSpace(s.Phase))
		mode := strings.ToUpper(strings.TrimSpace(s.ReviewMode))
		role := strings.ToUpper(strings.TrimSpace(s.Role))
		if phase == "REVIEW" && mode == "DOUBLE_BLIND" && role == "REVIEWER" {
			found = true
			if s.ThresholdCheck.Passed {
				fmt.Printf("✓ 达标：最小匿名集=%d >= %d\n", s.ThresholdCheck.MinSetSize, threshold)
			} else {
				fmt.Printf("✗ 未达标：最小匿名集=%d < %d（可通过扩大候选审稿池提升）\n", s.ThresholdCheck.MinSetSize, threshold)
			}
			break
		}
	}
	if !found {
		fmt.Println("未检测到双盲审稿人数据。请先准备 REVIEW + DOUBLE_BLIND + REVIEWER 样本。")
		fmt.Println("调试：当前 REVIEW 场景如下（phase | review_mode | role | population）")
		for _, s := range report.Scenarios {
			phase := strings.ToUpper(strings.TrimSpace(s.Phase))
			if phase == "REVIEW" {
				fmt.Printf("  %s | %s | %s | %d\n", s.Phase, s.ReviewMode, s.Role, s.Population)
			}
		}
	}
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

	// 如果没有找到已存在数据库，则回退到最常见位置（项目根目录下 cmd/identity_manager）
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
