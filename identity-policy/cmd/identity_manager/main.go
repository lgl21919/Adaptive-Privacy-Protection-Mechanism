package main

import (
	"github.com/tap-thesis/privacy-protection-identity/internal/blockchain"
	"github.com/tap-thesis/privacy-protection-identity/internal/db"
	"github.com/tap-thesis/privacy-protection-identity/internal/utils"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== 学术出版系统 - 用户身份信息上链 ===")

	// 初始化数据库
	_, err := db.InitDB("./academic_publishing.db")
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer db.CloseDB()

	// 新增批量审稿人：
	// 固定40人审稿人池；每种模式随机抽取20人（模式内不重复，模式间允许重叠）
	added, err := ensureAdditionalReviewersByPool(40, 20)
	if err != nil {
		log.Fatalf("新增审稿人失败: %v", err)
	}
	fmt.Printf("✓ 已补充审稿人记录: %d 条（REVIEW阶段，三种模式）\n", added)

	// 为当前双盲审稿人（REVIEW + DOUBLE_BLIND + REVIEWER）最多 20 人各建一条出版阶段镜像，用于跨阶段去匿名模拟验证
	pubMirrors, err := ensurePublicationMirrorsForDoubleBlindReviewers(20)
	if err != nil {
		log.Fatalf("补充出版阶段镜像失败: %v", err)
	}
	fmt.Printf("✓ 已为双盲审稿人补充出版阶段镜像记录: %d 条（与审稿记录链下/链上/伪名字段一致）\n", pubMirrors)

	// 初始化身份策略区块链客户端（使用Org1 User身份）
	fmt.Println("\n初始化身份策略区块链客户端（Org1 User）...")
	identityPolicyClient, err := blockchain.NewIdentityPolicyClient("basic")
	if err != nil {
		log.Fatalf("初始化身份策略区块链客户端失败: %v", err)
	}
	defer identityPolicyClient.Close()
	fmt.Println("✓ 身份策略区块链客户端初始化成功")

	// 从数据库读取所有用户信息
	fmt.Println("\n从数据库读取用户信息...")
	users, err := db.GetAllUsers()
	if err != nil {
		log.Fatalf("从数据库读取用户信息失败: %v", err)
	}

	if len(users) == 0 {
		log.Fatalf("数据库中没有任何用户信息，请先运行用户注册程序")
	}

	fmt.Printf("找到 %d 条用户记录\n", len(users))

	// 创建性能统计对象
	perfStats := utils.NewPerformanceStats("用户身份信息上链")

	// 将用户信息上链
	fmt.Println("\n开始将用户信息上链...")
	fmt.Println(strings.Repeat("=", 80))

	for i, userInfo := range users {
		fmt.Printf("\n[%d/%d] 处理用户: %s (阶段: %s, 角色: %s)\n",
			i+1, len(users), userInfo.OffChainID, userInfo.Phase, userInfo.Role)

		// 记录开始时间
		startTime := time.Now()

		// 执行上链操作
		err := identityPolicyClient.SaveUserIdentity(userInfo)

		// 计算耗时
		duration := time.Since(startTime)

		if err != nil {
			log.Printf("  ✗ 上链失败: %v (耗时: %v)", err, duration)
			perfStats.RecordFailure(duration)
		} else {
			fmt.Printf("  ✓ 上链成功 (耗时: %v)\n", duration)
			perfStats.RecordSuccess(duration)
		}
	}

	// 打印性能统计报告
	perfStats.PrintSummary()

	fmt.Println("\n=== 上链完成 ===")
}

func ensureAdditionalReviewersByPool(poolSize, perModeCount int) (int, error) {
	if poolSize <= 0 || perModeCount <= 0 {
		return 0, nil
	}
	if perModeCount > poolSize {
		return 0, fmt.Errorf("每种模式抽取人数(%d)不能超过审稿人池规模(%d)", perModeCount, poolSize)
	}

	modes := []string{
		"DOUBLE_BLIND",
		"SINGLE_BLIND",
		"OPEN",
	}

	// 固定审稿人池（总集合40人）
	pool := make([]db.UserIdentityInfo, 0, poolSize)
	for i := 1; i <= poolSize; i++ {
		username := fmt.Sprintf("reviewer_pool_%03d", i)
		offChainID := fmt.Sprintf("reviewer_pool_%03d@example.edu", i)
		pool = append(pool, db.UserIdentityInfo{
			Username:        username,
			OffChainID:      offChainID,
			OnChainIdentity: fmt.Sprintf("reviewer_pool_identity_%03d", i),
			PseudonymBase:   fmt.Sprintf("reviewer_pool_base_%03d", i),
			Role:            "REVIEWER",
			Phase:           "REVIEW",
			Attributes: map[string]string{
				"institution": "Reviewer Pool University",
				"email":       offChainID,
				"expertise":   "blockchain privacy",
				"source":      "random_pool_for_experiment",
			},
		})
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	added := 0
	for _, mode := range modes {
		perm := rng.Perm(poolSize)
		for i := 0; i < perModeCount; i++ {
			baseUser := pool[perm[i]]
			user := baseUser
			user.ReviewMode = mode
			user.PhasePseudonym = fmt.Sprintf("reviewer_pool_pseudo_%03d_%s", perm[i]+1, strings.ToLower(mode))
			if err := db.SavePhaseUser(user); err != nil {
				return added, err
			}
			added++
		}
	}

	return added, nil
}

// ensurePublicationMirrorsForDoubleBlindReviewers 为数据库中已有的双盲审稿人各写入一条 PUBLICATION 阶段记录。
// 主键为 (off_chain_id, phase, review_mode)：审稿行为 REVIEW+DOUBLE_BLIND；镜像行为 PUBLICATION+review_mode 空串。
// 身份字段与审稿行保持一致，便于 deanonymisation_sim 中审稿↔出版跨阶段关联检出。
func ensurePublicationMirrorsForDoubleBlindReviewers(limit int) (int, error) {
	all, err := db.GetAllUsers()
	if err != nil {
		return 0, err
	}
	var candidates []db.UserIdentityInfo
	for _, u := range all {
		ph := strings.ToUpper(strings.TrimSpace(u.Phase))
		mode := strings.ToUpper(strings.TrimSpace(u.ReviewMode))
		role := strings.ToUpper(strings.TrimSpace(u.Role))
		if ph == "REVIEW" && mode == "DOUBLE_BLIND" && role == "REVIEWER" {
			candidates = append(candidates, u)
		}
	}
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	added := 0
	for _, src := range candidates {
		pub := src
		pub.Phase = "PUBLICATION"
		pub.ReviewMode = ""
		if src.Attributes != nil {
			attrs := make(map[string]string, len(src.Attributes)+1)
			for k, v := range src.Attributes {
				attrs[k] = v
			}
			attrs["experiment_mirror"] = "double_blind_review_to_publication"
			pub.Attributes = attrs
		} else {
			pub.Attributes = map[string]string{
				"experiment_mirror": "double_blind_review_to_publication",
			}
		}
		if err := db.SavePhaseUser(pub); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}
