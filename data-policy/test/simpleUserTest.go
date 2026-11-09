package main

import (
    "fmt"
    "log"
    "time"
)

// 简化的用户注册测试（不依赖Fabric SDK）
func main() {
    fmt.Println("=== 简化用户注册测试 ===")

    // 1. 初始化身份管理器
    identityManager := NewEnhancedIdentityPolicyManager()
    fmt.Println("✓ 身份管理器初始化成功")

    // 2. 创建模拟用户
    testUser := &User{
        UserID:      "testuser001",
        Name:        "张三",
        Email:       "zhangsan@university.edu.cn",
        Institution: "清华大学",
        Role:        RoleAuthor,
        Attributes: map[string]string{
            "department": "计算机科学与技术系",
            "position":   "博士研究生",
        },
        CreatedAt: time.Now().Format(time.RFC3339),
    }

    // 3. 在身份管理器中注册用户
    userMapping, err := identityManager.RegisterUser(testUser.UserID, testUser.Attributes)
    if err != nil {
        log.Fatalf("身份管理器注册失败: %v", err)
    }
    fmt.Printf("✓ 用户身份映射创建成功:\n")
    fmt.Printf("  - 链下用户ID: %s\n", userMapping.OffChainUserID)
    fmt.Printf("  - 链上身份: %s\n", userMapping.OnChainIdentity)
    fmt.Printf("  - 伪名基础: %s\n", userMapping.PseudonymBase)

    // 4. 测试不同阶段的身份生成
    phases := []PublishingPhase{PhaseSubmission, PhaseReview, PhasePublication}
    paperID := "paper_2024_001"

    for _, phase := range phases {
        phaseIdentity, err := identityManager.GetOrCreatePhaseIdentity(
            testUser.UserID,
            testUser.Role,
            phase,
            paperID,
            nil,
        )
        if err != nil {
            log.Printf("阶段身份生成失败 (%s): %v", phase, err)
            continue
        }

        fmt.Printf("✓ %s阶段身份:\n", phase)
        fmt.Printf("  - 伪名: %s\n", phaseIdentity.Pseudonym)
        fmt.Printf("  - 可见性: %s\n", phaseIdentity.Visibility)
        fmt.Printf("  - 阶段: %s\n", phaseIdentity.Phase)
    }

    // 5. 测试身份一致性验证
    phaseIdentity1, _ := identityManager.GetOrCreatePhaseIdentity(
        testUser.UserID, testUser.Role, PhaseReview, paperID, nil,
    )
    phaseIdentity2, _ := identityManager.GetOrCreatePhaseIdentity(
        testUser.UserID, testUser.Role, PhaseReview, paperID, nil,
    )

    if phaseIdentity1.Pseudonym == phaseIdentity2.Pseudonym {
        fmt.Printf("✓ 身份一致性验证通过: %s\n", phaseIdentity1.Pseudonym)
    } else {
        fmt.Printf("✗ 身份一致性验证失败\n")
    }

    // 6. 测试用户映射查询
    retrievedMapping, err := identityManager.GetUserMapping(testUser.UserID)
    if err != nil {
        log.Printf("用户映射查询失败: %v", err)
    } else {
        fmt.Printf("✓ 用户映射查询成功: %s -> %s\n", 
            retrievedMapping.OffChainUserID, retrievedMapping.OnChainIdentity)
    }

    // 7. 测试身份历史记录
    history, err := identityManager.GetPhaseIdentityHistory(testUser.UserID)
    if err != nil {
        log.Printf("身份历史查询失败: %v", err)
    } else {
        fmt.Printf("✓ 用户身份历史记录 (%d条):\n", len(history))
        for i, identity := range history {
            fmt.Printf("  %d. %s阶段 - %s\n", i+1, identity.Phase, identity.Pseudonym)
        }
    }

    fmt.Println("\n=== 测试完成 ===")
    fmt.Println("说明: 此测试验证了身份管理的核心功能，包括:")
    fmt.Println("- 用户身份映射创建")
    fmt.Println("- 阶段特定身份生成")
    fmt.Println("- 身份一致性保证")
    fmt.Println("- 身份查询和历史记录")
    fmt.Println("\n如需测试完整的Fabric CA集成，请先解决SDK依赖问题。")
}