// 作者投稿阶段
func authorSubmissionExample(ipm *EnhancedIdentityPolicyManager) {
    phaseIdentity, err := ipm.GetOrCreatePhaseIdentity(
        "zhang_prof_001",
        RoleAuthor,
        PhaseSubmission,
        "paper_2024_001",
        nil,
    )
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("投稿阶段身份: %s (可见性: %s)\n", 
        phaseIdentity.Pseudonym, phaseIdentity.Visibility)
    // 输出: 投稿阶段身份: user_a1b2c3d4e5f6 (可见性: REAL_IDENTITY)
}

// 同一作者同一论文的审稿阶段
func authorReviewPhaseExample(ipm *EnhancedIdentityPolicyManager) {
    phaseIdentity, err := ipm.GetOrCreatePhaseIdentity(
        "zhang_prof_001", 
        RoleAuthor,
        PhaseReview,
        "paper_2024_001",
        nil,
    )
    
    fmt.Printf("审稿阶段身份: %s (可见性: %s)\n",
        phaseIdentity.Pseudonym, phaseIdentity.Visibility)
    // 输出: 审稿阶段身份: author_c8f2a1e9b5 (可见性: PSEUDONYMOUS)
}

// 验证一致性
func verifyConsistencyExample(ipm *EnhancedIdentityPolicyManager) {
    // 同一用户在相同上下文中应该得到相同的伪名
    phaseIdentity1, _ := ipm.GetOrCreatePhaseIdentity("zhang_prof_001", RoleAuthor, PhaseReview, "paper_2024_001", nil)
    phaseIdentity2, _ := ipm.GetOrCreatePhaseIdentity("zhang_prof_001", RoleAuthor, PhaseReview, "paper_2024_001", nil)
    
    fmt.Printf("身份一致性: %t\n", phaseIdentity1.Pseudonym == phaseIdentity2.Pseudonym)
    // 输出: 身份一致性: true
}