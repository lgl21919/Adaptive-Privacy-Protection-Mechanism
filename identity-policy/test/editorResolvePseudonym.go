func editorResolvePseudonym(ipm *EnhancedIdentityPolicyManager) {
    // 编辑需要知道审稿人的真实身份
    pseudonym := "reviewer_c8f2a1e9b5"
    
    realUserID, err := ipm.ResolvePseudonym(pseudonym, RoleEditor)
    if err != nil {
        fmt.Printf("解析失败: %v\n", err)
        return
    }
    
    fmt.Printf("伪名 %s 对应的真实用户: %s\n", pseudonym, realUserID)
    
    // 获取用户映射信息
    userMapping, _ := ipm.GetUserMapping(realUserID)
    fmt.Printf("用户链上身份: %s\n", userMapping.OnChainIdentity)
}