package main
func main() {
    ipm := NewEnhancedIdentityPolicyManager()
    
    // 用户注册
    userAttributes := map[string]string{
        "name":        "张教授",
        "institution": "清华大学",
        "email":       "zhang@tsinghua.edu.cn",
        "expertise":   "区块链,密码学",
    }
    
    mapping, err := ipm.RegisterUser("zhang_prof_001", userAttributes)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("链上身份: %s\n", mapping.OnChainIdentity)
    fmt.Printf("伪名基础: %s\n", mapping.PseudonymBase)
}