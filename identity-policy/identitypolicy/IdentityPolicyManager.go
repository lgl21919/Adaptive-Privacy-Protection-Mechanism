package identitypolicy

import (
    "crypto/sha256"
    "encoding/hex"
    //"encoding/json"
    "privacy-protection/adaptive/pkg/context"
    "privacy-protection/adaptive/pkg/reasoning"
    "github.com/tap-thesis/privacy-protection-identity/pkg/types"
    "fmt"
    "sync"
    "time"
)

// UserIdentityMapping 链下与链上身份映射
type UserIdentityMapping struct {
    OffChainUserID string    `json:"offChainUserID"` // 链下真实身份ID
    OnChainIdentity string   `json:"onChainIdentity"` // 链上固定身份
    PseudonymBase   string   `json:"pseudonymBase"`   // 伪名生成基础
    CreatedAt       time.Time `json:"createdAt"`
    LastAccessed    time.Time `json:"lastAccessed"`
}

// PhaseSpecificIdentity 阶段特定身份
type PhaseSpecificIdentity struct {
    Phase           types.PublishingPhase `json:"phase"`
    PaperID         string          `json:"paperID"`
    Pseudonym       string          `json:"pseudonym"`
    Visibility      types.IdentityVisibility `json:"visibility"`
    ContextHash     string          `json:"contextHash"` // 上下文哈希，确保一致性
}

// EnhancedIdentityPolicyManager 增强的身份策略管理器
type EnhancedIdentityPolicyManager struct {
    policies []types.IdentityPolicy
    // 身份映射存储
    userMappings      map[string]*UserIdentityMapping    // offChainUserID -> UserIdentityMapping
    phaseIdentities   map[string]*PhaseSpecificIdentity  // contextHash -> PhaseSpecificIdentity
    pseudonymRegistry map[string]string                  // pseudonym -> offChainUserID (仅编辑可访问)
    adaptive          *reasoning.AdaptiveCoordinator     // 上下文感知 + 逻辑推理引擎
    mutex             sync.RWMutex
}

func NewEnhancedIdentityPolicyManager() *EnhancedIdentityPolicyManager {
    return &EnhancedIdentityPolicyManager{
        policies: []types.IdentityPolicy{
            // 投稿阶段策略
            {Phase: types.PhaseSubmission, Role: types.RoleAuthor, RequiredVisibility: types.VisibilityReal, 
             Description: "作者在投稿时必须使用真实身份"},
            {Phase: types.PhaseSubmission, Role: types.RoleEditor, RequiredVisibility: types.VisibilityReal, 
             Description: "编辑在处理投稿时使用真实身份"},
            
            // 审稿阶段策略 - 双盲模式
            {Phase: types.PhaseReview, Role: types.RoleAuthor, RequiredVisibility: types.VisibilityPseudonym, 
             Description: "作者在双盲审稿阶段使用伪名", ReviewMode: types.ReviewModeDoubleBlind},
            {Phase: types.PhaseReview, Role: types.RoleReviewer, RequiredVisibility: types.VisibilityPseudonym, 
             Description: "审稿人在双盲评审中使用伪名", ReviewMode: types.ReviewModeDoubleBlind},
            {Phase: types.PhaseReview, Role: types.RoleEditor, RequiredVisibility: types.VisibilityReal, 
             Description: "编辑在双盲审稿管理中使用真实身份", ReviewMode: types.ReviewModeDoubleBlind},
            
            // 审稿阶段策略 - 单盲模式
            {Phase: types.PhaseReview, Role: types.RoleAuthor, RequiredVisibility: types.VisibilityReal, 
             Description: "作者在单盲审稿阶段使用真实身份", ReviewMode: types.ReviewModeSingleBlind},
            {Phase: types.PhaseReview, Role: types.RoleReviewer, RequiredVisibility: types.VisibilityPseudonym, 
             Description: "审稿人在单盲评审中使用伪名", ReviewMode: types.ReviewModeSingleBlind},
            {Phase: types.PhaseReview, Role: types.RoleEditor, RequiredVisibility: types.VisibilityReal, 
             Description: "编辑在单盲审稿管理中使用真实身份", ReviewMode: types.ReviewModeSingleBlind},
            
            // 审稿阶段策略 - 开放模式
            {Phase: types.PhaseReview, Role: types.RoleAuthor, RequiredVisibility: types.VisibilityReal, 
             Description: "作者在开放审稿阶段使用真实身份", ReviewMode: types.ReviewModeOpen},
            {Phase: types.PhaseReview, Role: types.RoleReviewer, RequiredVisibility: types.VisibilityReal, 
             Description: "审稿人在开放评审中使用真实身份", ReviewMode: types.ReviewModeOpen},
            {Phase: types.PhaseReview, Role: types.RoleEditor, RequiredVisibility: types.VisibilityReal, 
             Description: "编辑在开放审稿管理中使用真实身份", ReviewMode: types.ReviewModeOpen},
            
            // 出版阶段策略
            {Phase: types.PhasePublication, Role: types.RoleAuthor, RequiredVisibility: types.VisibilityReal, 
             Description: "出版时公开作者真实身份"},
            {Phase: types.PhasePublication, Role: types.RoleReviewer, RequiredVisibility: types.VisibilityReal, 
             Description: "可选择公开致谢审稿人"},
            {Phase: types.PhasePublication, Role: types.RoleEditor, RequiredVisibility: types.VisibilityReal, 
             Description: "出版时公开编辑真实身份"},
        },
        userMappings:      make(map[string]*UserIdentityMapping),
        phaseIdentities:   make(map[string]*PhaseSpecificIdentity),
        pseudonymRegistry: make(map[string]string),
        adaptive:          loadAdaptiveCoordinator(),
    }
}

// RegisterUser 注册用户并创建链上身份映射
func (ipm *EnhancedIdentityPolicyManager) RegisterUser(offChainUserID string, userAttributes map[string]string) (*UserIdentityMapping, error) {
    ipm.mutex.Lock()
    defer ipm.mutex.Unlock()

    // 检查用户是否已注册
    if existing, exists := ipm.userMappings[offChainUserID]; exists {
        existing.LastAccessed = time.Now()
        return existing, nil
    }

    // 生成链上固定身份
    onChainIdentity := ipm.generateOnChainIdentity(offChainUserID, userAttributes)
    
    // 生成伪名基础
    pseudonymBase := ipm.generatePseudonymBase(offChainUserID)

    // 创建映射
    mapping := &UserIdentityMapping{
        OffChainUserID: offChainUserID,
        OnChainIdentity: onChainIdentity,
        PseudonymBase:   pseudonymBase,
        CreatedAt:       time.Now(),
        LastAccessed:    time.Now(),
    }

    // 存储映射
    ipm.userMappings[offChainUserID] = mapping
    ipm.pseudonymRegistry[onChainIdentity] = offChainUserID

    return mapping, nil
}

// GetOrCreatePhaseIdentity 获取或创建阶段特定身份
// reviewMode 参数：审稿阶段必须提供，其他阶段可以为空字符串
func (ipm *EnhancedIdentityPolicyManager) GetOrCreatePhaseIdentity(
    offChainUserID string,
    userRole types.UserRole,
    phase types.PublishingPhase,
    paperID string,
    contextAttributes map[string]string,
    reviewMode types.ReviewMode,
) (*PhaseSpecificIdentity, error) {
    ipm.mutex.Lock()
    defer ipm.mutex.Unlock()

    // 验证用户是否已注册
    userMapping, exists := ipm.userMappings[offChainUserID]
    if !exists {
        return nil, fmt.Errorf("user not registered: %s", offChainUserID)
    }

    // 如果是审稿阶段，验证 reviewMode 是否提供
    if phase == types.PhaseReview && reviewMode == "" {
        return nil, fmt.Errorf("review mode is required for review phase")
    }

    // 生成上下文哈希（包含审稿模式，如果是审稿阶段）
    contextHash := ipm.generateContextHash(offChainUserID, phase, paperID, userRole, reviewMode)
    
    // 检查是否已存在阶段身份
    if phaseIdentity, exists := ipm.phaseIdentities[contextHash]; exists {
        phaseIdentity.Visibility = ipm.GetVisibilityPolicy(phase, userRole, reviewMode)
        return phaseIdentity, nil
    }

    // 获取可见性策略
    visibility := ipm.GetVisibilityPolicy(phase, userRole, reviewMode)

    // 根据策略生成相应的身份标识
    var pseudonym string
    switch visibility {
    case types.VisibilityReal:
        pseudonym = userMapping.OnChainIdentity // 使用链上固定身份
        
    case types.VisibilityPseudonym:
        pseudonym = ipm.generateDeterministicPseudonym(userMapping.PseudonymBase, phase, paperID, userRole)
        // 注册伪名映射（仅编辑可解析）
        ipm.pseudonymRegistry[pseudonym] = offChainUserID
        
    case types.VisibilityAnonymous:
        pseudonym = ipm.generateAnonymousIdentity(phase, paperID, userRole)
        // 匿名身份不注册映射
    }

    // 创建阶段身份
    phaseIdentity := &PhaseSpecificIdentity{
        Phase:       phase,
        PaperID:     paperID,
        Pseudonym:   pseudonym,
        Visibility:  visibility,
        ContextHash: contextHash,
    }

    // 存储阶段身份
    ipm.phaseIdentities[contextHash] = phaseIdentity
    userMapping.LastAccessed = time.Now()

    return phaseIdentity, nil
}

// generateOnChainIdentity 生成链上固定身份
func (ipm *EnhancedIdentityPolicyManager) generateOnChainIdentity(offChainUserID string, attributes map[string]string) string {
    // 基于链下ID和关键属性生成确定性链上身份
    data := offChainUserID
    if institution, exists := attributes["institution"]; exists {
        data += "|" + institution
    }
    if email, exists := attributes["email"]; exists {
        data += "|" + email
    }
    
    hash := sha256.Sum256([]byte(data))
    return "user_" + hex.EncodeToString(hash[:12]) // 截取前12字节
}

// generatePseudonymBase 生成伪名基础
func (ipm *EnhancedIdentityPolicyManager) generatePseudonymBase(offChainUserID string) string {
    hash := sha256.Sum256([]byte(offChainUserID + "|pseudonym_base"))
    return hex.EncodeToString(hash[:16])
}

// generateDeterministicPseudonym 生成确定性伪名
func (ipm *EnhancedIdentityPolicyManager) generateDeterministicPseudonym(
    pseudonymBase string,
    phase types.PublishingPhase,
    paperID string,
    role types.UserRole,
) string {
    // 基于基础伪名+阶段+论文+角色生成确定性伪名
    context := fmt.Sprintf("%s|%s|%s", phase, paperID, role)
    data := pseudonymBase + "|" + context
    
    hash := sha256.Sum256([]byte(data))
    
    // 根据角色生成不同的前缀
    prefix := "user"
    switch role {
    case types.RoleAuthor:
        prefix = "author"
    case types.RoleReviewer:
        prefix = "reviewer"
    case types.RoleEditor:
        prefix = "editor"
    }
    
    return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(hash[:10]))
}

// generateAnonymousIdentity 生成匿名身份
func (ipm *EnhancedIdentityPolicyManager) generateAnonymousIdentity(
    phase types.PublishingPhase,
    paperID string,
    role types.UserRole,
) string {
    // 生成完全随机的匿名身份
    randomData := fmt.Sprintf("%s|%s|%s|%d", phase, paperID, role, time.Now().UnixNano())
    hash := sha256.Sum256([]byte(randomData))
    return "anon_" + hex.EncodeToString(hash[:8])
}

// generateContextHash 生成上下文哈希
func (ipm *EnhancedIdentityPolicyManager) generateContextHash(
    offChainUserID string,
    phase types.PublishingPhase,
    paperID string,
    role types.UserRole,
    reviewMode types.ReviewMode,
) string {
    // 如果是审稿阶段，将审稿模式包含在哈希中
    if phase == types.PhaseReview {
        data := fmt.Sprintf("%s|%s|%s|%s|%s", offChainUserID, phase, paperID, role, reviewMode)
        hash := sha256.Sum256([]byte(data))
        return hex.EncodeToString(hash[:])
    }
    // 非审稿阶段，不包含审稿模式
    data := fmt.Sprintf("%s|%s|%s|%s", offChainUserID, phase, paperID, role)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// GetVisibilityPolicy 获取身份可见性策略（自适应：Context-Awareness + Logical Reasoning）
func (ipm *EnhancedIdentityPolicyManager) GetVisibilityPolicy(phase types.PublishingPhase, role types.UserRole, reviewMode types.ReviewMode) types.IdentityVisibility {
    if ipm.adaptive != nil {
        dec, err := ipm.adaptive.EvaluateIdentityPolicy(context.ContextInput{
            Phase:      string(phase),
            Role:       string(role),
            ReviewMode: string(reviewMode),
        })
        if err == nil && dec.IAPPStrategy != "" {
            return mapIAPPToVisibility(dec.IAPPStrategy)
        }
    }
    return ipm.getVisibilityPolicyLegacy(phase, role, reviewMode)
}

// getVisibilityPolicyLegacy 回退至内置策略表（无自适应配置时）
func (ipm *EnhancedIdentityPolicyManager) getVisibilityPolicyLegacy(phase types.PublishingPhase, role types.UserRole, reviewMode types.ReviewMode) types.IdentityVisibility {
    for _, policy := range ipm.policies {
        if policy.Phase == phase && policy.Role == role {
            // 如果是审稿阶段，需要匹配审稿模式
            if phase == types.PhaseReview {
                if policy.ReviewMode == reviewMode {
                    return policy.RequiredVisibility
                }
            } else {
                // 非审稿阶段，直接返回匹配的策略
                return policy.RequiredVisibility
            }
        }
    }
    return types.VisibilityAnonymous // 默认匿名
}

// EvaluateAdaptivePolicy 暴露 IAPP 自适应决策（Context-Awareness + Logical Reasoning）
func (ipm *EnhancedIdentityPolicyManager) EvaluateAdaptivePolicy(phase types.PublishingPhase, role types.UserRole, reviewMode types.ReviewMode) (*reasoning.PolicyDecision, error) {
    if ipm.adaptive == nil {
        return nil, fmt.Errorf("adaptive coordinator not initialized")
    }
    return ipm.adaptive.EvaluateIdentityPolicy(context.ContextInput{
        Phase:      string(phase),
        Role:       string(role),
        ReviewMode: string(reviewMode),
    })
}

// GetIdentityPolicy 获取完整的身份策略信息
// 输入参数与 GetOrCreatePhaseIdentity 函数相同
func (ipm *EnhancedIdentityPolicyManager) GetIdentityPolicy(
    offChainUserID string,
    userRole types.UserRole,
    phase types.PublishingPhase,
    paperID string,
    contextAttributes map[string]string,
    reviewMode types.ReviewMode,
) (*types.IdentityPolicy, error) {
    ipm.mutex.RLock()
    defer ipm.mutex.RUnlock()

    // 如果是审稿阶段，验证 reviewMode 是否提供
    if phase == types.PhaseReview && reviewMode == "" {
        return nil, fmt.Errorf("review mode is required for review phase")
    }

    // 查找匹配的策略
    for _, policy := range ipm.policies {
        if policy.Phase == phase && policy.Role == userRole {
            // 如果是审稿阶段，需要匹配审稿模式
            if phase == types.PhaseReview {
                if policy.ReviewMode == reviewMode {
                    // 返回策略的副本
                    return &types.IdentityPolicy{
                        Phase:              policy.Phase,
                        Role:               policy.Role,
                        RequiredVisibility: policy.RequiredVisibility,
                        Description:        policy.Description,
                        ReviewMode:         policy.ReviewMode,
                    }, nil
                }
            } else {
                // 非审稿阶段，直接返回匹配的策略
                return &types.IdentityPolicy{
                    Phase:              policy.Phase,
                    Role:               policy.Role,
                    RequiredVisibility: policy.RequiredVisibility,
                    Description:        policy.Description,
                    ReviewMode:         policy.ReviewMode,
                }, nil
            }
        }
    }
    
    // 如果没有找到匹配的策略，返回默认策略
    return &types.IdentityPolicy{
        Phase:              phase,
        Role:               userRole,
        RequiredVisibility: types.VisibilityAnonymous,
        Description:        "默认策略：匿名身份",
        ReviewMode:         reviewMode,
    }, nil
}

// ResolvePseudonym 解析伪名到真实身份（仅编辑权限）
func (ipm *EnhancedIdentityPolicyManager) ResolvePseudonym(pseudonym string, requesterRole types.UserRole) (string, error) {
    if requesterRole != types.RoleEditor {
        return "", fmt.Errorf("only editors can resolve pseudonyms")
    }
    
    ipm.mutex.RLock()
    defer ipm.mutex.RUnlock()
    
    offChainUserID, exists := ipm.pseudonymRegistry[pseudonym]
    if !exists {
        return "", fmt.Errorf("pseudonym not found: %s", pseudonym)
    }
    
    return offChainUserID, nil
}

// GetUserMapping 获取用户映射信息
func (ipm *EnhancedIdentityPolicyManager) GetUserMapping(offChainUserID string) (*UserIdentityMapping, error) {
    ipm.mutex.RLock()
    defer ipm.mutex.RUnlock()
    
    mapping, exists := ipm.userMappings[offChainUserID]
    if !exists {
        return nil, fmt.Errorf("user mapping not found: %s", offChainUserID)
    }
    
    return mapping, nil
}

// GetPhaseIdentityHistory 获取用户的阶段身份历史
func (ipm *EnhancedIdentityPolicyManager) GetPhaseIdentityHistory(offChainUserID string) ([]*PhaseSpecificIdentity, error) {
    ipm.mutex.RLock()
    defer ipm.mutex.RUnlock()
    
    var history []*PhaseSpecificIdentity
    for _, phaseIdentity := range ipm.phaseIdentities {
        // 通过伪名注册表反向查找
        if realID, exists := ipm.pseudonymRegistry[phaseIdentity.Pseudonym]; exists && realID == offChainUserID {
            history = append(history, phaseIdentity)
        }
    }
    
    return history, nil
}

// VerifyConsistency 验证身份一致性
// reviewMode 参数：审稿阶段必须提供，其他阶段可以为空字符串
func (ipm *EnhancedIdentityPolicyManager) VerifyConsistency(offChainUserID, phase, paperID, role, expectedPseudonym string, reviewMode types.ReviewMode) bool {
    contextHash := ipm.generateContextHash(offChainUserID, types.PublishingPhase(phase), paperID, types.UserRole(role), reviewMode)
    
    ipm.mutex.RLock()
    defer ipm.mutex.RUnlock()
    
    phaseIdentity, exists := ipm.phaseIdentities[contextHash]
    if !exists {
        return false
    }
    
    return phaseIdentity.Pseudonym == expectedPseudonym
}