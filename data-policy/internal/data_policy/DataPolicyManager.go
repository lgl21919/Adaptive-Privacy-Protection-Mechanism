package data_policy

import (
	"github.com/tap-thesis/privacy-protection-data/pkg/types"
	"fmt"
)

// DataPolicyManager 数据保护策略管理器接口
type DataPolicyManager interface {
	// GetEncryptionPolicy 获取特定阶段和数据类型的加密策略
	GetEncryptionPolicy(phase types.PublishingPhase, dataType string) (EncryptionPolicy, error)
	
	// EncryptData 根据阶段、数据类型和参与者加密数据
	EncryptData(data []byte, phase types.PublishingPhase, dataType string, participants []string) ([]byte, map[string][]byte, error)
	
	// DecryptData 根据阶段、数据类型和参与者解密数据
	DecryptData(encryptedData []byte, metadata map[string][]byte, phase types.PublishingPhase, dataType string, participantID string) ([]byte, error)
}

// EncryptionPolicy 加密策略接口
type EncryptionPolicy interface {
	// Encrypt 加密数据
	Encrypt(data []byte, participants []string) ([]byte, map[string][]byte, error)
	
	// Decrypt 解密数据
	Decrypt(encryptedData []byte, metadata map[string][]byte, participantID string) ([]byte, error)
	
	// GetPolicyType 获取策略类型
	GetPolicyType() string
}

// 数据类型常量（兼容旧代码）
const (
	DataTypePaper   = "PAPER"
	DataTypeMessage = "MESSAGE"
)

// 使用 types 包中定义的数据类型
var (
	DataTypeManuscript          = string(types.DataTypeManuscript)
	DataTypeEncryptionKey       = string(types.DataTypeEncryptionKey)
	DataTypeSupplementaryData   = string(types.DataTypeSupplementaryData)
	DataTypeFinalRecommendation = string(types.DataTypeFinalRecommendation)
)

// EnhancedDataPolicyManager 增强型数据保护策略管理器实现
type EnhancedDataPolicyManager struct {
	policies map[string]EncryptionPolicy // 策略映射表
	// 支持多策略选择：根据安全级别选择不同的策略
	policySelectors map[string]func(level types.DataSecurityLevel) EncryptionPolicy
}

// NewEnhancedDataPolicyManager 创建新的增强型数据保护策略管理器
func NewEnhancedDataPolicyManager() *EnhancedDataPolicyManager {
	manager := &EnhancedDataPolicyManager{
		policies:        make(map[string]EncryptionPolicy),
		policySelectors: make(map[string]func(level types.DataSecurityLevel) EncryptionPolicy),
	}
	
	// 初始化各种加密策略
	ecdhPolicy := NewECDHEncryptionPolicy()
	sssPolicy := NewSSSEncryptionPolicy()
	prePolicy := NewProxyReEncryptionPolicy()
	publicPolicy := NewPublicEncryptionPolicy()
	mpcPolicy := NewMPCEncryptionPolicy()
	
	// ========== 提交阶段 (SUBMISSION) ==========
	// Manuscript: Level 1/2, ECDH/SSS
	// Level 1 使用 ECDH, Level 2 使用 SSS
	manager.policySelectors[getPolicyKey(types.PhaseSubmission, DataTypeManuscript)] = func(level types.DataSecurityLevel) EncryptionPolicy {
		if level == types.DataSecLevel1 {
			return ecdhPolicy
		}
		return sssPolicy // Level 2 默认使用 SSS
	}
	manager.policies[getPolicyKey(types.PhaseSubmission, DataTypeManuscript)] = ecdhPolicy // 默认策略
	
	// Interactive Messages: Level 1/2, PRE/ECDH
	// Level 1 使用 ECDH, Level 2 使用 PRE
	manager.policySelectors[getPolicyKey(types.PhaseSubmission, DataTypeMessage)] = func(level types.DataSecurityLevel) EncryptionPolicy {
		if level == types.DataSecLevel1 {
			return ecdhPolicy
		}
		return prePolicy // Level 2 使用 PRE
	}
	manager.policies[getPolicyKey(types.PhaseSubmission, DataTypeMessage)] = ecdhPolicy // 默认策略
	
	// encryption key: Level 1, PRE
	manager.policies[getPolicyKey(types.PhaseSubmission, DataTypeEncryptionKey)] = prePolicy
	
	// ========== 审稿阶段 (REVIEW) ==========
	// Review Manuscript: Level 1/2, ECDH/SSS
	manager.policySelectors[getPolicyKey(types.PhaseReview, DataTypeManuscript)] = func(level types.DataSecurityLevel) EncryptionPolicy {
		if level == types.DataSecLevel1 {
			return ecdhPolicy
		}
		return sssPolicy // Level 2 使用 SSS
	}
	manager.policies[getPolicyKey(types.PhaseReview, DataTypeManuscript)] = ecdhPolicy // 默认策略
	
	// Supplementary Data: Level 1/2, PRE/ECDH
	manager.policySelectors[getPolicyKey(types.PhaseReview, DataTypeSupplementaryData)] = func(level types.DataSecurityLevel) EncryptionPolicy {
		if level == types.DataSecLevel1 {
			return ecdhPolicy
		}
		return prePolicy // Level 2 使用 PRE
	}
	manager.policies[getPolicyKey(types.PhaseReview, DataTypeSupplementaryData)] = ecdhPolicy // 默认策略
	
	// Interactive Messages: Level 1/2, PRE/ECDH
	manager.policySelectors[getPolicyKey(types.PhaseReview, DataTypeMessage)] = func(level types.DataSecurityLevel) EncryptionPolicy {
		if level == types.DataSecLevel1 {
			return ecdhPolicy
		}
		return prePolicy // Level 2 使用 PRE
	}
	manager.policies[getPolicyKey(types.PhaseReview, DataTypeMessage)] = ecdhPolicy // 默认策略
	
	// Final Recommendations/Votes: Level 1/2/3, PRE/ECDH/MPC
	manager.policySelectors[getPolicyKey(types.PhaseReview, DataTypeFinalRecommendation)] = func(level types.DataSecurityLevel) EncryptionPolicy {
		switch level {
		case types.DataSecLevel1:
			return ecdhPolicy
		case types.DataSecLevel2:
			return prePolicy
		case types.DataSecLevel3:
			return mpcPolicy
		default:
			return ecdhPolicy
		}
	}
	manager.policies[getPolicyKey(types.PhaseReview, DataTypeFinalRecommendation)] = ecdhPolicy // 默认策略
	
	// encryption key: Level 1, PRE
	manager.policies[getPolicyKey(types.PhaseReview, DataTypeEncryptionKey)] = prePolicy
	
	// ========== 出版阶段 (PUBLICATION) ==========
	// Published Manuscript: Level 1/2, ECDH/SSS
	manager.policySelectors[getPolicyKey(types.PhasePublication, DataTypeManuscript)] = func(level types.DataSecurityLevel) EncryptionPolicy {
		if level == types.DataSecLevel1 {
			return ecdhPolicy
		}
		return sssPolicy // Level 2 使用 SSS
	}
	manager.policies[getPolicyKey(types.PhasePublication, DataTypeManuscript)] = ecdhPolicy // 默认策略
	
	// Interactive Messages: Level 0, Public
	manager.policies[getPolicyKey(types.PhasePublication, DataTypeMessage)] = publicPolicy
	
	// encryption key: Level 1, PRE
	manager.policies[getPolicyKey(types.PhasePublication, DataTypeEncryptionKey)] = prePolicy
	
	// ========== 兼容旧代码 ==========
	// 保持对旧数据类型的支持
	manager.policies[getPolicyKey(types.PhaseSubmission, DataTypePaper)] = ecdhPolicy
	manager.policies[getPolicyKey(types.PhaseReview, DataTypePaper)] = sssPolicy
	manager.policies[getPolicyKey(types.PhasePublication, DataTypePaper)] = publicPolicy
	
	return manager
}

// 生成策略映射表的键
func getPolicyKey(phase types.PublishingPhase, dataType string) string {
	return string(phase) + "_" + dataType
}

// GetEncryptionPolicy 获取特定阶段和数据类型的加密策略
// 如果不指定安全级别，返回默认策略
func (m *EnhancedDataPolicyManager) GetEncryptionPolicy(phase types.PublishingPhase, dataType string) (EncryptionPolicy, error) {
	return m.GetEncryptionPolicyWithLevel(phase, dataType, types.DataSecLevel1)
}

// GetEncryptionPolicyWithLevel 根据阶段、数据类型和安全级别获取加密策略
func (m *EnhancedDataPolicyManager) GetEncryptionPolicyWithLevel(phase types.PublishingPhase, dataType string, level types.DataSecurityLevel) (EncryptionPolicy, error) {
	key := getPolicyKey(phase, dataType)
	
	// 首先检查是否有策略选择器（支持多策略）
	if selector, exists := m.policySelectors[key]; exists {
		return selector(level), nil
	}
	
	// 否则使用默认策略
	policy, exists := m.policies[key]
	if !exists {
		return nil, fmt.Errorf("未找到阶段 %s 和数据类型 %s 的加密策略", phase, dataType)
	}
	return policy, nil
}

// EncryptData 根据阶段、数据类型和参与者加密数据
func (m *EnhancedDataPolicyManager) EncryptData(data []byte, phase types.PublishingPhase, dataType string, participants []string) ([]byte, map[string][]byte, error) {
	return m.EncryptDataWithLevel(data, phase, dataType, participants, types.DataSecLevel1)
}

// EncryptDataWithLevel 根据阶段、数据类型、参与者和安全级别加密数据
func (m *EnhancedDataPolicyManager) EncryptDataWithLevel(data []byte, phase types.PublishingPhase, dataType string, participants []string, level types.DataSecurityLevel) ([]byte, map[string][]byte, error) {
	policy, err := m.GetEncryptionPolicyWithLevel(phase, dataType, level)
	if err != nil {
		return nil, nil, err
	}
	
	return policy.Encrypt(data, participants)
}

// DecryptData 根据阶段、数据类型和参与者解密数据
func (m *EnhancedDataPolicyManager) DecryptData(encryptedData []byte, metadata map[string][]byte, phase types.PublishingPhase, dataType string, participantID string) ([]byte, error) {
	return m.DecryptDataWithLevel(encryptedData, metadata, phase, dataType, participantID, types.DataSecLevel1)
}

// DecryptDataWithLevel 根据阶段、数据类型、参与者和安全级别解密数据
func (m *EnhancedDataPolicyManager) DecryptDataWithLevel(encryptedData []byte, metadata map[string][]byte, phase types.PublishingPhase, dataType string, participantID string, level types.DataSecurityLevel) ([]byte, error) {
	policy, err := m.GetEncryptionPolicyWithLevel(phase, dataType, level)
	if err != nil {
		return nil, err
	}
	
	return policy.Decrypt(encryptedData, metadata, participantID)
}

// EncryptPaper 加密论文
func (m *EnhancedDataPolicyManager) EncryptPaper(data []byte, phase types.PublishingPhase, participants []string) ([]byte, map[string][]byte, error) {
	return m.EncryptData(data, phase, DataTypePaper, participants)
}

// DecryptPaper 解密论文
func (m *EnhancedDataPolicyManager) DecryptPaper(encryptedData []byte, metadata map[string][]byte, phase types.PublishingPhase, participantID string) ([]byte, error) {
	return m.DecryptData(encryptedData, metadata, phase, DataTypePaper, participantID)
}

// EncryptMessage 加密消息
func (m *EnhancedDataPolicyManager) EncryptMessage(data []byte, phase types.PublishingPhase, participants []string) ([]byte, map[string][]byte, error) {
	return m.EncryptData(data, phase, DataTypeMessage, participants)
}

// DecryptMessage 解密消息
func (m *EnhancedDataPolicyManager) DecryptMessage(encryptedData []byte, metadata map[string][]byte, phase types.PublishingPhase, participantID string) ([]byte, error) {
	return m.DecryptData(encryptedData, metadata, phase, DataTypeMessage, participantID)
}