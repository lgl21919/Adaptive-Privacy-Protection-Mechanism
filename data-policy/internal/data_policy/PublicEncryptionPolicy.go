package data_policy

import (
	//"fmt"
)

// PublicEncryptionPolicy 公开数据策略（不加密）
type PublicEncryptionPolicy struct{}

// NewPublicEncryptionPolicy 创建新的公开数据策略
func NewPublicEncryptionPolicy() *PublicEncryptionPolicy {
	return &PublicEncryptionPolicy{}
}

// GetPolicyType 获取策略类型
func (p *PublicEncryptionPolicy) GetPolicyType() string {
	return "PUBLIC"
}

// Encrypt 公开数据不进行加密
func (p *PublicEncryptionPolicy) Encrypt(data []byte, participants []string) ([]byte, map[string][]byte, error) {
	// 出版阶段数据是公开的，不进行加密
	metadata := make(map[string][]byte)
	for _, participant := range participants {
		metadata[participant] = []byte("PUBLIC")
	}
	
	return data, metadata, nil
}

// Decrypt 公开数据不需要解密
func (p *PublicEncryptionPolicy) Decrypt(encryptedData []byte, metadata map[string][]byte, participantID string) ([]byte, error) {
	// 出版阶段数据是公开的，直接返回
	return encryptedData, nil
}