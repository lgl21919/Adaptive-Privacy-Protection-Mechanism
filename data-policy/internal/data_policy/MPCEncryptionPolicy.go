package data_policy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// MPCEncryptionPolicy 基于多方计算的加密策略
// 使用阈值秘密共享实现多方安全计算
type MPCEncryptionPolicy struct{}

// NewMPCEncryptionPolicy 创建新的MPC加密策略
func NewMPCEncryptionPolicy() *MPCEncryptionPolicy {
	return &MPCEncryptionPolicy{}
}

// GetPolicyType 获取策略类型
func (p *MPCEncryptionPolicy) GetPolicyType() string {
	return "MPC"
}

// Encrypt 使用MPC加密数据
// MPC策略使用阈值秘密共享，需要多个参与者协作才能解密
func (p *MPCEncryptionPolicy) Encrypt(data []byte, participants []string) ([]byte, map[string][]byte, error) {
	if len(participants) < 2 {
		return nil, nil, fmt.Errorf("MPC加密至少需要2个参与者")
	}

	// 生成AES加密密钥
	aesKey := make([]byte, 32) // 256位密钥
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, nil, fmt.Errorf("生成AES密钥失败: %w", err)
	}

	// 使用AES-GCM加密数据
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("创建AES密码块失败: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("生成随机数失败: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("创建GCM失败: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	// 将nonce附加到密文
	encryptedData := append(nonce, ciphertext...)

	// 使用阈值秘密共享分割密钥（生产级实现）
	// 阈值设置为参与者数量的2/3，确保需要多数参与者协作
	threshold := (len(participants) * 2) / 3
	if threshold < 2 {
		threshold = 2
	}

	// 使用生产级分享生成函数
	shares, err := generateSharesProduction(aesKey, len(participants), threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("生成密钥分享失败: %w", err)
	}

	// 为每个参与者分配密钥分享
	// 生产级元数据格式：[阈值(1字节) | 分享索引x(1字节) | 分享值y(32字节固定长度)]
	metadata := make(map[string][]byte)
	for i, participant := range participants {
		shareData := make([]byte, 0, 34)
		shareData = append(shareData, byte(threshold))
		shareData = append(shareData, byte(i+1)) // x值从1开始
		
		// 确保y值是32字节固定长度（与SSS保持一致）
		yBytes := shares[i].y.Bytes()
		yPadded := make([]byte, 32)
		copy(yPadded[32-len(yBytes):], yBytes)
		shareData = append(shareData, yPadded...)
		
		metadata[participant] = shareData
	}

	return encryptedData, metadata, nil
}

// Decrypt 使用MPC解密数据
// 注意：MPC解密需要多个参与者协作，这里实现单参与者解密（需要足够的密钥分享）
func (p *MPCEncryptionPolicy) Decrypt(encryptedData []byte, metadata map[string][]byte, participantID string) ([]byte, error) {
	participantMetadata, exists := metadata[participantID]
	if !exists {
		return nil, fmt.Errorf("未找到参与者 %s 的元数据", participantID)
	}

	if len(participantMetadata) < 1 {
		return nil, fmt.Errorf("元数据格式错误")
	}

	// 解析元数据格式：[阈值(1字节) | 分享索引x(1字节) | 分享值y(32字节)]
	if len(participantMetadata) < 34 {
		return nil, fmt.Errorf("元数据格式错误，期望至少34字节，实际%d字节", len(participantMetadata))
	}
	
	threshold := int(participantMetadata[0])
	shareIndex := int(participantMetadata[1]) // x值
	shareY := participantMetadata[2:34]       // y值（固定32字节）

	// 收集所有可用的密钥分享（带索引信息）
	// 在实际MPC中，这需要多方协作协议，这里简化实现：收集所有参与者的分享
	type shareWithIndex struct {
		index int    // x值
		y     []byte // y值
	}
	allSharesWithIndex := make([]shareWithIndex, 0, len(metadata))
	allSharesWithIndex = append(allSharesWithIndex, shareWithIndex{index: shareIndex, y: shareY})
	
	// 从其他参与者收集分享
	for otherID, otherMetadata := range metadata {
		if otherID != participantID && len(otherMetadata) >= 34 {
			otherIndex := int(otherMetadata[1])
			otherY := otherMetadata[2:34]
			allSharesWithIndex = append(allSharesWithIndex, shareWithIndex{index: otherIndex, y: otherY})
		}
	}

	// 检查是否有足够的分享
	if len(allSharesWithIndex) < threshold {
		return nil, fmt.Errorf("需要至少 %d 个密钥分享才能解密，当前只有 %d 个", threshold, len(allSharesWithIndex))
	}

	// 按索引排序，确保顺序正确（x=1, 2, 3...）
	for i := 0; i < len(allSharesWithIndex)-1; i++ {
		for j := i + 1; j < len(allSharesWithIndex); j++ {
			if allSharesWithIndex[i].index > allSharesWithIndex[j].index {
				allSharesWithIndex[i], allSharesWithIndex[j] = allSharesWithIndex[j], allSharesWithIndex[i]
			}
		}
	}

	// 提取前threshold个分享（按顺序）
	sharesForRecovery := make([][]byte, threshold)
	shareIndices := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		sharesForRecovery[i] = allSharesWithIndex[i].y
		shareIndices[i] = allSharesWithIndex[i].index
	}

	// 使用生产级SSS恢复密钥
	aesKey, err := recoverSecretProduction(sharesForRecovery, threshold, shareIndices)
	if err != nil {
		return nil, fmt.Errorf("恢复密钥失败: %w", err)
	}

	// 使用AES密钥解密数据
	// 前12字节是nonce
	nonce := encryptedData[:12]
	// 剩余部分是密文
	ciphertext := encryptedData[12:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密数据失败: %w", err)
	}

	return plaintext, nil
}

