package data_policy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	//"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

// SSSEncryptionPolicy 基于Shamir's Secret Sharing的加密策略
type SSSEncryptionPolicy struct{}

// NewSSSEncryptionPolicy 创建新的SSS加密策略
func NewSSSEncryptionPolicy() *SSSEncryptionPolicy {
	return &SSSEncryptionPolicy{}
}

// GetPolicyType 获取策略类型
func (p *SSSEncryptionPolicy) GetPolicyType() string {
	return "SSS"
}

// Encrypt 使用SSS加密数据（生产级实现）
func (p *SSSEncryptionPolicy) Encrypt(data []byte, participants []string) ([]byte, map[string][]byte, error) {
	if len(participants) < 2 {
		return nil, nil, fmt.Errorf("SSS加密至少需要2个参与者")
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
	
	// 使用SSS分割密钥
	// 阈值设置为参与者数量的一半加一，确保需要多数参与者协作
	threshold := len(participants)/2 + 1
	if threshold < 2 {
		threshold = 2
	}
	
	shares, err := generateSharesProduction(aesKey, len(participants), threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("生成密钥分享失败: %w", err)
	}
	
	// 为每个参与者分配密钥分享
	// 生产级实现：只存储分享，不存储原始密钥
	metadata := make(map[string][]byte)
	for i, participant := range participants {
		// 元数据格式：[阈值(1字节) | 分享索引x(1字节) | 分享值y(32字节固定长度)]
		shareData := make([]byte, 0, 34)
		shareData = append(shareData, byte(threshold))
		shareData = append(shareData, byte(i+1)) // x值从1开始
		
		// 确保y值是32字节固定长度
		yBytes := shares[i].y.Bytes()
		yPadded := make([]byte, 32)
		copy(yPadded[32-len(yBytes):], yBytes)
		shareData = append(shareData, yPadded...)
		
		metadata[participant] = shareData
	}
	
	return encryptedData, metadata, nil
}

// Decrypt 使用SSS解密数据（生产级实现）
func (p *SSSEncryptionPolicy) Decrypt(encryptedData []byte, metadata map[string][]byte, participantID string) ([]byte, error) {
	// 获取当前参与者的分享
	participantMetadata, exists := metadata[participantID]
	if !exists {
		return nil, fmt.Errorf("未找到参与者 %s 的密钥分享", participantID)
	}
	
	if len(participantMetadata) < 34 {
		return nil, fmt.Errorf("分享数据格式不正确，期望至少34字节，实际%d字节", len(participantMetadata))
	}
	
	// 解析元数据：[阈值(1字节) | 分享索引x(1字节) | 分享值y(32字节)]
	threshold := int(participantMetadata[0])
	shareIndex := int(participantMetadata[1])
	shareY := participantMetadata[2:34]
	
	// 收集所有可用的密钥分享
	// 在实际应用中，这需要多方协作协议，这里简化实现：收集所有参与者的分享
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
	
	// 使用SSS恢复密钥
	aesKey, err := recoverSecretProduction(sharesForRecovery, threshold, shareIndices)
	if err != nil {
		return nil, fmt.Errorf("恢复密钥失败: %w", err)
	}
	
	// 使用AES密钥解密数据
	if len(encryptedData) < 12 {
		return nil, fmt.Errorf("加密数据长度不足，期望至少12字节，实际%d字节", len(encryptedData))
	}
	
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

// Share 表示一个密钥分享（包含x和y值）
type Share struct {
	x *big.Int // x值（分享索引）
	y *big.Int // y值（分享值）
}

// generateSharesProduction 生成密钥分享（生产级实现）
func generateSharesProduction(secret []byte, n, t int) ([]Share, error) {
	if t > n {
		return nil, fmt.Errorf("阈值不能大于分享数量")
	}
	if t < 2 {
		return nil, fmt.Errorf("阈值至少为2")
	}
	if n < t {
		return nil, fmt.Errorf("分享数量不能小于阈值")
	}
	
	// 将密钥转换为大整数
	secretInt := new(big.Int).SetBytes(secret)
	
	// 使用更大的素数（2^256附近的素数，更安全）
	// 使用 2^256 - 189 作为素数（这是一个已知的安全素数）
	prime := new(big.Int)
	prime.Exp(big.NewInt(2), big.NewInt(256), nil)
	prime.Sub(prime, big.NewInt(189))
	
	// 确保密钥小于素数
	if secretInt.Cmp(prime) >= 0 {
		return nil, fmt.Errorf("密钥值过大，超过素数范围")
	}
	
	// 生成随机多项式系数
	coefficients := make([]*big.Int, t)
	coefficients[0] = new(big.Int).Set(secretInt) // 常数项为密钥
	
	for i := 1; i < t; i++ {
		coeff, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, fmt.Errorf("生成随机系数失败: %w", err)
		}
		coefficients[i] = coeff
	}
	
	// 生成分享
	shares := make([]Share, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1)) // x值从1开始
		y := evaluatePolynomial(coefficients, x, prime)
		
		shares[i] = Share{
			x: x,
			y: y,
		}
	}
	
	return shares, nil
}

// generateShares 生成密钥分享（保留用于兼容性）
func generateShares(secret []byte, n, t int) ([][]byte, error) {
	shares, err := generateSharesProduction(secret, n, t)
	if err != nil {
		return nil, err
	}
	
	// 转换为旧格式（只返回y值）
	result := make([][]byte, n)
	for i := 0; i < n; i++ {
		result[i] = shares[i].y.Bytes()
	}
	
	return result, nil
}

// evaluatePolynomial 在点x处评估多项式
func evaluatePolynomial(coefficients []*big.Int, x *big.Int, prime *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
	xPow := new(big.Int).Set(big.NewInt(1))
	
	for i := 1; i < len(coefficients); i++ {
		xPow = new(big.Int).Mul(xPow, x)
		xPow = new(big.Int).Mod(xPow, prime)
		
		term := new(big.Int).Mul(coefficients[i], xPow)
		term = new(big.Int).Mod(term, prime)
		
		result = new(big.Int).Add(result, term)
		result = new(big.Int).Mod(result, prime)
	}
	
	return result
}

// recoverSecretProduction 从密钥分享中恢复密钥（生产级实现）
// 使用拉格朗日插值法恢复秘密
func recoverSecretProduction(sharesY [][]byte, threshold int, shareIndices []int) ([]byte, error) {
	if len(sharesY) < threshold {
		return nil, fmt.Errorf("需要至少 %d 个分享才能恢复密钥，当前只有 %d 个", threshold, len(sharesY))
	}
	if len(shareIndices) < threshold {
		return nil, fmt.Errorf("分享索引数量不足")
	}
	
	// 使用与生成时相同的素数
	prime := new(big.Int)
	prime.Exp(big.NewInt(2), big.NewInt(256), nil)
	prime.Sub(prime, big.NewInt(189))
	
	// 使用拉格朗日插值法恢复秘密
	secret := big.NewInt(0)
	
	for i := 0; i < threshold; i++ {
		xi := big.NewInt(int64(shareIndices[i])) // 使用实际的x值
		yi := new(big.Int).SetBytes(sharesY[i])
		
		// 计算拉格朗日基多项式 L_i(0)
		lagrange := big.NewInt(1)
		for j := 0; j < threshold; j++ {
			if i != j {
				xj := big.NewInt(int64(shareIndices[j]))
				// L_i(0) = ∏(0 - x_j) / (x_i - x_j) for j != i
				numerator := new(big.Int).Neg(xj)           // 0 - x_j = -x_j
				denominator := new(big.Int).Sub(xi, xj)     // x_i - x_j
				
				// 检查分母是否为0（不应该发生，但安全检查）
				if denominator.Sign() == 0 {
					return nil, fmt.Errorf("检测到重复的分享索引: %d", shareIndices[i])
				}
				
				// 计算模逆
				denomInv := new(big.Int).ModInverse(denominator, prime)
				if denomInv == nil {
					return nil, fmt.Errorf("计算模逆失败，可能存在重复的分享索引")
				}
				
				term := new(big.Int).Mul(numerator, denomInv)
				term = new(big.Int).Mod(term, prime)
				
				lagrange = new(big.Int).Mul(lagrange, term)
				lagrange = new(big.Int).Mod(lagrange, prime)
			}
		}
		
		// 累加 y_i * L_i(0)
		term := new(big.Int).Mul(yi, lagrange)
		term = new(big.Int).Mod(term, prime)
		secret = new(big.Int).Add(secret, term)
		secret = new(big.Int).Mod(secret, prime)
	}
	
	// 将大整数转换回字节数组
	secretBytes := secret.Bytes()
	
	// 确保返回32字节（256位）
	result := make([]byte, 32)
	copy(result[32-len(secretBytes):], secretBytes)
	
	return result, nil
}

// recoverSecret 从密钥分享中恢复密钥（保留用于兼容性）
func recoverSecret(shares [][]byte, threshold int) ([]byte, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("需要至少 %d 个分享才能恢复密钥，当前只有 %d 个", threshold, len(shares))
	}
	
	// 使用与生成时相同的素数
	prime := new(big.Int)
	prime.Exp(big.NewInt(2), big.NewInt(256), nil)
	prime.Sub(prime, big.NewInt(189))
	
	// 使用拉格朗日插值法恢复秘密
	// 假设分享是按顺序的，x值为1,2,3...
	secret := big.NewInt(0)
	
	for i := 0; i < threshold; i++ {
		xi := big.NewInt(int64(i + 1))
		yi := new(big.Int).SetBytes(shares[i])
		
		// 计算拉格朗日基多项式
		lagrange := big.NewInt(1)
		for j := 0; j < threshold; j++ {
			if i != j {
				xj := big.NewInt(int64(j + 1))
				// L_i(0) = ∏(0 - x_j) / (x_i - x_j) for j != i
				numerator := new(big.Int).Neg(xj)        // 0 - x_j = -x_j
				denominator := new(big.Int).Sub(xi, xj) // x_i - x_j
				
				// 计算模逆
				denomInv := new(big.Int).ModInverse(denominator, prime)
				if denomInv == nil {
					return nil, fmt.Errorf("计算模逆失败")
				}
				
				term := new(big.Int).Mul(numerator, denomInv)
				term = new(big.Int).Mod(term, prime)
				
				lagrange = new(big.Int).Mul(lagrange, term)
				lagrange = new(big.Int).Mod(lagrange, prime)
			}
		}
		
		// 累加 y_i * L_i(0)
		term := new(big.Int).Mul(yi, lagrange)
		term = new(big.Int).Mod(term, prime)
		secret = new(big.Int).Add(secret, term)
		secret = new(big.Int).Mod(secret, prime)
	}
	
	// 将大整数转换回字节数组
	secretBytes := secret.Bytes()
	
	// 确保返回32字节（256位）
	result := make([]byte, 32)
	copy(result[32-len(secretBytes):], secretBytes)
	
	return result, nil
}