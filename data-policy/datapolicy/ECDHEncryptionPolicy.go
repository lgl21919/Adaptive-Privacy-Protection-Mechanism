package datapolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
)

// ECDHEncryptionPolicy 基于ECDH和HKDF的加密策略
type ECDHEncryptionPolicy struct{
	// 存储参与者的密钥对，用于模拟测试
	participantKeys map[string]*ecdsa.PrivateKey
}

// NewECDHEncryptionPolicy 创建新的ECDH加密策略
func NewECDHEncryptionPolicy() *ECDHEncryptionPolicy {
	return &ECDHEncryptionPolicy{
		participantKeys: make(map[string]*ecdsa.PrivateKey),
	}
}

// GetPolicyType 获取策略类型
func (p *ECDHEncryptionPolicy) GetPolicyType() string {
	return "ECDH_HKDF"
}

// Encrypt 使用ECDH和HKDF加密数据
func (p *ECDHEncryptionPolicy) Encrypt(data []byte, participants []string) ([]byte, map[string][]byte, error) {
	// 生成临时密钥对
	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成临时密钥对失败: %w", err)
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
	
	// 为每个参与者生成密钥元数据
	metadata := make(map[string][]byte)
	
	// 临时公钥字节
	ephemeralPubKeyBytes := elliptic.Marshal(elliptic.P256(), ephemeralKey.PublicKey.X, ephemeralKey.PublicKey.Y)
	
	for _, participant := range participants {
		// 为每个参与者生成或获取密钥对
		recipientKey, exists := p.participantKeys[participant]
		if !exists {
			// 如果不存在，为参与者生成新的密钥对
			recipientKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, nil, fmt.Errorf("为参与者生成密钥失败: %w", err)
			}
			p.participantKeys[participant] = recipientKey
		}
		
		// 计算共享密钥
		x, _ := elliptic.P256().ScalarMult(recipientKey.PublicKey.X, recipientKey.PublicKey.Y, 
			ephemeralKey.D.Bytes())
		
		// 使用HKDF从共享密钥派生加密密钥
		sharedSecret := x.Bytes()
		kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("ECDH key derivation"))
		
		derivedKey := make([]byte, 32)
		if _, err := io.ReadFull(kdf, derivedKey); err != nil {
			return nil, nil, fmt.Errorf("派生密钥失败: %w", err)
		}
		
		// 使用派生密钥加密AES密钥
		block, err := aes.NewCipher(derivedKey)
		if err != nil {
			return nil, nil, fmt.Errorf("创建AES密码块失败: %w", err)
		}
		
		nonceKey := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonceKey); err != nil {
			return nil, nil, fmt.Errorf("生成随机数失败: %w", err)
		}
		
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, nil, fmt.Errorf("创建GCM失败: %w", err)
		}
		
		encryptedKey := aesgcm.Seal(nil, nonceKey, aesKey, nil)
		
		// 元数据包含: 临时公钥 + nonce + 加密的AES密钥
		participantMetadata := append(ephemeralPubKeyBytes, nonceKey...)
		participantMetadata = append(participantMetadata, encryptedKey...)
		
		metadata[participant] = participantMetadata
	}
	
	return encryptedData, metadata, nil
}

// Decrypt 使用ECDH和HKDF解密数据
func (p *ECDHEncryptionPolicy) Decrypt(encryptedData []byte, metadata map[string][]byte, participantID string) ([]byte, error) {
	participantMetadata, exists := metadata[participantID]
	if !exists {
		return nil, fmt.Errorf("未找到参与者 %s 的元数据", participantID)
	}
	
	// 检查元数据长度（至少需要公钥 + 12字节nonce）
	if len(participantMetadata) < 45 {
		return nil, fmt.Errorf("元数据长度不足，期望至少45字节，实际%d字节", len(participantMetadata))
	}
	
	// 解析元数据
	// 临时公钥可能是65字节（未压缩）或33字节（压缩），或64字节（某些特殊情况）
	// 对于P256曲线，未压缩格式通常是65字节（0x04 + 32字节X + 32字节Y）
	// 动态检测公钥长度：尝试从最大长度开始，逐步减小
	
	var x, y *big.Int
	var nonceKey, encryptedKey []byte
	
	// 尝试不同的公钥长度（从大到小）
	for _, keyLen := range []int{65, 64, 33} {
		if len(participantMetadata) < keyLen+12 {
			continue // 元数据长度不足
		}
		
		ephemeralPubKeyBytes := participantMetadata[:keyLen]
		
		// 如果是64字节，尝试添加前缀0x04
		if keyLen == 64 {
			// 检查第一个字节是否是0x04
			if len(participantMetadata) > 0 && participantMetadata[0] != 0x04 {
				// 手动添加前缀字节0x04（未压缩格式）
				ephemeralPubKeyBytesWithPrefix := make([]byte, 65)
				ephemeralPubKeyBytesWithPrefix[0] = 0x04
				copy(ephemeralPubKeyBytesWithPrefix[1:], ephemeralPubKeyBytes)
				x, y = elliptic.Unmarshal(elliptic.P256(), ephemeralPubKeyBytesWithPrefix)
			} else {
				// 如果第一个字节已经是0x04，说明实际是65字节，但被截断了
				x, y = nil, nil
			}
		} else {
			x, y = elliptic.Unmarshal(elliptic.P256(), ephemeralPubKeyBytes)
		}
		
		if x != nil {
			nonceKey = participantMetadata[keyLen : keyLen+12]
			encryptedKey = participantMetadata[keyLen+12:]
			break
		}
	}
	
	if x == nil {
		return nil, fmt.Errorf("解析公钥失败，元数据长度: %d字节，前几个字节: %v", 
			len(participantMetadata), participantMetadata[:min(20, len(participantMetadata))])
	}
	
	return p.decryptWithMetadata(encryptedData, x, y, nonceKey, encryptedKey, participantID)
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// decryptWithMetadata 使用解析后的元数据解密数据
func (p *ECDHEncryptionPolicy) decryptWithMetadata(encryptedData []byte, x, y *big.Int, nonceKey, encryptedKey []byte, participantID string) ([]byte, error) {
	// 获取参与者的私钥
	recipientKey, exists := p.participantKeys[participantID]
	if !exists {
		return nil, fmt.Errorf("未找到参与者 %s 的私钥", participantID)
	}
	
	// 计算共享密钥
	sharedX, _ := elliptic.P256().ScalarMult(x, y, recipientKey.D.Bytes())
	
	// 使用HKDF从共享密钥派生加密密钥
	sharedSecret := sharedX.Bytes()
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("ECDH key derivation"))
	
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("派生密钥失败: %w", err)
	}
	
	// 使用派生密钥解密AES密钥
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %w", err)
	}
	
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %w", err)
	}
	
	aesKey, err := aesgcm.Open(nil, nonceKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("解密AES密钥失败: %w", err)
	}
	
	// 使用AES密钥解密数据
	// 检查加密数据长度
	if len(encryptedData) < 12 {
		return nil, fmt.Errorf("加密数据长度不足，期望至少12字节，实际%d字节", len(encryptedData))
	}
	
	// 前12字节是nonce
	nonce := encryptedData[:12]
	// 剩余部分是密文
	ciphertext := encryptedData[12:]
	
	block, err = aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %w", err)
	}
	
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %w", err)
	}
	
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密数据失败: %w", err)
	}
	
	return plaintext, nil
}