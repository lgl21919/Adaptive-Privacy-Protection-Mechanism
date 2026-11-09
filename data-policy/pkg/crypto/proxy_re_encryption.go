package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"sync"
	"time"
	"encoding/pem"
	"crypto/x509"
)

// ProxyReEncryption 生产级代理重加密系统
type ProxyReEncryption struct {
	curve elliptic.Curve
	// 密钥存储（生产环境应使用安全的密钥管理系统）
	privateKeys map[string]*ecdsa.PrivateKey
	publicKeys  map[string]*ecdsa.PublicKey
	reKeys      map[string]map[string]*ReEncryptionKey
	// 并发安全
	mu sync.RWMutex
	// 配置参数
	config *Config
}

// Config 系统配置
type Config struct {
	// 密钥默认过期时间
	DefaultKeyExpiration time.Duration
	// 重加密密钥默认过期时间
	DefaultReKeyExpiration time.Duration
	// HMAC密钥
	HMACSecret []byte
	// 是否启用密钥过期检查
	EnableKeyExpiration bool
}

// ECPoint 椭圆曲线点
type ECPoint struct {
	X, Y *big.Int
}

// ReEncryptionKey 重加密密钥
type ReEncryptionKey struct {
	// 核心重加密参数
	Alpha *big.Int  // 重加密密钥的核心部分
	Beta  *ECPoint  // 公开验证部分
	// 元数据
	FromID    string    // 源用户ID
	ToID      string    // 目标用户ID
	CreatedAt time.Time // 创建时间
	ExpiresAt time.Time // 过期时间
	// 完整性保护
	MAC []byte // 消息认证码
}

// Ciphertext 密文结构
type Ciphertext struct {
	// 椭圆曲线部分
	C1 *ECPoint // g^r
	// 对称加密部分
	C2 []byte // 加密的数据
	IV []byte // 初始化向量
	// 元数据
	Level     int       // 密文级别 (1: 原始, 2: 重加密)
	Timestamp time.Time // 加密时间戳
	// 完整性保护
	MAC []byte // 消息认证码
}

// ReEncryptedCiphertext 重加密后的密文
type ReEncryptedCiphertext struct {
	*Ciphertext
	// 重加密特有字段
	OriginalC1     *ECPoint // 原始C1，用于保持 AAD 一致性
	OriginalFromID string   // 原始发送者ID
	ReEncryptedBy  string   // 重加密执行者ID
	Proof          []byte   // 重加密正确性证明
}

// NewProxyReEncryption 创建新的代理重加密系统
func NewProxyReEncryption(config *Config) *ProxyReEncryption {
	if config == nil {
		config = &Config{
			DefaultKeyExpiration:   365 * 24 * time.Hour, // 1年
			DefaultReKeyExpiration: 30 * 24 * time.Hour,  // 30天
			HMACSecret:            []byte("PRE_HMAC_SECRET_KEY_2024"),
			EnableKeyExpiration:   true,
		}
	}

	return &ProxyReEncryption{
		curve:       elliptic.P256(),
		privateKeys: make(map[string]*ecdsa.PrivateKey),
		publicKeys:  make(map[string]*ecdsa.PublicKey),
		reKeys:      make(map[string]map[string]*ReEncryptionKey),
		config:      config,
	}
}

// GenerateKeyPair 生成用户密钥对
func (pre *ProxyReEncryption) GenerateKeyPair(userID string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	pre.mu.Lock()
	defer pre.mu.Unlock()

	// 生成ECDSA密钥对
	privateKey, err := ecdsa.GenerateKey(pre.curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成密钥对失败: %w", err)
	}

	publicKey := &privateKey.PublicKey

	// 存储密钥
	pre.privateKeys[userID] = privateKey
	pre.publicKeys[userID] = publicKey

	return privateKey, publicKey, nil
}

// GetPublicKey 获取用户公钥
func (pre *ProxyReEncryption) GetPublicKey(userID string) (*ecdsa.PublicKey, error) {
	pre.mu.RLock()
	defer pre.mu.RUnlock()

	publicKey, exists := pre.publicKeys[userID]
	if !exists {
		return nil, fmt.Errorf("用户 %s 的公钥不存在", userID)
	}

	return publicKey, nil
}

// GetPrivateKey 获取用户私钥（谨慎使用，仅用于调试）
func (pre *ProxyReEncryption) GetPrivateKey(userID string) (*ecdsa.PrivateKey, error) {
	pre.mu.RLock()
	defer pre.mu.RUnlock()

	privateKey, exists := pre.privateKeys[userID]
	if !exists {
		return nil, fmt.Errorf("用户 %s 的私钥不存在", userID)
	}

	return privateKey, nil
}

// ListAllUsers 列出所有已注册的用户ID
func (pre *ProxyReEncryption) ListAllUsers() []string {
	pre.mu.RLock()
	defer pre.mu.RUnlock()

	users := make([]string, 0, len(pre.publicKeys))
	for userID := range pre.publicKeys {
		users = append(users, userID)
	}
	return users
}

// PrintKeyInfo 打印用户密钥信息（用于调试和演示）
func (pre *ProxyReEncryption) PrintKeyInfo(userID string) error {
	pre.mu.RLock()
	defer pre.mu.RUnlock()

	privateKey, privExists := pre.privateKeys[userID]
	publicKey, pubExists := pre.publicKeys[userID]

	if !privExists && !pubExists {
		return fmt.Errorf("用户 %s 的密钥不存在", userID)
	}

	fmt.Printf("\n=== 用户密钥信息: %s ===\n", userID)
	
	if pubExists {
		fmt.Printf("公钥:\n")
		fmt.Printf("  X坐标: %s\n", publicKey.X.String())
		fmt.Printf("  Y坐标: %s\n", publicKey.Y.String())
		fmt.Printf("  曲线: %s\n", publicKey.Curve.Params().Name)
	}
	
	if privExists {
		fmt.Printf("私钥:\n")
		fmt.Printf("  D值: %s\n", privateKey.D.String())
		fmt.Printf("  曲线: %s\n", privateKey.Curve.Params().Name)
		// 注意：实际应用中不应打印私钥，这里仅用于演示
	}
	
	fmt.Printf("存储位置: 内存中的 map 结构\n")
	fmt.Printf("  - privateKeys[\"%s\"]\n", userID)
	fmt.Printf("  - publicKeys[\"%s\"]\n", userID)
	fmt.Printf("================================\n\n")
	
	return nil
}

// GenerateReEncryptionKey 生成重加密密钥
func (pre *ProxyReEncryption) GenerateReEncryptionKey(fromID, toID string, expiration time.Duration) (*ReEncryptionKey, error) {
	pre.mu.Lock()
	defer pre.mu.Unlock()

	// 检查源用户私钥
	fromPrivateKey, exists := pre.privateKeys[fromID]
	if !exists {
		return nil, fmt.Errorf("源用户 %s 的私钥不存在", fromID)
	}

	// 检查目标用户私钥（用于计算 d_b 的逆元）
	toPrivateKey, exists := pre.privateKeys[toID]
	if !exists {
		return nil, fmt.Errorf("目标用户 %s 的私钥不存在", toID)
	}
	toPublicKey := &toPrivateKey.PublicKey

	// 椭圆曲线阶
	n := pre.curve.Params().N

	// 计算 alpha = d_a * d_b^(-1) mod n
	dBInv := new(big.Int).ModInverse(toPrivateKey.D, n)
	if dBInv == nil {
		return nil, fmt.Errorf("计算目标私钥逆元失败")
	}
	alpha := new(big.Int).Mul(fromPrivateKey.D, dBInv)
	alpha.Mod(alpha, n)

	// 计算公开验证部分（使用随机 r 作为辅助公开参数）
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("生成随机数失败: %w", err)
	}
	betaX, betaY := pre.curve.ScalarMult(toPublicKey.X, toPublicKey.Y, r.Bytes())
	beta := &ECPoint{X: betaX, Y: betaY}

	// 创建重加密密钥
	now := time.Now()
	reKey := &ReEncryptionKey{
		Alpha:     alpha,
		Beta:      beta,
		FromID:    fromID,
		ToID:      toID,
		CreatedAt: now,
		ExpiresAt: now.Add(expiration),
	}

	// 计算MAC
	reKey.MAC = pre.computeReKeyMAC(reKey)

	// 存储重加密密钥
	if pre.reKeys[fromID] == nil {
		pre.reKeys[fromID] = make(map[string]*ReEncryptionKey)
	}
	pre.reKeys[fromID][toID] = reKey

	return reKey, nil
}

// computeReKeyMAC 计算重加密密钥的MAC
func (pre *ProxyReEncryption) computeReKeyMAC(reKey *ReEncryptionKey) []byte {
	h := hmac.New(sha256.New, pre.config.HMACSecret)
	h.Write(reKey.Alpha.Bytes())
	h.Write(reKey.Beta.X.Bytes())
	h.Write(reKey.Beta.Y.Bytes())
	h.Write([]byte(reKey.FromID))
	h.Write([]byte(reKey.ToID))

	// 添加时间戳
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(reKey.CreatedAt.Unix()))
	h.Write(timeBytes)

	return h.Sum(nil)
}

// verifyReKeyMAC 验证重加密密钥的MAC
func (pre *ProxyReEncryption) verifyReKeyMAC(reKey *ReEncryptionKey) bool {
	expectedMAC := pre.computeReKeyMAC(reKey)
	return hmac.Equal(reKey.MAC, expectedMAC)
}

// Encrypt 加密数据
func (pre *ProxyReEncryption) Encrypt(data []byte, recipientID string) (*Ciphertext, error) {
	pre.mu.RLock()
	recipientPublicKey, exists := pre.publicKeys[recipientID]
	pre.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("接收者 %s 的公钥不存在", recipientID)
	}

	// 生成随机数 k
	n := pre.curve.Params().N
	k, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("生成随机数失败: %w", err)
	}

	// 计算 C1 = g^k
	c1X, c1Y := pre.curve.ScalarBaseMult(k.Bytes())
	c1 := &ECPoint{X: c1X, Y: c1Y}

	// 计算共享密钥 = recipientPublicKey^k
	sharedX, sharedY := pre.curve.ScalarMult(recipientPublicKey.X, recipientPublicKey.Y, k.Bytes())

	// 从共享密钥派生AES密钥
	sharedSecret := append(sharedX.Bytes(), sharedY.Bytes()...)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("PRE_AES_KEY_DERIVATION"))

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, fmt.Errorf("派生AES密钥失败: %w", err)
	}

	// 生成随机IV
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("生成IV失败: %w", err)
	}

	// 使用AES-GCM加密数据
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %w", err)
	}

	// 使用C1作为附加认证数据
	aad := append(c1.X.Bytes(), c1.Y.Bytes()...)
	c2 := aesgcm.Seal(nil, iv, data, aad)

	// 创建密文
	ciphertext := &Ciphertext{
		C1:        c1,
		C2:        c2,
		IV:        iv,
		Level:     1,
		Timestamp: time.Now(),
	}

	// 计算密文MAC
	ciphertext.MAC = pre.computeCiphertextMAC(ciphertext)

	return ciphertext, nil
}

// computeCiphertextMAC 计算密文MAC
func (pre *ProxyReEncryption) computeCiphertextMAC(ct *Ciphertext) []byte {
	h := hmac.New(sha256.New, pre.config.HMACSecret)
	h.Write(ct.C1.X.Bytes())
	h.Write(ct.C1.Y.Bytes())
	h.Write(ct.C2)
	h.Write(ct.IV)
	h.Write([]byte{byte(ct.Level)})

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(ct.Timestamp.Unix()))
	h.Write(timeBytes)

	return h.Sum(nil)
}

// verifyCiphertextMAC 验证密文MAC
func (pre *ProxyReEncryption) verifyCiphertextMAC(ct *Ciphertext) bool {
	expectedMAC := pre.computeCiphertextMAC(ct)
	return hmac.Equal(ct.MAC, expectedMAC)
}

// ReEncrypt 重加密
func (pre *ProxyReEncryption) ReEncrypt(ct *Ciphertext, reKey *ReEncryptionKey) (*ReEncryptedCiphertext, error) {
	// 验证输入
	if ct.Level != 1 {
		return nil, fmt.Errorf("只能对第一级密文进行重加密")
	}

	if !pre.verifyCiphertextMAC(ct) {
		return nil, fmt.Errorf("密文完整性验证失败")
	}

	if !pre.verifyReKeyMAC(reKey) {
		return nil, fmt.Errorf("重加密密钥完整性验证失败")
	}

	// 检查重加密密钥是否过期
	if pre.config.EnableKeyExpiration && time.Now().After(reKey.ExpiresAt) {
		return nil, fmt.Errorf("重加密密钥已过期")
	}

	// 执行重加密转换
	c1PrimeX, c1PrimeY := pre.curve.ScalarMult(ct.C1.X, ct.C1.Y, reKey.Alpha.Bytes())
	c1Prime := &ECPoint{X: c1PrimeX, Y: c1PrimeY}

	// 创建重加密后的密文（保存原始C1用于 AAD 一致性）
	reEncryptedCt := &ReEncryptedCiphertext{
		Ciphertext: &Ciphertext{
			C1:        c1Prime,
			C2:        ct.C2, // 数据部分保持不变
			IV:        ct.IV,
			Level:     2,
			Timestamp: time.Now(),
		},
		OriginalC1:     ct.C1,
		OriginalFromID: reKey.FromID,
		ReEncryptedBy:  "proxy",
	}

	// 生成重加密证明
	reEncryptedCt.Proof = pre.generateReEncryptionProof(ct, reKey, reEncryptedCt.Ciphertext)

	// 计算新的MAC
	reEncryptedCt.Ciphertext.MAC = pre.computeCiphertextMAC(reEncryptedCt.Ciphertext)

	return reEncryptedCt, nil
}

// generateReEncryptionProof 生成重加密证明
func (pre *ProxyReEncryption) generateReEncryptionProof(originalCt *Ciphertext, reKey *ReEncryptionKey, newCt *Ciphertext) []byte {
	h := sha256.New()
	h.Write(originalCt.C1.X.Bytes())
	h.Write(originalCt.C1.Y.Bytes())
	h.Write(newCt.C1.X.Bytes())
	h.Write(newCt.C1.Y.Bytes())
	h.Write(reKey.Alpha.Bytes())
	h.Write(reKey.Beta.X.Bytes())
	h.Write(reKey.Beta.Y.Bytes())
	return h.Sum(nil)
}

// Decrypt 解密
func (pre *ProxyReEncryption) Decrypt(ct interface{}, recipientID string) ([]byte, error) {
	var ciphertext *Ciphertext
	var aadC1 *ECPoint

	switch v := ct.(type) {
	case *Ciphertext:
		ciphertext = v
		aadC1 = v.C1
	case *ReEncryptedCiphertext:
		ciphertext = v.Ciphertext
		// 二级密文使用原始C1作为 AAD，保持与加密时一致
		if v.OriginalC1 == nil {
			return nil, fmt.Errorf("重加密密文缺少原始C1")
		}
		aadC1 = v.OriginalC1
	default:
		return nil, fmt.Errorf("不支持的密文类型")
	}

	// 验证密文完整性
	if !pre.verifyCiphertextMAC(ciphertext) {
		return nil, fmt.Errorf("密文完整性验证失败")
	}

	// 计算共享密钥 = C1^privateKey
	pre.mu.RLock()
	recipientPrivateKey, exists := pre.privateKeys[recipientID]
	pre.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("接收者 %s 的私钥不存在", recipientID)
	}

	sharedX, sharedY := pre.curve.ScalarMult(ciphertext.C1.X, ciphertext.C1.Y, recipientPrivateKey.D.Bytes())

	// 从共享密钥派生AES密钥
	sharedSecret := append(sharedX.Bytes(), sharedY.Bytes()...)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("PRE_AES_KEY_DERIVATION"))

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, fmt.Errorf("派生AES密钥失败: %w", err)
	}

	// 解密数据（使用与加密时一致的 AAD）
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码块失败: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %w", err)
	}
	aad := append(aadC1.X.Bytes(), aadC1.Y.Bytes()...)
	plaintext, err := aesgcm.Open(nil, ciphertext.IV, ciphertext.C2, aad)
	if err != nil {
		return nil, fmt.Errorf("解密数据失败: %w", err)
	}

	return plaintext, nil
}

// GetReEncryptionKey 获取重加密密钥
func (pre *ProxyReEncryption) GetReEncryptionKey(fromID, toID string) (*ReEncryptionKey, error) {
	pre.mu.RLock()
	defer pre.mu.RUnlock()

	if fromKeys, exists := pre.reKeys[fromID]; exists {
		if reKey, exists := fromKeys[toID]; exists {
			// 检查是否过期
			if pre.config.EnableKeyExpiration && time.Now().After(reKey.ExpiresAt) {
				return nil, fmt.Errorf("重加密密钥已过期")
			}
			return reKey, nil
		}
	}

	return nil, fmt.Errorf("重加密密钥不存在")
}

// RevokeReEncryptionKey 撤销重加密密钥
func (pre *ProxyReEncryption) RevokeReEncryptionKey(fromID, toID string) error {
	pre.mu.Lock()
	defer pre.mu.Unlock()

	if fromKeys, exists := pre.reKeys[fromID]; exists {
		delete(fromKeys, toID)
		if len(fromKeys) == 0 {
			delete(pre.reKeys, fromID)
		}
		return nil
	}

	return fmt.Errorf("重加密密钥不存在")
}

// CleanupExpiredKeys 清理过期密钥
func (pre *ProxyReEncryption) CleanupExpiredKeys() int {
	if !pre.config.EnableKeyExpiration {
		return 0
	}

	pre.mu.Lock()
	defer pre.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for fromID, fromKeys := range pre.reKeys {
		for toID, reKey := range fromKeys {
			if now.After(reKey.ExpiresAt) {
				delete(fromKeys, toID)
				cleaned++
			}
		}
		if len(fromKeys) == 0 {
			delete(pre.reKeys, fromID)
		}
	}

	return cleaned
}
// 文件级新增方法：导入PEM密钥对与解析助手

// ImportKeyPairFromPEM 从证书PEM和私钥PEM导入用户密钥对
func (pre *ProxyReEncryption) ImportKeyPairFromPEM(userID string, certPEM []byte, keyPEM []byte) error {
    priv, err := parseECDSAPrivateKeyFromPEM(keyPEM)
    if err != nil {
        return fmt.Errorf("解析私钥失败: %w", err)
    }
    pub, err := parseECDSAPublicKeyFromCertPEM(certPEM)
    if err != nil {
        return fmt.Errorf("解析证书公钥失败: %w", err)
    }
    // 曲线校验，确保与系统曲线一致
    if priv.Curve != pre.curve || pub.Curve != pre.curve {
        return fmt.Errorf("密钥曲线不匹配，期望: %s", pre.curve.Params().Name)
    }

    pre.mu.Lock()
    pre.privateKeys[userID] = priv
    pre.publicKeys[userID] = pub
    pre.mu.Unlock()
    return nil
}

// ImportPrivateKeyPEM 仅从私钥PEM导入（公钥由私钥派生）
func (pre *ProxyReEncryption) ImportPrivateKeyPEM(userID string, keyPEM []byte) error {
    priv, err := parseECDSAPrivateKeyFromPEM(keyPEM)
    if err != nil {
        return fmt.Errorf("解析私钥失败: %w", err)
    }
    if priv.Curve != pre.curve {
        return fmt.Errorf("私钥曲线不匹配，期望: %s", pre.curve.Params().Name)
    }
    pub := &priv.PublicKey

    pre.mu.Lock()
    pre.privateKeys[userID] = priv
    pre.publicKeys[userID] = pub
    pre.mu.Unlock()
    return nil
}

// 解析PEM中的 ECDSA 私钥，支持 ECPrivateKey 和 PKCS#8
func parseECDSAPrivateKeyFromPEM(keyPEM []byte) (*ecdsa.PrivateKey, error) {
    block, _ := pem.Decode(keyPEM)
    if block == nil {
        return nil, fmt.Errorf("PEM私钥解析失败: 空数据或格式错误")
    }
    // 尝试 EC 私钥
    if priv, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
        return priv, nil
    }
    // 尝试 PKCS#8
    v, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("PKCS#8私钥解析失败: %w", err)
    }
    priv, ok := v.(*ecdsa.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("私钥类型不是 ECDSA")
    }
    return priv, nil
}

// 从证书PEM解析 ECDSA 公钥
func parseECDSAPublicKeyFromCertPEM(certPEM []byte) (*ecdsa.PublicKey, error) {
    block, _ := pem.Decode(certPEM)
    if block == nil {
        return nil, fmt.Errorf("PEM证书解析失败: 空数据或格式错误")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("X.509证书解析失败: %w", err)
    }
    pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
    if !ok {
        return nil, fmt.Errorf("证书公钥类型不是 ECDSA")
    }
    return pub, nil
}

