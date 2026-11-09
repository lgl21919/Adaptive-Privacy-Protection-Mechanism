//go:build pre_demo

package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/tap-thesis/privacy-protection-data/pkg/crypto"
	"os"
)

// BasicUsageExample 基本使用示例
func BasicUsageExample() {
	fmt.Println("=== 代理重加密基本使用示例 ===")

	// 1. 创建代理重加密系统
	pre := crypto.NewProxyReEncryption(nil)
	fmt.Println("✓ 代理重加密系统创建成功")

	// 2. 导入 User1@org1.example.com 的密钥对
	fmt.Println("\n--- 导入用户密钥对 ---")
	
	// User1@org1.example.com (数据拥有者)
	certPEM, err := os.ReadFile("../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/cert.pem")
	if err != nil {
		log.Fatalf("读取 User1 证书失败: %v", err)
	}
	
	keyPEM, err := os.ReadFile("../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/50a64a07697b2576ad8be28b307921995b82c93f84ed2f14ffd89461fe33eaeb_sk")
	if err != nil {
		log.Fatalf("读取 User1 私钥失败: %v", err)
	}
	
	err = pre.ImportKeyPairFromPEM("User1@org1.example.com", certPEM, keyPEM)
	if err != nil {
		log.Fatalf("导入 User1 密钥对失败: %v", err)
	}
	
	// 获取导入后的公钥
	alicePub, err := pre.GetPublicKey("User1@org1.example.com")
	if err != nil {
		log.Fatalf("获取 User1 公钥失败: %v", err)
	}
	
	fmt.Printf("✓ User1 密钥对导入成功\n")
	fmt.Printf("  公钥X: %s\n", alicePub.X.String()[:20]+"...")
	fmt.Printf("  公钥Y: %s\n", alicePub.Y.String()[:20]+"...")

	// Bob (数据接收者)
	_, _, err = pre.GenerateKeyPair("bob")
	if err != nil {
		log.Fatalf("生成Bob密钥对失败: %v", err)
	}
	fmt.Printf("✓ Bob密钥对生成成功\n")

	// 3. Alice加密数据
	fmt.Println("\n--- 数据加密 ---")
	//originalData := []byte("这是Alice的机密学术论文：《基于椭圆曲线的代理重加密算法研究》")
	//fmt.Printf("原始数据: %s\n", string(originalData))
	// 生成一个随机的AES-256密钥 (32字节)
	originalData := make([]byte, 32)
	_, err = rand.Read(originalData)
	if err != nil {
		log.Fatalf("生成随机AES密钥失败: %v", err)
	}
	fmt.Printf("原始AES密钥: %x\n", originalData)

	ciphertext, err := pre.Encrypt(originalData, "User1@org1.example.com")
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}
	fmt.Printf("✓ 数据加密成功，密文级别: %d\n", ciphertext.Level)
	fmt.Printf("  密文大小: %d 字节\n", len(ciphertext.C2))

	// 4. Alice验证自己可以解密
	fmt.Println("\n--- 数据拥有者解密验证 ---")
	decryptedData, err := pre.Decrypt(ciphertext, "User1@org1.example.com")
	if err != nil {
		log.Fatalf("Alice解密失败: %v", err)
	}
	fmt.Printf("✓ Alice解密成功: %s\n", string(decryptedData))

	// 5. 生成从Alice到Bob的重加密密钥
	fmt.Println("\n--- 生成重加密密钥 ---")
	reKey, err := pre.GenerateReEncryptionKey("User1@org1.example.com", "bob", 24*time.Hour)
	if err != nil {
		log.Fatalf("生成重加密密钥失败: %v", err)
	}
	fmt.Printf("✓ 重加密密钥生成成功 (Alice -> Bob)\n")
	fmt.Printf("  密钥ID: %s -> %s\n", reKey.FromID, reKey.ToID)
	fmt.Printf("  创建时间: %s\n", reKey.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  过期时间: %s\n", reKey.ExpiresAt.Format("2006-01-02 15:04:05"))

	// 6. 代理服务器执行重加密
	fmt.Println("\n--- 代理重加密 ---")
	reEncryptedCt, err := pre.ReEncrypt(ciphertext, reKey)
	if err != nil {
		log.Fatalf("重加密失败: %v", err)
	}
	fmt.Printf("✓ 重加密成功，新密文级别: %d\n", reEncryptedCt.Level)
	fmt.Printf("  原始发送者: %s\n", reEncryptedCt.OriginalFromID)
	fmt.Printf("  重加密执行者: %s\n", reEncryptedCt.ReEncryptedBy)

	// 7. Bob解密重加密后的密文
	fmt.Println("\n--- 目标用户解密 ---")
	bobDecryptedData, err := pre.Decrypt(reEncryptedCt, "bob")
	if err != nil {
		log.Fatalf("Bob解密失败: %v", err)
	}
	fmt.Printf("✓ Bob解密成功: %s\n", string(bobDecryptedData))

	// 8. 验证数据完整性
	if string(originalData) == string(bobDecryptedData) {
		fmt.Println("✓ 数据完整性验证通过")
	} else {
		fmt.Println("✗ 数据完整性验证失败")
	}

	fmt.Println("\n=== 基本使用示例完成 ===")
}

// MultiUserExample 多用户使用示例
func MultiUserExample() {
	fmt.Println("\n=== 多用户代理重加密示例 ===")

	pre := crypto.NewProxyReEncryption(nil)

	// 创建多个用户
	users := []string{"author", "editor", "reviewer1", "reviewer2", "publisher"}
	fmt.Printf("创建用户: %v\n", users)

	for _, user := range users {
		_, _, err := pre.GenerateKeyPair(user)
		if err != nil {
			log.Fatalf("生成%s密钥对失败: %v", user, err)
		}
		fmt.Printf("✓ %s 密钥对生成成功\n", user)
	}

	// 作者加密论文
	paperContent := []byte("《区块链环境下的隐私保护代理重加密机制研究》- 这是一篇关于代理重加密在区块链中应用的学术论文。")
	fmt.Printf("\n论文内容: %s\n", string(paperContent))

	authorCiphertext, err := pre.Encrypt(paperContent, "author")
	if err != nil {
		log.Fatalf("作者加密失败: %v", err)
	}
	fmt.Println("✓ 作者加密论文成功")

	// 为不同角色生成重加密密钥
	recipients := map[string]time.Duration{
		"editor":    7 * 24 * time.Hour,  // 编辑器7天访问权限
		"reviewer1": 14 * 24 * time.Hour, // 审稿人14天访问权限
		"reviewer2": 14 * 24 * time.Hour, // 审稿人14天访问权限
		"publisher": 365 * 24 * time.Hour, // 出版商1年访问权限
	}

	fmt.Println("\n--- 生成多个重加密密钥 ---")
	reKeys := make(map[string]*crypto.ReEncryptionKey)
	for recipient, expiration := range recipients {
		reKey, err := pre.GenerateReEncryptionKey("author", recipient, expiration)
		if err != nil {
			log.Fatalf("生成重加密密钥失败 (author -> %s): %v", recipient, err)
		}
		reKeys[recipient] = reKey
		fmt.Printf("✓ 重加密密钥生成成功 (author -> %s), 有效期: %v\n", recipient, expiration)
	}

	// 为每个接收者执行重加密和解密
	fmt.Println("\n--- 多用户访问测试 ---")
	for recipient := range recipients {
		// 重加密
		reEncryptedCt, err := pre.ReEncrypt(authorCiphertext, reKeys[recipient])
		if err != nil {
			log.Fatalf("%s重加密失败: %v", recipient, err)
		}

		// 解密
		decryptedData, err := pre.Decrypt(reEncryptedCt, recipient)
		if err != nil {
			log.Fatalf("%s解密失败: %v", recipient, err)
		}

		fmt.Printf("✓ %s 成功访问论文内容\n", recipient)
		
		// 验证内容
		if string(paperContent) == string(decryptedData) {
			fmt.Printf("  - 内容验证通过\n")
		} else {
			fmt.Printf("  - 内容验证失败\n")
		}
	}

	fmt.Println("\n=== 多用户示例完成 ===")
}

// SecurityExample 安全特性示例
func SecurityExample() {
	fmt.Println("\n=== 安全特性演示 ===")

	pre := crypto.NewProxyReEncryption(nil)

	// 生成用户密钥对
	pre.GenerateKeyPair("User1@org1.example.com")
	pre.GenerateKeyPair("bob")
	pre.GenerateKeyPair("charlie")

	testData := []byte("机密数据")

	// 1. 密文完整性保护
	fmt.Println("\n--- 密文完整性保护测试 ---")
	ciphertext, _ := pre.Encrypt(testData, "User1@org1.example.com")
	
	// 保存原始MAC
	originalMAC := make([]byte, len(ciphertext.MAC))
	copy(originalMAC, ciphertext.MAC)
	
	// 篡改MAC
	ciphertext.MAC[0] ^= 0xFF
	
	// 尝试解密篡改的密文
	_, err := pre.Decrypt(ciphertext, "User1@org1.example.com")
	if err != nil {
		fmt.Printf("✓ 密文完整性验证成功，检测到篡改: %v\n", err)
	} else {
		fmt.Printf("✗ 密文完整性验证失败，未检测到篡改\n")
	}
	
	// 恢复正确的MAC
	copy(ciphertext.MAC, originalMAC)

	// 2. 重加密密钥完整性保护测试
	fmt.Println("\n--- 重加密密钥完整性保护测试 ---")
	reKey, _ := pre.GenerateReEncryptionKey("User1@org1.example.com", "bob", time.Hour)
	
	// 篡改重加密密钥的MAC
	originalReKeyMAC := make([]byte, len(reKey.MAC))
	copy(originalReKeyMAC, reKey.MAC)
	reKey.MAC[0] ^= 0xFF
	
	// 尝试使用篡改的重加密密钥
	_, err = pre.ReEncrypt(ciphertext, reKey)
	if err != nil {
		fmt.Printf("✓ 重加密密钥完整性验证成功，检测到篡改: %v\n", err)
	} else {
		fmt.Printf("✗ 重加密密钥完整性验证失败，未检测到篡改\n")
	}

	// 3. 访问控制测试
	fmt.Println("\n--- 访问控制测试 ---")
	
	// Charlie尝试解密Alice的密文（没有重加密密钥）
	_, err = pre.Decrypt(ciphertext, "charlie")
	if err != nil {
		fmt.Printf("✓ 访问控制成功，Charlie无法解密Alice的密文: %v\n", err)
	} else {
		fmt.Printf("✗ 访问控制失败，Charlie能够解密Alice的密文\n")
	}

	// 4. 密钥过期测试
	fmt.Println("\n--- 密钥过期测试 ---")
	
	// 生成一个很短过期时间的重加密密钥
	shortReKey, _ := pre.GenerateReEncryptionKey("User1@org1.example.com", "bob", 100*time.Millisecond)
	
	// 等待密钥过期
	time.Sleep(200 * time.Millisecond)
	
	// 尝试使用过期的重加密密钥
	_, err = pre.ReEncrypt(ciphertext, shortReKey)
	if err != nil {
		fmt.Printf("✓ 密钥过期检查成功，过期密钥被拒绝: %v\n", err)
	} else {
		fmt.Printf("✗ 密钥过期检查失败，过期密钥仍可使用\n")
	}

	fmt.Println("\n=== 安全特性演示完成 ===")
}

// PerformanceExample 性能测试示例
func PerformanceExample() {
	fmt.Println("\n=== 性能测试示例 ===")

	pre := crypto.NewProxyReEncryption(nil)
	pre.GenerateKeyPair("alice")
	pre.GenerateKeyPair("bob")

	testData := []byte("性能测试数据 - 这是一个用于测试加密解密性能的数据块")
	testCount := 100

	// 加密性能测试
	fmt.Printf("\n--- 加密性能测试 (%d次) ---\n", testCount)
	start := time.Now()
	var lastCiphertext *crypto.Ciphertext
	
	for i := 0; i < testCount; i++ {
		ct, err := pre.Encrypt(testData, "alice")
		if err != nil {
			log.Fatalf("加密失败: %v", err)
		}
		lastCiphertext = ct
	}
	
	encryptDuration := time.Since(start)
	fmt.Printf("✓ 加密性能: %d次加密耗时 %v\n", testCount, encryptDuration)
	fmt.Printf("  平均每次加密: %v\n", encryptDuration/time.Duration(testCount))
	fmt.Printf("  加密吞吐量: %.2f ops/sec\n", float64(testCount)/encryptDuration.Seconds())

	// 解密性能测试
	fmt.Printf("\n--- 解密性能测试 (%d次) ---\n", testCount)
	start = time.Now()
	
	for i := 0; i < testCount; i++ {
		_, err := pre.Decrypt(lastCiphertext, "alice")
		if err != nil {
			log.Fatalf("解密失败: %v", err)
		}
	}
	
	decryptDuration := time.Since(start)
	fmt.Printf("✓ 解密性能: %d次解密耗时 %v\n", testCount, decryptDuration)
	fmt.Printf("  平均每次解密: %v\n", decryptDuration/time.Duration(testCount))
	fmt.Printf("  解密吞吐量: %.2f ops/sec\n", float64(testCount)/decryptDuration.Seconds())

	// 重加密性能测试
	reKey, _ := pre.GenerateReEncryptionKey("alice", "bob", time.Hour)
	
	fmt.Printf("\n--- 重加密性能测试 (%d次) ---\n", testCount)
	start = time.Now()
	
	for i := 0; i < testCount; i++ {
		_, err := pre.ReEncrypt(lastCiphertext, reKey)
		if err != nil {
			log.Fatalf("重加密失败: %v", err)
		}
	}
	
	reEncryptDuration := time.Since(start)
	fmt.Printf("✓ 重加密性能: %d次重加密耗时 %v\n", testCount, reEncryptDuration)
	fmt.Printf("  平均每次重加密: %v\n", reEncryptDuration/time.Duration(testCount))
	fmt.Printf("  重加密吞吐量: %.2f ops/sec\n", float64(testCount)/reEncryptDuration.Seconds())

	fmt.Println("\n=== 性能测试完成 ===")
}

func main() {
	pre := crypto.NewProxyReEncryption(nil)

	// 可选：导入 Fabric CA 用户私钥（仅私钥导入）
	keyPEM, err := os.ReadFile(`../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/50a64a07697b2576ad8be28b307921995b82c93f84ed2f14ffd89461fe33eaeb_sk`)
	if err == nil {
		if err := pre.ImportPrivateKeyPEM("User1@org1.example.com", keyPEM); err != nil {
			log.Printf("导入Fabric密钥失败: %v (继续使用生成的密钥)", err)
		} else {
			fmt.Println("✓ Fabric用户密钥导入成功")
		}
	} else {
		log.Printf("无法读取Fabric密钥文件: %v (将使用生成的密钥)", err)
	}

	fmt.Println("\n🚀 代理重加密系统使用示例")
	fmt.Println("========================================")

	// 演示密钥存储和打印
	KeyStorageExample(pre)

	// 运行各种示例
	BasicUsageExample()
	MultiUserExample()
	SecurityExample()
	PerformanceExample()

	fmt.Println("\n🎉 所有示例运行完成！")
	fmt.Println("========================================")
}

// KeyStorageExample 密钥存储和打印示例
func KeyStorageExample(pre *crypto.ProxyReEncryption) {
	fmt.Println("\n=== 密钥存储和打印示例 ===")
	
	// 1. 生成一些测试用户密钥对
	fmt.Println("\n--- 生成用户密钥对 ---")
	users := []string{"alice", "bob", "charlie"}
	for _, user := range users {
		_, _, err := pre.GenerateKeyPair(user)
		if err != nil {
			log.Printf("生成%s密钥对失败: %v", user, err)
			continue
		}
		fmt.Printf("✓ %s 密钥对生成成功\n", user)
	}
	
	// 2. 列出所有用户
	fmt.Println("\n--- 已注册的用户列表 ---")
	allUsers := pre.ListAllUsers()
	fmt.Printf("已注册用户数量: %d\n", len(allUsers))
	for _, userID := range allUsers {
		fmt.Printf("  - %s\n", userID)
	}
	
	// 3. 打印每个用户的密钥信息
	fmt.Println("\n--- 用户密钥详细信息 ---")
	for _, userID := range allUsers {
		if err := pre.PrintKeyInfo(userID); err != nil {
			log.Printf("打印%s密钥信息失败: %v", userID, err)
		}
	}
	
	// 4. 演示如何获取和使用密钥
	fmt.Println("\n--- 密钥使用示例 ---")
	
	// 获取公钥用于加密
	alicePubKey, err := pre.GetPublicKey("alice")
	if err != nil {
		log.Printf("获取alice公钥失败: %v", err)
	} else {
		fmt.Printf("✓ 获取alice公钥成功\n")
		fmt.Printf("  公钥X (前20字符): %s...\n", alicePubKey.X.String()[:20])
		fmt.Printf("  公钥Y (前20字符): %s...\n", alicePubKey.Y.String()[:20])
	}
	
	// 获取私钥用于解密（注意：实际应用中不应直接暴露私钥）
	alicePrivKey, err := pre.GetPrivateKey("alice")
	if err != nil {
		log.Printf("获取alice私钥失败: %v", err)
	} else {
		fmt.Printf("✓ 获取alice私钥成功\n")
		fmt.Printf("  私钥D (前20字符): %s...\n", alicePrivKey.D.String()[:20])
		fmt.Printf("  警告: 实际应用中不应直接访问或打印私钥！\n")
	}
	
	// 5. 演示密钥在加密/解密中的使用
	fmt.Println("\n--- 密钥在加密/解密中的使用流程 ---")
	testData := []byte("测试数据")
	
	// 加密：使用alice的公钥
	fmt.Println("1. 加密过程：")
	fmt.Println("   - 系统从 publicKeys[\"alice\"] 获取alice的公钥")
	fmt.Println("   - 使用公钥计算共享密钥: sharedKey = pubKey^k")
	fmt.Println("   - 派生AES密钥并加密数据")
	ciphertext, err := pre.Encrypt(testData, "alice")
	if err != nil {
		log.Printf("加密失败: %v", err)
	} else {
		fmt.Printf("   ✓ 加密成功，使用了alice的公钥\n")
	}
	
	// 解密：使用alice的私钥
	fmt.Println("\n2. 解密过程：")
	fmt.Println("   - 系统从 privateKeys[\"alice\"] 获取alice的私钥")
	fmt.Println("   - 使用私钥计算共享密钥: sharedKey = C1^privateKey")
	fmt.Println("   - 派生AES密钥并解密数据")
	decryptedData, err := pre.Decrypt(ciphertext, "alice")
	if err != nil {
		log.Printf("解密失败: %v", err)
	} else {
		fmt.Printf("   ✓ 解密成功，使用了alice的私钥\n")
		fmt.Printf("   原始数据: %s\n", string(testData))
		fmt.Printf("   解密数据: %s\n", string(decryptedData))
	}
	
	// 6. 演示密钥在重加密中的使用
	fmt.Println("\n3. 重加密过程：")
	fmt.Println("   - 系统从 privateKeys[\"alice\"] 获取alice的私钥")
	fmt.Println("   - 系统从 privateKeys[\"bob\"] 获取bob的私钥")
	fmt.Println("   - 计算重加密密钥: alpha = d_alice * d_bob^(-1) mod n")
	reKey, err := pre.GenerateReEncryptionKey("alice", "bob", time.Hour)
	if err != nil {
		log.Printf("生成重加密密钥失败: %v", err)
	} else {
		fmt.Printf("   ✓ 重加密密钥生成成功，使用了alice和bob的私钥\n")
		fmt.Printf("   Alpha值 (前20字符): %s...\n", reKey.Alpha.String()[:20])
	}
	
	fmt.Println("\n=== 密钥存储和打印示例完成 ===")
}