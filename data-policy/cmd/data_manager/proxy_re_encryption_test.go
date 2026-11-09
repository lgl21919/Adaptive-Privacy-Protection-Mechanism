package main

import (
	"bytes"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/tap-thesis/privacy-protection-data/pkg/crypto"
)

// TestBasicProxyReEncryption 基本代理重加密测试
func TestBasicProxyReEncryption(t *testing.T) {
	fmt.Println("=== 基本代理重加密测试 ===")

	// 创建代理重加密系统
	pre := crypto.NewProxyReEncryption(nil)

	// 生成用户密钥对
	_, _, err := pre.GenerateKeyPair("alice")
	if err != nil {
		t.Fatalf("生成Alice密钥对失败: %v", err)
	}
	fmt.Printf("✓ Alice密钥对生成成功\n")

	_, _, err = pre.GenerateKeyPair("bob")
	if err != nil {
		t.Fatalf("生成Bob密钥对失败: %v", err)
	}
	fmt.Printf("✓ Bob密钥对生成成功\n")

	// 测试数据
	originalData := []byte("这是一个机密的学术论文内容，需要通过代理重加密进行安全传输。")
	fmt.Printf("原始数据: %s\n", string(originalData))

	// Alice加密数据
	ciphertext, err := pre.Encrypt(originalData, "alice")
	if err != nil {
		t.Fatalf("Alice加密失败: %v", err)
	}
	fmt.Printf("✓ Alice加密成功，密文级别: %d\n", ciphertext.Level)

	// Alice直接解密验证
	decryptedData, err := pre.Decrypt(ciphertext, "alice")
	if err != nil {
		t.Fatalf("Alice解密失败: %v", err)
	}
	if !bytes.Equal(originalData, decryptedData) {
		t.Fatalf("Alice解密结果不匹配")
	}
	fmt.Printf("✓ Alice直接解密验证成功\n")

	// 生成从Alice到Bob的重加密密钥
	reKey, err := pre.GenerateReEncryptionKey("alice", "bob", 24*time.Hour)
	if err != nil {
		t.Fatalf("生成重加密密钥失败: %v", err)
	}
	fmt.Printf("✓ 重加密密钥生成成功 (Alice -> Bob)\n")

	// 执行重加密
	reEncryptedCt, err := pre.ReEncrypt(ciphertext, reKey)
	if err != nil {
		t.Fatalf("重加密失败: %v", err)
	}
	fmt.Printf("✓ 重加密成功，新密文级别: %d\n", reEncryptedCt.Level)

	// Bob解密重加密后的密文
	bobDecryptedData, err := pre.Decrypt(reEncryptedCt, "bob")
	if err != nil {
		t.Fatalf("Bob解密重加密密文失败: %v", err)
	}
	if !bytes.Equal(originalData, bobDecryptedData) {
		t.Fatalf("Bob解密结果不匹配")
	}
	fmt.Printf("✓ Bob成功解密重加密密文\n")
    fmt.Printf("解密结果: %s\n", string(bobDecryptedData))

    fmt.Println("=== 基本代理重加密测试完成 ===")
}

// TestMultiUserProxyReEncryption 多用户代理重加密测试
func TestMultiUserProxyReEncryption(t *testing.T) {
	fmt.Println("=== 多用户代理重加密测试 ===")

	pre := crypto.NewProxyReEncryption(nil)

	// 生成多个用户的密钥对
	users := []string{"author", "editor", "reviewer1", "reviewer2", "publisher"}
	for _, user := range users {
		_, _, err := pre.GenerateKeyPair(user)
		if err != nil {
			t.Fatalf("生成%s密钥对失败: %v", user, err)
		}
		fmt.Printf("✓ %s密钥对生成成功\n", user)
	}

	// 作者加密论文
	paperContent := []byte("这是一篇关于区块链隐私保护的学术论文，包含创新的代理重加密算法。")
	authorCiphertext, err := pre.Encrypt(paperContent, "author")
	if err != nil {
		t.Fatalf("作者加密失败: %v", err)
	}
	fmt.Printf("✓ 作者加密论文成功\n")

	// 生成多个重加密密钥
	recipients := []string{"editor", "reviewer1", "reviewer2"}
	reKeys := make(map[string]*crypto.ReEncryptionKey)

	for _, recipient := range recipients {
		reKey, err := pre.GenerateReEncryptionKey("author", recipient, 7*24*time.Hour)
		if err != nil {
			t.Fatalf("生成重加密密钥失败 (author -> %s): %v", recipient, err)
		}
		reKeys[recipient] = reKey
		fmt.Printf("✓ 重加密密钥生成成功 (author -> %s)\n", recipient)
	}

	// 为每个接收者执行重加密和解密
	for _, recipient := range recipients {
		// 重加密
		reEncryptedCt, err := pre.ReEncrypt(authorCiphertext, reKeys[recipient])
		if err != nil {
			t.Fatalf("%s重加密失败: %v", recipient, err)
		}

		// 解密
		decryptedData, err := pre.Decrypt(reEncryptedCt, recipient)
		if err != nil {
			t.Fatalf("%s解密失败: %v", recipient, err)
		}

		if !bytes.Equal(paperContent, decryptedData) {
			t.Fatalf("%s解密结果不匹配", recipient)
		}
		fmt.Printf("✓ %s成功解密论文\n", recipient)
	}

	fmt.Println("=== 多用户代理重加密测试完成 ===")
}

// TestKeyExpiration 密钥过期测试
func TestKeyExpiration(t *testing.T) {
	fmt.Println("=== 密钥过期测试 ===")

	// 创建启用密钥过期的配置
	config := &crypto.Config{
		DefaultKeyExpiration:   365 * 24 * time.Hour,
		DefaultReKeyExpiration: 30 * 24 * time.Hour,
		HMACSecret:            []byte("TEST_HMAC_SECRET"),
		EnableKeyExpiration:   true,
	}
	pre := crypto.NewProxyReEncryption(config)

	// 生成用户密钥对
	_, _, err := pre.GenerateKeyPair("alice")
	if err != nil {
		t.Fatalf("生成Alice密钥对失败: %v", err)
	}

	_, _, err = pre.GenerateKeyPair("bob")
	if err != nil {
		t.Fatalf("生成Bob密钥对失败: %v", err)
	}

	// 生成一个很短过期时间的重加密密钥
	shortExpiration := 100 * time.Millisecond
	reKey, err := pre.GenerateReEncryptionKey("alice", "bob", shortExpiration)
	if err != nil {
		t.Fatalf("生成重加密密钥失败: %v", err)
	}
	fmt.Printf("✓ 生成短期重加密密钥成功，过期时间: %v\n", shortExpiration)

	// 等待密钥过期
	time.Sleep(200 * time.Millisecond)

	// 尝试使用过期的重加密密钥
	testData := []byte("测试数据")
	ciphertext, err := pre.Encrypt(testData, "alice")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	_, err = pre.ReEncrypt(ciphertext, reKey)
	if err == nil {
		t.Fatalf("期望重加密失败（密钥已过期），但成功了")
	}
	fmt.Printf("✓ 过期密钥重加密正确失败: %v\n", err)

	// 测试密钥清理功能
	cleaned := pre.CleanupExpiredKeys()
	fmt.Printf("✓ 清理过期密钥数量: %d\n", cleaned)

	fmt.Println("=== 密钥过期测试完成 ===")
}

// TestSecurityFeatures 安全特性测试
func TestSecurityFeatures(t *testing.T) {
	fmt.Println("=== 安全特性测试 ===")

	pre := crypto.NewProxyReEncryption(nil)

	// 生成用户密钥对
	_, _, err := pre.GenerateKeyPair("alice")
	if err != nil {
		t.Fatalf("生成Alice密钥对失败: %v", err)
	}

	_, _, err = pre.GenerateKeyPair("bob")
	if err != nil {
		t.Fatalf("生成Bob密钥对失败: %v", err)
	}

	// 测试数据
	testData := []byte("机密数据")
	
	// 加密
	ciphertext, err := pre.Encrypt(testData, "alice")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 测试密文完整性验证
	originalMAC := make([]byte, len(ciphertext.MAC))
	copy(originalMAC, ciphertext.MAC)
	
	// 篡改密文MAC
	ciphertext.MAC[0] ^= 0xFF
	
	// 尝试解密篡改的密文
	_, err = pre.Decrypt(ciphertext, "alice")
	if err == nil {
		t.Fatalf("期望解密失败（MAC被篡改），但成功了")
	}
	fmt.Printf("✓ 密文完整性验证正确失败: %v\n", err)

	// 恢复正确的MAC
	copy(ciphertext.MAC, originalMAC)

	// 验证正常解密
	decryptedData, err := pre.Decrypt(ciphertext, "alice")
	if err != nil {
		t.Fatalf("正常解密失败: %v", err)
	}
	if !bytes.Equal(testData, decryptedData) {
		t.Fatalf("解密结果不匹配")
	}
	fmt.Printf("✓ 恢复MAC后解密成功\n")

	fmt.Println("=== 安全特性测试完成 ===")
}

// TestErrorHandling 错误处理测试
func TestErrorHandling(t *testing.T) {
	fmt.Println("=== 错误处理测试 ===")

	pre := crypto.NewProxyReEncryption(nil)

	// 测试不存在用户的加密
	_, err := pre.Encrypt([]byte("test"), "nonexistent")
	if err == nil {
		t.Fatalf("期望加密失败（用户不存在），但成功了")
	}
	fmt.Printf("✓ 不存在用户加密正确失败: %v\n", err)

	// 测试不存在用户的解密
	pre.GenerateKeyPair("alice")
	ciphertext, _ := pre.Encrypt([]byte("test"), "alice")
	
	_, err = pre.Decrypt(ciphertext, "nonexistent")
	if err == nil {
		t.Fatalf("期望解密失败（用户不存在），但成功了")
	}
	fmt.Printf("✓ 不存在用户解密正确失败: %v\n", err)

	// 测试生成重加密密钥时用户不存在
	_, err = pre.GenerateReEncryptionKey("nonexistent", "alice", time.Hour)
	if err == nil {
		t.Fatalf("期望生成重加密密钥失败（源用户不存在），但成功了")
	}
	fmt.Printf("✓ 源用户不存在时生成重加密密钥正确失败: %v\n", err)

	_, err = pre.GenerateReEncryptionKey("alice", "nonexistent", time.Hour)
	if err == nil {
		t.Fatalf("期望生成重加密密钥失败（目标用户不存在），但成功了")
	}
	fmt.Printf("✓ 目标用户不存在时生成重加密密钥正确失败: %v\n", err)

	fmt.Println("=== 错误处理测试完成 ===")
}

// TestPerformance 性能测试
func TestPerformance(t *testing.T) {
	fmt.Println("=== 性能测试 ===")

	pre := crypto.NewProxyReEncryption(nil)

	// 生成用户密钥对
	pre.GenerateKeyPair("alice")
	pre.GenerateKeyPair("bob")

	// 测试数据
	testData := []byte("这是一个用于性能测试的数据块，包含一些文本内容用于测试加密解密性能。")

	// 测试加密性能
	encryptCount := 100
	start := time.Now()
	var ciphertext *crypto.Ciphertext
	var err error

	for i := 0; i < encryptCount; i++ {
		ciphertext, err = pre.Encrypt(testData, "alice")
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}
	}
	encryptDuration := time.Since(start)
	fmt.Printf("✓ 加密性能: %d次加密耗时 %v，平均每次 %v\n", 
		encryptCount, encryptDuration, encryptDuration/time.Duration(encryptCount))

	// 测试解密性能
	decryptCount := 100
	start = time.Now()

	for i := 0; i < decryptCount; i++ {
		_, err = pre.Decrypt(ciphertext, "alice")
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}
	}
	decryptDuration := time.Since(start)
	fmt.Printf("✓ 解密性能: %d次解密耗时 %v，平均每次 %v\n", 
		decryptCount, decryptDuration, decryptDuration/time.Duration(decryptCount))

	// 测试重加密性能
	reKey, err := pre.GenerateReEncryptionKey("alice", "bob", time.Hour)
	if err != nil {
		t.Fatalf("生成重加密密钥失败: %v", err)
	}

	reEncryptCount := 100
	start = time.Now()

	for i := 0; i < reEncryptCount; i++ {
		_, err = pre.ReEncrypt(ciphertext, reKey)
		if err != nil {
			t.Fatalf("重加密失败: %v", err)
		}
	}
	reEncryptDuration := time.Since(start)
	fmt.Printf("✓ 重加密性能: %d次重加密耗时 %v，平均每次 %v\n", 
		reEncryptCount, reEncryptDuration, reEncryptDuration/time.Duration(reEncryptCount))

	fmt.Println("=== 性能测试完成 ===")
}

// TestConcurrency 并发测试
func TestConcurrency(t *testing.T) {
	fmt.Println("=== 并发测试 ===")

	pre := crypto.NewProxyReEncryption(nil)

	// 生成用户密钥对
	userCount := 10
	for i := 0; i < userCount; i++ {
		userID := fmt.Sprintf("user%d", i)
		_, _, err := pre.GenerateKeyPair(userID)
		if err != nil {
			t.Fatalf("生成%s密钥对失败: %v", userID, err)
		}
	}

	// 并发加密测试
	concurrency := 50
	done := make(chan bool, concurrency)
	errors := make(chan error, concurrency)

	testData := []byte("并发测试数据")

	start := time.Now()
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			userID := fmt.Sprintf("user%d", id%userCount)
			
			// 加密
			ciphertext, err := pre.Encrypt(testData, userID)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d 加密失败: %v", id, err)
				return
			}

			// 解密
			decryptedData, err := pre.Decrypt(ciphertext, userID)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d 解密失败: %v", id, err)
				return
			}

			if !bytes.Equal(testData, decryptedData) {
				errors <- fmt.Errorf("goroutine %d 解密结果不匹配", id)
				return
			}

			done <- true
		}(i)
	}

	// 等待所有goroutine完成
	completed := 0
	for completed < concurrency {
		select {
		case <-done:
			completed++
		case err := <-errors:
			t.Fatalf("并发测试失败: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatalf("并发测试超时")
		}
	}

	duration := time.Since(start)
	fmt.Printf("✓ 并发测试完成: %d个goroutine，耗时 %v\n", concurrency, duration)

	fmt.Println("=== 并发测试完成 ===")
}

// BenchmarkEncryption 加密基准测试
func BenchmarkEncryption(b *testing.B) {
	pre := crypto.NewProxyReEncryption(nil)
	pre.GenerateKeyPair("alice")
	
	testData := []byte("基准测试数据")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pre.Encrypt(testData, "alice")
		if err != nil {
			b.Fatalf("加密失败: %v", err)
		}
	}
}

// BenchmarkDecryption 解密基准测试
func BenchmarkDecryption(b *testing.B) {
	pre := crypto.NewProxyReEncryption(nil)
	pre.GenerateKeyPair("alice")
	
	testData := []byte("基准测试数据")
	ciphertext, _ := pre.Encrypt(testData, "alice")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pre.Decrypt(ciphertext, "alice")
		if err != nil {
			b.Fatalf("解密失败: %v", err)
		}
	}
}

// BenchmarkReEncryption 重加密基准测试
func BenchmarkReEncryption(b *testing.B) {
	pre := crypto.NewProxyReEncryption(nil)
	pre.GenerateKeyPair("alice")
	pre.GenerateKeyPair("bob")
	
	testData := []byte("基准测试数据")
	ciphertext, _ := pre.Encrypt(testData, "alice")
	reKey, _ := pre.GenerateReEncryptionKey("alice", "bob", time.Hour)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pre.ReEncrypt(ciphertext, reKey)
		if err != nil {
			b.Fatalf("重加密失败: %v", err)
		}
	}
}

// 运行所有测试的主函数
func RunAllTests() {
	log.Println("开始运行代理重加密系统完整测试套件...")
	
	// 这里可以添加测试运行逻辑
	// 在实际使用中，通过 go test 命令运行
}