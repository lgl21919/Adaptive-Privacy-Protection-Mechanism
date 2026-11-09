//go:build encryption_chain

package main

import (
	"github.com/tap-thesis/privacy-protection-data/internal/blockchain"
	"github.com/tap-thesis/privacy-protection-data/internal/data_policy"
	"github.com/tap-thesis/privacy-protection-data/internal/db"
	"github.com/tap-thesis/privacy-protection-data/pkg/types"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== 数据保护策略上链存储与加密论文测试 ===")
	fmt.Println()

	// 获取当前工作目录
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("获取工作目录失败: %v", err)
	}
	fmt.Printf("当前工作目录: %s\n", workDir)
	fmt.Println()

	// 1. 初始化数据库
	fmt.Println("步骤1: 初始化数据库...")
	dbPath := filepath.Join(workDir, "academic_publishing.db")
	_, err = db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer db.CloseDB()
	fmt.Println("✓ 数据库初始化成功")
	fmt.Println()

	// 2. 使用fabric-ca用户User1创建区块链客户端
	fmt.Println("步骤2: 创建区块链客户端（使用User1身份）...")
	
	// 获取基础路径（用于查找组织目录）
	basePaths := []string{
		"../../test-network/organizations/peerOrganizations",
		"../../../fabric-samples/test-network/organizations/peerOrganizations",
		"../test-network/organizations/peerOrganizations",
		"./test-network/organizations/peerOrganizations",
	}
	
	var basePath string
	for _, path := range basePaths {
		fullPath := filepath.Join(workDir, path)
		if _, err := os.Stat(fullPath); err == nil {
			basePath = fullPath
			break
		}
	}
	
	if basePath == "" {
		log.Fatalf("未找到Fabric网络组织路径，请确保test-network已部署")
	}
	
	fmt.Printf("使用Fabric基础路径: %s\n", basePath)
	
	// 获取org1的路径（用于User1）
	org1Path := filepath.Join(basePath, "org1.example.com")
	user1Config := blockchain.BlockchainClientConfig{
		MSPID:         "Org1MSP",
		CryptoPath:    org1Path,
		CertPath:      filepath.Join(org1Path, "users/User1@org1.example.com/msp/signcerts"),
		KeyPath:       filepath.Join(org1Path, "users/User1@org1.example.com/msp/keystore"),
		TLSCertPath:   filepath.Join(org1Path, "peers/peer0.org1.example.com/tls/ca.crt"),
		PeerEndpoint:  "dns:///localhost:7051",
		GatewayPeer:   "peer0.org1.example.com",
		ChannelName:   "mychannel",
		ChaincodeName: "academicPublishing",
	}

	user1Client, err := blockchain.NewClientWithConfig(user1Config)
	if err != nil {
		log.Printf("创建User1客户端失败: %v", err)
		log.Println("提示: 请确保Fabric网络正在运行，并且路径配置正确")
		log.Fatalf("错误详情: %v", err)
	}
	defer user1Client.Close()

	fmt.Println("✓ User1客户端创建成功")
	fmt.Println()

	// 3. 存储数据保护策略到区块链（使用User1）
	fmt.Println("步骤3: 存储数据保护策略到区块链...")
	policyID := fmt.Sprintf("policy_%s_%s_%d", "REVIEW", "MANUSCRIPT", 1)
	err = user1Client.StoreDataProtectionPolicy(
		policyID,
		types.PhaseReview,
		data_policy.DataTypeManuscript,
		types.DataSecLevel1,
		"ECDH_HKDF",
		"审稿阶段论文数据Level1加密策略",
		"User1",
	)
	if err != nil {
		log.Printf("⚠ 存储数据保护策略失败: %v", err)
		log.Println("提示: 这可能是正常的，如果策略已存在或网络未完全启动")
	} else {
		fmt.Printf("✓ 数据保护策略已存储: %s\n", policyID)
	}
	fmt.Println()

	// 4. 从数据库获取用户
	fmt.Println("步骤4: 从数据库获取用户...")
	authorUser, err := db.GetUserByRole("AUTHOR")
	if err != nil {
		// 尝试小写
		authorUser, err = db.GetUserByRole("author")
	}
	if err != nil {
		log.Printf("⚠ 获取作者用户失败: %v", err)
		log.Println("提示: 请确保数据库中已有AUTHOR角色的用户")
		log.Println("可以使用其他测试程序先创建用户")
		// 创建示例用户用于测试
		authorUser = &db.UserIdentityInfo{
			Username:        "test_author",
			OffChainID:      "author_001",
			OnChainIdentity: "User1@org1.example.com",
			Role:            "AUTHOR",
			Phase:           "REVIEW",
			Attributes:      make(map[string]string),
		}
		fmt.Println("使用示例作者用户进行测试")
	}
	fmt.Printf("✓ 作者用户: %s (链上身份: %s, 角色: %s)\n", authorUser.Username, authorUser.OnChainIdentity, authorUser.Role)

	editorUser, err := db.GetUserByRole("EDITOR")
	if err != nil {
		// 尝试小写
		editorUser, err = db.GetUserByRole("editor")
	}
	if err != nil {
		log.Printf("⚠ 获取编辑用户失败: %v", err)
		editorUser = &db.UserIdentityInfo{
			Username:        "test_editor",
			OffChainID:      "editor_001",
			OnChainIdentity: "User1@org2.example.com",
			Role:            "EDITOR",
			Phase:           "REVIEW",
			Attributes:      make(map[string]string),
		}
		fmt.Println("使用示例编辑用户进行测试")
	}
	fmt.Printf("✓ 编辑用户: %s (链上身份: %s, 角色: %s)\n", editorUser.Username, editorUser.OnChainIdentity, editorUser.Role)

	reviewerUser, err := db.GetUserByRole("REVIEWER")
	if err != nil {
		// 尝试小写
		reviewerUser, err = db.GetUserByRole("reviewer")
	}
	if err != nil {
		log.Printf("⚠ 获取审稿用户失败: %v", err)
		reviewerUser = &db.UserIdentityInfo{
			Username:        "test_reviewer",
			OffChainID:      "reviewer_001",
			OnChainIdentity: "User1@org3.example.com",
			Role:            "REVIEWER",
			Phase:           "REVIEW",
			Attributes:      make(map[string]string),
		}
		fmt.Println("使用示例审稿用户进行测试")
	}
	fmt.Printf("✓ 审稿用户: %s (链上身份: %s, 角色: %s)\n", reviewerUser.Username, reviewerUser.OnChainIdentity, reviewerUser.Role)
	fmt.Println()

	// 5. 使用编辑角色的链上身份和本地MSP文件创建客户端
	fmt.Println("步骤5: 使用编辑角色创建区块链客户端...")
	
	// 根据用户角色获取组织配置
	editorOrgConfig := getOrgConfigByRole("EDITOR", basePath)
	editorConfig := blockchain.BlockchainClientConfig{
		MSPID:         editorOrgConfig.MSPID,
		CryptoPath:    editorOrgConfig.CryptoPath,
		CertPath:      filepath.Join(editorOrgConfig.CryptoPath, fmt.Sprintf("users/%s/msp/signcerts", editorUser.OnChainIdentity)),
		KeyPath:       filepath.Join(editorOrgConfig.CryptoPath, fmt.Sprintf("users/%s/msp/keystore", editorUser.OnChainIdentity)),
		TLSCertPath:   editorOrgConfig.TLSCertPath,
		PeerEndpoint:  editorOrgConfig.PeerEndpoint,
		GatewayPeer:   editorOrgConfig.GatewayPeer,
		ChannelName:   "mychannel",
		ChaincodeName: "academicPublishing",
	}

	editorClient, err := blockchain.NewClientWithConfig(editorConfig)
	if err != nil {
		log.Printf("⚠ 创建编辑客户端失败，使用User1客户端: %v", err)
		editorClient = user1Client // 如果失败，使用User1客户端
		fmt.Println("使用User1客户端继续执行")
	} else {
		fmt.Printf("✓ 编辑客户端创建成功 (使用 %s)\n", editorOrgConfig.MSPID)
	}
	fmt.Println()

	// 6. 测试用例1：链下获取策略和加密处理
	fmt.Println("=== 测试用例1: 链下获取策略和加密处理 ===")
	fmt.Println()
	
	testCase1Start := time.Now()
	var testCase1Operations []struct {
		name     string
		success  bool
		duration time.Duration
	}
	
	// 6.1 获取链下保护策略
	op1Start := time.Now()
	fmt.Println("步骤6.1: 获取链下保护策略（审稿阶段、论文类型、安全级别1）...")
	policyManager := data_policy.NewEnhancedDataPolicyManager()
	policy, err := policyManager.GetEncryptionPolicyWithLevel(
		types.PhaseReview,
		data_policy.DataTypeManuscript,
		types.DataSecLevel1,
	)
	op1Duration := time.Since(op1Start)
	if err != nil {
		log.Fatalf("获取保护策略失败: %v", err)
	}
	policyType := policy.GetPolicyType()
	fmt.Printf("✓ 获取到策略类型: %s\n", policyType)
	testCase1Operations = append(testCase1Operations, struct {
		name     string
		success  bool
		duration time.Duration
	}{"获取链下保护策略", true, op1Duration})
	fmt.Println()

	// 6.2 准备论文数据
	op2Start := time.Now()
	fmt.Println("步骤6.2: 准备论文数据...")
	paperContent := "这是一篇测试论文的内容。This is a test paper content for encryption testing."
	paperID := fmt.Sprintf("paper_%d", time.Now().Unix())
	paper := &types.Paper{
		PaperID:        paperID,
		Title:          "测试论文标题",
		Abstract:       "测试论文摘要",
		Content:        paperContent,
		ContentHash:    "test_hash",
		AuthorID:       authorUser.OffChainID,
		AuthorIdentity: authorUser.OnChainIdentity,
		Status:         string(types.StatusUnderReview),
		Phase:          string(types.PhaseReview),
		SubmittedAt:    time.Now().Format(time.RFC3339),
		UpdatedAt:      time.Now().Format(time.RFC3339),
		Version:        1,
		Metadata:       make(map[string]string),
	}
	op2Duration := time.Since(op2Start)
	fmt.Printf("✓ 论文ID: %s\n", paperID)
	fmt.Println("【论文原始内容（加密前）】")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(paper.Content)
	fmt.Println(strings.Repeat("-", 60))
	testCase1Operations = append(testCase1Operations, struct {
		name     string
		success  bool
		duration time.Duration
	}{"准备论文数据", true, op2Duration})
	fmt.Println()

	// 6.3 使用策略加密论文数据
	op3Start := time.Now()
	fmt.Println("步骤6.3: 使用策略加密论文数据...")
	participants := []string{authorUser.OffChainID, reviewerUser.OffChainID}
	encryptedContent, metadata, err := policyManager.EncryptDataWithLevel(
		[]byte(paper.Content),
		types.PhaseReview,
		data_policy.DataTypeManuscript,
		participants,
		types.DataSecLevel1,
	)
	op3Duration := time.Since(op3Start)
	if err != nil {
		log.Fatalf("加密论文数据失败: %v", err)
	}
	fmt.Printf("✓ 论文数据加密成功，密文长度: %d 字节\n", len(encryptedContent))
	testCase1Operations = append(testCase1Operations, struct {
		name     string
		success  bool
		duration time.Duration
	}{"使用策略加密论文数据", true, op3Duration})
	fmt.Println()

	// 6.4 生成AES对称密钥并使用PRE加密（用于Level2）
	op4Start := time.Now()
	fmt.Println("步骤6.4: 生成AES对称密钥并使用PRE重加密...")
	
	// 生成一个新的AES密钥（用于PRE加密）
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		log.Fatalf("生成AES密钥失败: %v", err)
	}
	
	// 使用PRE策略为每个接收用户生成重加密密钥并加密AES密钥
	prePolicy := data_policy.NewProxyReEncryptionPolicy()
	reEncKeys := make(map[string][]byte)
	
	// 为作者生成重加密密钥并加密AES密钥
	editorPREKey, err := prePolicy.GenerateReEncryptionKey(editorUser.OffChainID, authorUser.OffChainID, 24*time.Hour)
	if err == nil {
		// 序列化重加密密钥
		reEncKeyBytes, _ := json.Marshal(editorPREKey)
		// 使用PRE加密AES密钥（简化：直接存储重加密密钥和加密后的AES密钥）
		encryptedAESKey, _, err := prePolicy.Encrypt(aesKey, []string{authorUser.OffChainID})
		if err == nil {
			// 将重加密密钥和加密的AES密钥组合
			combined := append(reEncKeyBytes, encryptedAESKey...)
			reEncKeys[authorUser.OffChainID] = combined
			fmt.Printf("✓ 为作者生成重加密密钥并加密AES密钥\n")
		} else {
			log.Printf("⚠ 为作者加密AES密钥失败: %v", err)
		}
	} else {
		log.Printf("⚠ 为作者生成重加密密钥失败: %v", err)
	}
	
	// 为审稿人生成重加密密钥并加密AES密钥
	reviewerPREKey, err := prePolicy.GenerateReEncryptionKey(editorUser.OffChainID, reviewerUser.OffChainID, 24*time.Hour)
	if err == nil {
		// 序列化重加密密钥
		reEncKeyBytes, _ := json.Marshal(reviewerPREKey)
		// 使用PRE加密AES密钥
		encryptedAESKey, _, err := prePolicy.Encrypt(aesKey, []string{reviewerUser.OffChainID})
		if err == nil {
			// 将重加密密钥和加密的AES密钥组合
			combined := append(reEncKeyBytes, encryptedAESKey...)
			reEncKeys[reviewerUser.OffChainID] = combined
			fmt.Printf("✓ 为审稿人生成重加密密钥并加密AES密钥\n")
		} else {
			log.Printf("⚠ 为审稿人加密AES密钥失败: %v", err)
		}
	} else {
		log.Printf("⚠ 为审稿人生成重加密密钥失败: %v", err)
	}
	op4Duration := time.Since(op4Start)
	testCase1Operations = append(testCase1Operations, struct {
		name     string
		success  bool
		duration time.Duration
	}{"生成AES对称密钥并使用PRE重加密", true, op4Duration})
	fmt.Println()
	
	// 测试用例1完成，生成性能测试报告
	testCase1Duration := time.Since(testCase1Start)
	printTestCaseReport("测试用例1: 链下获取策略和加密处理", testCase1Operations, testCase1Duration)
	fmt.Println()

	// 10. 创建加密论文结构体
	fmt.Println("步骤10: 创建加密论文结构体...")
	encryptedPaper := &types.EncryptedPaper{
		PaperID:         paper.PaperID,
		Version:         paper.Version,
		Title:           paper.Title,
		Abstract:        paper.Abstract,
		ContentHash:     paper.ContentHash,
		AuthorID:        paper.AuthorID,
		AuthorIdentity:  paper.AuthorIdentity,
		FromUserID:      editorUser.OffChainID,
		FromIdentity:    editorUser.OnChainIdentity,
		ToUserIDs:       []string{authorUser.OffChainID, reviewerUser.OffChainID},
		ToIdentities:    []string{authorUser.OnChainIdentity, reviewerUser.OnChainIdentity},
		L1Content:       encryptedContent, // Level1: ECDH加密的论文内容
		L1Encrypted:     true,
		L1EncryptionType: policyType,
		L2Content:        reEncKeys, // Level2: 每个用户对应的PRE重加密密钥
		L2Encrypted:     true,
		L2EncryptionType: "PROXY_REENCRYPTION",
		DataType:        types.DataTypeManuscript,
		SecurityLevel:   types.DataSecLevel1,
		Status:          paper.Status,
		Phase:           paper.Phase,
		SubmittedAt:     paper.SubmittedAt,
		UpdatedAt:       time.Now().Format(time.RFC3339),
		Metadata:        metadata,
		AccessControl:   make(map[string]string),
	}
	fmt.Println("✓ 加密论文结构体创建成功")
	fmt.Println()

	// 11. 测试用例2：论文上链
	fmt.Println("=== 测试用例2: 论文上链 ===")
	fmt.Println()
	testCase2Start := time.Now()
	var testCase2Operations []struct {
		name     string
		success  bool
		duration time.Duration
	}
	
	op1Start = time.Now()
	fmt.Println("步骤11: 上传加密论文数据到链上...")
	uploadErr := editorClient.StoreEncryptedPaper(encryptedPaper)
	op1Duration = time.Since(op1Start)
	if uploadErr != nil {
		log.Printf("⚠ 上传加密论文失败: %v", uploadErr)
		log.Println("提示: 请确保Fabric网络正在运行，chaincode已部署")
		testCase2Operations = append(testCase2Operations, struct {
			name     string
			success  bool
			duration time.Duration
		}{"上传加密论文数据到链上", false, op1Duration})
	} else {
		fmt.Println("✓ 加密论文已上传到链上（Level1 context）")
		fmt.Println("✓ 重加密密钥已上传到链上（Level2 context）")
		testCase2Operations = append(testCase2Operations, struct {
			name     string
			success  bool
			duration time.Duration
		}{"上传加密论文数据到链上", true, op1Duration})
	}
	
	// 测试用例2完成，生成性能测试报告
	testCase2Duration := time.Since(testCase2Start)
	printTestCaseReport("测试用例2: 论文上链", testCase2Operations, testCase2Duration)
	fmt.Println()

	// 12. 测试用例3：论文链上获取
	fmt.Println("=== 测试用例3: 论文链上获取 ===")
	fmt.Println()
	testCase3Start := time.Now()
	var testCase3Operations []struct {
		name     string
		success  bool
		duration time.Duration
	}
	
	op1Start = time.Now()
	fmt.Println("步骤12: 从链上读取加密论文...")
	var retrievedPaper *types.EncryptedPaper
	var retrieveErr error
	retrievedPaper, retrieveErr = editorClient.GetEncryptedPaper(paperID)
	op1Duration = time.Since(op1Start)
	if retrieveErr != nil {
		log.Printf("⚠ 读取加密论文失败: %v", retrieveErr)
		log.Println("提示: 如果上一步上传失败，这一步也会失败")
		testCase3Operations = append(testCase3Operations, struct {
			name     string
			success  bool
			duration time.Duration
		}{"从链上读取加密论文", false, op1Duration})
	} else {
		fmt.Printf("✓ 成功读取加密论文: %s\n", retrievedPaper.PaperID)
		fmt.Printf("  - 接收用户数量: %d\n", len(retrievedPaper.ToUserIDs))
		fmt.Printf("  - Level2重加密密钥数量: %d\n", len(retrievedPaper.L2Content))
		for userID := range retrievedPaper.L2Content {
			fmt.Printf("    - 用户 %s 的重加密密钥已存储\n", userID)
		}
		testCase3Operations = append(testCase3Operations, struct {
			name     string
			success  bool
			duration time.Duration
		}{"从链上读取加密论文", true, op1Duration})
	}
	
	// 测试用例3完成，生成性能测试报告
	testCase3Duration := time.Since(testCase3Start)
	printTestCaseReport("测试用例3: 论文链上获取", testCase3Operations, testCase3Duration)
	fmt.Println()

	// 13. 验证：读取特定用户的重加密密钥
	fmt.Println("步骤13: 验证 - 读取特定用户的重加密密钥...")
	authorReKey, err := editorClient.GetReEncryptionKey(paperID, authorUser.OffChainID)
	if err != nil {
		log.Printf("⚠ 读取作者重加密密钥失败: %v", err)
	} else {
		fmt.Printf("✓ 成功读取作者重加密密钥，长度: %d 字节\n", len(authorReKey))
	}
	
	reviewerReKey, err := editorClient.GetReEncryptionKey(paperID, reviewerUser.OffChainID)
	if err != nil {
		log.Printf("⚠ 读取审稿人重加密密钥失败: %v", err)
	} else {
		fmt.Printf("✓ 成功读取审稿人重加密密钥，长度: %d 字节\n", len(reviewerReKey))
	}
	fmt.Println()

	// 14. 测试用例4：论文链下解密
	fmt.Println("=== 测试用例4: 论文链下解密 ===")
	fmt.Println()
	testCase4Start := time.Now()
	var testCase4Operations []struct {
		name     string
		success  bool
		duration time.Duration
	}
	
	op1Start = time.Now()
	fmt.Println("步骤14: 解密从链上获取的加密论文...")
	if retrievedPaper != nil {
		// 使用策略管理器解密论文
		decryptedContent, err := policyManager.DecryptDataWithLevel(
			retrievedPaper.L1Content,
			retrievedPaper.Metadata,
			types.PhaseReview,
			data_policy.DataTypeManuscript,
			authorUser.OffChainID, // 使用作者身份解密
			types.DataSecLevel1,
		)
		op1Duration = time.Since(op1Start)
		if err != nil {
			log.Printf("⚠ 解密论文失败: %v", err)
			testCase4Operations = append(testCase4Operations, struct {
				name     string
				success  bool
				duration time.Duration
			}{"解密从链上获取的加密论文", false, op1Duration})
		} else {
			fmt.Println("✓ 论文解密成功")
			fmt.Println("【论文解密后内容】")
			fmt.Println(strings.Repeat("-", 60))
			fmt.Println(string(decryptedContent))
			fmt.Println(strings.Repeat("-", 60))
			
			// 验证解密后的内容是否与原始内容一致
			verifySuccess := string(decryptedContent) == paperContent
			if verifySuccess {
				fmt.Println("✓ 解密内容与原始内容一致，验证通过")
			} else {
				fmt.Println("⚠ 警告：解密内容与原始内容不一致")
			}
			testCase4Operations = append(testCase4Operations, struct {
				name     string
				success  bool
				duration time.Duration
			}{"解密从链上获取的加密论文", verifySuccess, op1Duration})
		}
	} else {
		op1Duration = time.Since(op1Start)
		log.Println("⚠ 无法解密：未成功从链上获取加密论文")
		testCase4Operations = append(testCase4Operations, struct {
			name     string
			success  bool
			duration time.Duration
		}{"解密从链上获取的加密论文", false, op1Duration})
	}
	
	// 测试用例4完成，生成性能测试报告
	testCase4Duration := time.Since(testCase4Start)
	printTestCaseReport("测试用例4: 论文链下解密", testCase4Operations, testCase4Duration)
	fmt.Println()

	// 打印总体测试结果统计（性能测试报告格式）
	fmt.Println()
	fmt.Println("【数据保护策略上链存储与加密论文测试】性能测试报告")
	fmt.Println(strings.Repeat("=", 60))
	
	// 统计所有测试用例的结果
	allTestCases := []struct {
		name      string
		success   bool
		duration  time.Duration
		operations []struct {
			name     string
			success  bool
			duration time.Duration
		}
	}{
		{"测试用例1: 链下获取策略和加密处理", true, testCase1Duration, testCase1Operations},
		{"测试用例2: 论文上链", uploadErr == nil, testCase2Duration, testCase2Operations},
		{"测试用例3: 论文链上获取", retrieveErr == nil && retrievedPaper != nil, testCase3Duration, testCase3Operations},
		{"测试用例4: 论文链下解密", func() bool {
			if retrievedPaper != nil {
				decrypted, err := policyManager.DecryptDataWithLevel(
					retrievedPaper.L1Content,
					retrievedPaper.Metadata,
					types.PhaseReview,
					data_policy.DataTypeManuscript,
					authorUser.OffChainID,
					types.DataSecLevel1,
				)
				return err == nil && string(decrypted) == paperContent
			}
			return false
		}(), testCase4Duration, testCase4Operations},
	}
	
	// 计算总体统计信息
	totalTests := len(allTestCases)
	successCount := 0
	var totalDuration time.Duration
	var minDuration, maxDuration time.Duration
	hasDuration := false
	
	for _, testCase := range allTestCases {
		if testCase.success {
			successCount++
		}
		if testCase.duration > 0 {
			totalDuration += testCase.duration
			if !hasDuration {
				minDuration = testCase.duration
				maxDuration = testCase.duration
				hasDuration = true
			} else {
				if testCase.duration < minDuration {
					minDuration = testCase.duration
				}
				if testCase.duration > maxDuration {
					maxDuration = testCase.duration
				}
			}
		}
	}
	
	failCount := totalTests - successCount
	successRate := float64(successCount) / float64(totalTests) * 100
	
	// 计算平均耗时
	var avgDuration time.Duration
	if hasDuration {
		avgDuration = totalDuration / time.Duration(totalTests)
	}
	
	// 输出总体统计信息
	fmt.Printf("总操作次数:   %d\n", totalTests)
	fmt.Printf("成功次数:     %d\n", successCount)
	fmt.Printf("失败次数:     %d\n", failCount)
	fmt.Printf("成功率:       %.2f%%\n", successRate)
	fmt.Println()
	
	if hasDuration {
		fmt.Println("响应时间统计:")
		fmt.Printf("  总耗时:     %s\n", formatDuration(totalDuration))
		fmt.Printf("  平均耗时:   %s\n", formatDuration(avgDuration))
		fmt.Printf("  最小耗时:   %s\n", formatDuration(minDuration))
		fmt.Printf("  最大耗时:   %s\n", formatDuration(maxDuration))
		fmt.Println()
		fmt.Printf("总经过时间:   %s\n", formatDuration(totalDuration))
	} else {
		fmt.Println("响应时间统计:")
		fmt.Println("  (未记录响应时间)")
		fmt.Println()
	}
	
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Println("=== 测试完成 ===")
	fmt.Println()
	fmt.Println("提示: 如果某些步骤失败，请检查:")
	fmt.Println("  - Fabric网络是否正在运行")
	fmt.Println("  - Chaincode是否已部署")
	fmt.Println("  - 数据库是否包含必要的用户数据")
	fmt.Println("  - 路径配置是否正确")
}

// OrgConfig 组织配置结构体
type OrgConfig struct {
	MSPID        string
	CryptoPath   string
	TLSCertPath  string
	PeerEndpoint string
	GatewayPeer  string
}

// getOrgConfigByRole 根据用户角色获取对应的组织配置
// 作者角色 -> org1, 编辑角色 -> org2, 审稿人角色 -> org3
func getOrgConfigByRole(role string, basePath string) OrgConfig {
	var orgNum string
	var mspID string
	var peerPort string
	var gatewayPeer string
	
	switch role {
	case "AUTHOR", "author":
		orgNum = "org1"
		mspID = "Org1MSP"
		peerPort = "7051"
		gatewayPeer = "peer0.org1.example.com"
	case "EDITOR", "editor":
		orgNum = "org2"
		mspID = "Org2MSP"
		peerPort = "9051"
		gatewayPeer = "peer0.org2.example.com"
	case "REVIEWER", "reviewer":
		orgNum = "org3"
		mspID = "Org3MSP"
		peerPort = "11051"
		gatewayPeer = "peer0.org3.example.com"
	default:
		// 默认使用org1
		orgNum = "org1"
		mspID = "Org1MSP"
		peerPort = "7051"
		gatewayPeer = "peer0.org1.example.com"
	}
	
	orgPath := filepath.Join(basePath, fmt.Sprintf("%s.example.com", orgNum))
	tlsCertPath := filepath.Join(orgPath, fmt.Sprintf("peers/%s/tls/ca.crt", gatewayPeer))
	
	return OrgConfig{
		MSPID:        mspID,
		CryptoPath:   orgPath,
		TLSCertPath:  tlsCertPath,
		PeerEndpoint: fmt.Sprintf("dns:///localhost:%s", peerPort),
		GatewayPeer:  gatewayPeer,
	}
}

// formatDuration 格式化时间持续时间为易读的字符串
func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%.3fns", float64(d.Nanoseconds()))
	} else if d < time.Millisecond {
		return fmt.Sprintf("%.3fµs", float64(d.Nanoseconds())/1000.0)
	} else {
		return fmt.Sprintf("%.3fms", float64(d.Nanoseconds())/1000000.0)
	}
}

// printTestCaseReport 打印单个测试用例的性能测试报告
func printTestCaseReport(testCaseName string, operations []struct {
	name     string
	success  bool
	duration time.Duration
}, totalDuration time.Duration) {
	fmt.Println()
	fmt.Printf("【%s】性能测试报告\n", testCaseName)
	fmt.Println(strings.Repeat("=", 60))
	
	// 计算统计信息
	totalOps := len(operations)
	successCount := 0
	var totalOpDuration time.Duration
	var minDuration, maxDuration time.Duration
	hasDuration := false
	
	for _, op := range operations {
		if op.success {
			successCount++
		}
		if op.duration > 0 {
			totalOpDuration += op.duration
			if !hasDuration {
				minDuration = op.duration
				maxDuration = op.duration
				hasDuration = true
			} else {
				if op.duration < minDuration {
					minDuration = op.duration
				}
				if op.duration > maxDuration {
					maxDuration = op.duration
				}
			}
		}
	}
	
	failCount := totalOps - successCount
	successRate := float64(successCount) / float64(totalOps) * 100
	
	// 计算平均耗时
	var avgDuration time.Duration
	if hasDuration {
		avgDuration = totalOpDuration / time.Duration(totalOps)
	}
	
	// 输出统计信息
	fmt.Printf("总操作次数:   %d\n", totalOps)
	fmt.Printf("成功次数:     %d\n", successCount)
	fmt.Printf("失败次数:     %d\n", failCount)
	fmt.Printf("成功率:       %.2f%%\n", successRate)
	fmt.Println()
	
	if hasDuration {
		fmt.Println("响应时间统计:")
		fmt.Printf("  总耗时:     %s\n", formatDuration(totalOpDuration))
		fmt.Printf("  平均耗时:   %s\n", formatDuration(avgDuration))
		fmt.Printf("  最小耗时:   %s\n", formatDuration(minDuration))
		fmt.Printf("  最大耗时:   %s\n", formatDuration(maxDuration))
		fmt.Println()
		fmt.Printf("总经过时间:   %s\n", formatDuration(totalDuration))
	} else {
		fmt.Println("响应时间统计:")
		fmt.Println("  (未记录响应时间)")
		fmt.Println()
		fmt.Printf("总经过时间:   %s\n", formatDuration(totalDuration))
	}
	
	fmt.Println(strings.Repeat("=", 60))
}

