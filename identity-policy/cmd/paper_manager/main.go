package main

import (
    "github.com/tap-thesis/privacy-protection-identity/internal/blockchain"
    "github.com/tap-thesis/privacy-protection-identity/internal/db"
    "github.com/tap-thesis/privacy-protection-identity/internal/utils"
    "github.com/tap-thesis/privacy-protection-identity/pkg/types"
    "fmt"
    "log"
    "os"
    "strconv"
    "strings"
    "time"
)

func main() {
    fmt.Println("=== 学术出版系统 - 论文管理 ===")

    // 连接数据库
    _, err := db.InitDB("../identity_manager/academic_publishing.db")
    if err != nil {
        log.Fatalf("连接数据库失败: %v", err)
    }
    defer db.CloseDB()

    // 调试: 打印所有用户记录
    fmt.Println("\n调试: 打印所有用户记录...")
    err = db.DebugPrintAllUsers()
    if err != nil {
        log.Fatalf("调试打印失败: %v", err)
    }
    
    // 尝试直接执行 SQL 查询
    fmt.Println("\n尝试直接执行 SQL 查询...")
    dbInstance, err := db.GetDB()
    if err != nil {
        log.Fatalf("获取数据库实例失败: %v", err)
    }
    
    debugAuthorID := "zhang4@tsinghua.edu.cn"
    debugPhase := "SUBMISSION"
    rows, err := dbInstance.Query("SELECT username FROM users WHERE off_chain_id = ? AND phase = ?", debugAuthorID, debugPhase)
    if err != nil {
        log.Fatalf("直接查询失败: %v", err)
    }
    defer rows.Close()
    
    foundUser := false
    for rows.Next() {
        foundUser = true
        var username string
        if err := rows.Scan(&username); err != nil {
            log.Fatalf("读取查询结果失败: %v", err)
        }
        fmt.Printf("找到用户: %s\n", username)
    }
    
    if !foundUser {
        fmt.Printf("未找到用户: off_chain_id = %s, phase = %s\n", debugAuthorID, debugPhase)
        
        // 尝试查询所有 zhang4@tsinghua.edu.cn 用户，不限制阶段
        fmt.Println("\n尝试查询所有 zhang4@tsinghua.edu.cn 用户，不限制阶段...")
        rows, err = dbInstance.Query("SELECT username, phase FROM users WHERE off_chain_id = ?", debugAuthorID)
        if err != nil {
            log.Fatalf("查询失败: %v", err)
        }
        defer rows.Close()
        
        foundAny := false
        for rows.Next() {
            foundAny = true
            var username, userPhase string
            if err := rows.Scan(&username, &userPhase); err != nil {
                log.Fatalf("读取查询结果失败: %v", err)
            }
            fmt.Printf("找到用户: %s, 阶段: %s\n", username, userPhase)
        }
        
        if !foundAny {
            fmt.Printf("数据库中不存在 off_chain_id = %s 的用户\n", debugAuthorID)
            
            // 尝试查询任何用户
            fmt.Println("\n尝试查询任何用户...")
            rows, err = dbInstance.Query("SELECT username, off_chain_id, phase FROM users LIMIT 5")
            if err != nil {
                log.Fatalf("查询失败: %v", err)
            }
            defer rows.Close()
            
            foundAny = false
            for rows.Next() {
                foundAny = true
                var username, offChainID, userPhase string
                if err := rows.Scan(&username, &offChainID, &userPhase); err != nil {
                    log.Fatalf("读取查询结果失败: %v", err)
                }
                fmt.Printf("用户: %s, 链下ID: %s, 阶段: %s\n", username, offChainID, userPhase)
            }
            
            if !foundAny {
                fmt.Println("数据库中没有任何用户记录!")
            }
        }
    }

    // 步骤1: 获取作者信息
    fmt.Println("\n1. 获取作者信息...")
    authorOffChainID := "zhang@tsinghua.edu.cn"  // 使用已知存在的用户
    phase := "SUBMISSION" // 指定阶段为投稿阶段
    
    // 从数据库中获取特定阶段的作者信息
    authorInfo, err := db.GetPhaseUserByOffChainID(authorOffChainID, phase)
    if err != nil {
        log.Fatalf("获取作者信息失败: %v", err)
    }
    fmt.Printf("✓ 获取作者信息成功: %s (链上身份: %s, 阶段: %s)\n", 
        authorInfo.Username, authorInfo.OnChainIdentity, authorInfo.Phase)

    // 步骤2: 初始化区块链客户端
    fmt.Println("\n2. 初始化区块链客户端...")
    
    // 使用作者信息初始化区块链客户端
    clientConfig := blockchain.BlockchainClientConfig{
        MSPID:       "Org1MSP",
        CryptoPath:  "../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com",
        CertPath:    "../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/" + authorInfo.Username+ "@org1.example.com/msp/signcerts",
        KeyPath:     "../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/" + authorInfo.Username+ "@org1.example.com/msp/keystore",
        TLSCertPath: "../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
        PeerEndpoint: "dns:///localhost:7051",
        GatewayPeer:  "peer0.org1.example.com",
        ChannelName:  "mychannel",
        ChaincodeName: "basic",
    }
    
    blockchainClient, err := blockchain.NewClientWithConfig(clientConfig)
    if err != nil {
        log.Fatalf("初始化区块链客户端失败: %v", err)
    }
    defer blockchainClient.Close()
    fmt.Println("✓ 区块链客户端初始化成功")

    // 步骤3: 作者提交论文
    fmt.Println("\n3. 作者提交论文...")
    
    // 创建论文提交性能统计对象
    paperPerfStats := utils.NewPerformanceStats("论文提交上链")
    
    // 读取或创建计数器文件
    counterFile := "paper_counter.txt"
    counter := 1
    
    // 尝试读取现有计数器值
    data, err := os.ReadFile(counterFile)
    if err == nil {
        // 文件存在，读取计数器值
        counterStr := strings.TrimSpace(string(data))
        counter, err = strconv.Atoi(counterStr)
        if err != nil {
            counter = 1 // 如果解析失败，重置为1
        } else {
            counter++ // 递增计数器
        }
    }
    
    // 生成新的paperID，保持原有格式，只在PAPER后插入数字
    paperID := fmt.Sprintf("PAPER%d-%s", counter, authorInfo.OnChainIdentity[:8])
    
    // 保存新的计数器值到文件
    err = os.WriteFile(counterFile, []byte(strconv.Itoa(counter)), 0644)
    if err != nil {
        log.Printf("警告: 无法保存计数器值: %v", err)
    }
    
    title := "基于区块链的学术出版隐私保护研究"
    abstract := "本文提出了一种基于区块链的学术出版隐私保护机制..."
    contentHash := "0x123456789abcdef"
    
    paper := &types.Paper{
        PaperID:        paperID,
        Title:          title,
        Abstract:       abstract,
        ContentHash:    contentHash,
        AuthorIdentity: authorInfo.OnChainIdentity,
        Status:         string(types.StatusSubmitted),
        Phase:          string(types.PhaseSubmission),
        Metadata: map[string]string{
            "keywords": "区块链,隐私保护,学术出版",
            "language": "中文",
            "pages":    "15",
        },
    }
    
    // 记录开始时间
    startTime := time.Now()
    
    // 执行论文提交
    err = blockchainClient.SubmitPaper(paper)
    
    // 计算耗时
    duration := time.Since(startTime)
    
    if err != nil {
        log.Printf("✗ 论文提交失败: %v (耗时: %v)", err, duration)
        paperPerfStats.RecordFailure(duration)
        log.Fatalf("论文提交失败: %v", err)
    } else {
        fmt.Printf("✓ 论文提交成功，ID: %s (耗时: %v)\n", paperID, duration)
        paperPerfStats.RecordSuccess(duration)
    }
    
    // 打印论文提交性能统计
    paperPerfStats.PrintSummary()

    // 步骤4: 查询所有论文
    fmt.Println("\n4. 查询所有论文...")
    papers, err := blockchainClient.GetAllPapers()
    if err != nil {
        log.Fatalf("获取所有论文失败: %v", err)
    }
    fmt.Printf("✓ 成功获取所有论文，共 %d 篇\n", len(papers))
    for i, p := range papers {
        fmt.Printf("  %d. %s (作者: %s, 阶段: %s)\n", i+1, p.Title, p.AuthorIdentity, p.Phase)
    }

    // 步骤5: 获取编辑信息
    fmt.Println("\n5. 获取编辑信息...")
    editorOffChainID := "li@journal.com"
    // 同样指定阶段为投稿阶段
    editorInfo, err := db.GetPhaseUserByOffChainID(editorOffChainID, phase)
    if err != nil {
        log.Printf("警告: 获取编辑信息失败: %v，将使用模拟编辑身份", err)
        editorInfo = &db.UserIdentityInfo{
            OnChainIdentity: "editor_li_789012", // 使用模拟编辑身份
            Phase:           phase,
        }
    } else {
        fmt.Printf("✓ 获取编辑信息成功: %s (链上身份: %s, 阶段: %s)\n", 
            editorInfo.Username, editorInfo.OnChainIdentity, editorInfo.Phase)
    }

    // 步骤6: 作者发送消息给编辑
    fmt.Println("\n6. 作者发送消息给编辑...")
    
    // 创建消息发送性能统计对象
    messagePerfStats := utils.NewPerformanceStats("消息发送上链")
    
    authorMessage := &types.Message{
        MessageID:    fmt.Sprintf("msg_%d_1", time.Now().Unix()),
        PaperID:      paperID,
        FromIdentity: authorInfo.OnChainIdentity,
        ToIdentity:   editorInfo.OnChainIdentity,
        Content:      "请问我的论文审稿进展如何？",
        MessageType:  "INQUIRY",
        Phase:        phase,
    }
    
    // 记录开始时间
    startTime = time.Now()
    
    // 执行消息发送
    err = blockchainClient.SendMessage(authorMessage)
    
    // 计算耗时
    duration = time.Since(startTime)
    
    if err != nil {
        log.Printf("✗ 发送消息失败: %v (耗时: %v)", err, duration)
        messagePerfStats.RecordFailure(duration)
        log.Fatalf("发送消息失败: %v", err)
    } else {
        fmt.Printf("✓ 作者消息发送成功 (耗时: %v)\n", duration)
        messagePerfStats.RecordSuccess(duration)
    }

    // 步骤7: 编辑回复作者
    fmt.Println("\n7. 编辑回复作者...")
    editorMessage := &types.Message{
        MessageID:    fmt.Sprintf("msg_%d_2", time.Now().Unix()),
        PaperID:      paperID,
        FromIdentity: editorInfo.OnChainIdentity,
        ToIdentity:   authorInfo.OnChainIdentity,
        Content:      "您的论文已分配给审稿人，预计两周内完成初审。",
        MessageType:  "REPLY",
        Phase:        phase,
    }
    
    // 记录开始时间
    startTime = time.Now()
    
    // 执行消息发送
    err = blockchainClient.SendMessage(editorMessage)
    
    // 计算耗时
    duration = time.Since(startTime)
    
    if err != nil {
        log.Printf("✗ 发送消息失败: %v (耗时: %v)", err, duration)
        messagePerfStats.RecordFailure(duration)
        log.Fatalf("发送消息失败: %v", err)
    } else {
        fmt.Printf("✓ 编辑回复发送成功 (耗时: %v)\n", duration)
        messagePerfStats.RecordSuccess(duration)
    }
    
    // 打印消息发送性能统计
    messagePerfStats.PrintSummary()

    // 步骤8: 查询论文的消息列表
    fmt.Println("\n8. 查询论文的消息列表...")
    messages, err := blockchainClient.GetMessagesByPaper(paperID)
    if err != nil {
        log.Fatalf("获取消息失败: %v", err)
    }
    fmt.Printf("✓ 获取到 %d 条消息:\n", len(messages))
    for i, msg := range messages {
        fmt.Printf("  消息 %d: 从 %s 到 %s - %s\n", 
            i+1, msg.FromIdentity, msg.ToIdentity, msg.Content)
    }

    fmt.Println("\n=== 论文管理完成 ===")
}