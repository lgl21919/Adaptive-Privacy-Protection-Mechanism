package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// 主函数：演示学术出版系统的完整流程
func main() {
	fmt.Println("=== 学术出版系统演示 ===")

	// 1. 初始化客户端
	fmt.Println("\n1. 初始化区块链客户端...")
	client, err := NewAcademicPublishingClient()
	if err != nil {
		log.Fatalf("初始化客户端失败: %v", err)
	}
	defer client.Close()
	fmt.Println("✓ 客户端初始化成功")

	// 2. 作者提交论文
	fmt.Println("\n2. 作者提交论文...")
	paperID := fmt.Sprintf("paper_%d", time.Now().Unix())
	authorIdentity := "author_zhang_123456" // 假设这是作者在链上的身份标识

	// 模拟PDF内容（实际应用中应该是文件内容的哈希）
	pdfContent := "这是论文PDF内容的Base64编码"
	contentHash := base64.StdEncoding.EncodeToString([]byte(pdfContent))

	paper := &Paper{
		PaperID:        paperID,
		Title:          "基于区块链的学术出版隐私保护研究",
		Abstract:       "本文研究了如何利用区块链技术保护学术出版过程中的隐私...",
		ContentHash:    contentHash,
		AuthorIdentity: authorIdentity,
		Status:         string(StatusSubmitted),
		Phase:          string(PhaseSubmission),
		Metadata: map[string]string{
			"keywords": "区块链,隐私保护,学术出版",
			"language": "中文",
			"pages":    "15",
		},
	}

	err = client.SubmitPaper(paper)
	if err != nil {
		log.Fatalf("提交论文失败: %v", err)
	}
	fmt.Printf("✓ 论文提交成功，ID: %s\n", paperID)

	// 3. 编辑读取论文
	fmt.Println("\n3. 编辑读取论文...")
	retrievedPaper, err := client.ReadPaper(paperID)
	if err != nil {
		log.Fatalf("读取论文失败: %v", err)
	}
	fmt.Printf("✓ 读取论文成功: %s (状态: %s, 阶段: %s)\n", 
		retrievedPaper.Title, retrievedPaper.Status, retrievedPaper.Phase)

	// 4. 编辑更新论文状态
	fmt.Println("\n4. 编辑更新论文状态...")
	editorIdentity := "editor_li_789012" // 假设这是编辑在链上的身份标识
	err = client.UpdatePaperStatus(paperID, string(StatusUnderReview), editorIdentity)
	if err != nil {
		log.Fatalf("更新论文状态失败: %v", err)
	}
	fmt.Println("✓ 论文状态更新为: UNDER_REVIEW")

	// 5. 更新论文阶段
	fmt.Println("\n5. 更新论文阶段...")
	err = client.UpdatePaperPhase(paperID, string(PhaseReview))
	if err != nil {
		log.Fatalf("更新论文阶段失败: %v", err)
	}
	fmt.Println("✓ 论文阶段更新为: REVIEW")

	// 6. 作者发送消息给编辑
	fmt.Println("\n6. 作者发送消息给编辑...")
	authorMessage := &Message{
		MessageID:    fmt.Sprintf("msg_%d_1", time.Now().Unix()),
		PaperID:      paperID,
		FromIdentity: authorIdentity,
		ToIdentity:   editorIdentity,
		Content:      "请问我的论文审稿进展如何？",
		MessageType:  "INQUIRY",
		Phase:        string(PhaseReview),
	}
	err = client.SendMessage(authorMessage)
	if err != nil {
		log.Fatalf("发送消息失败: %v", err)
	}
	fmt.Println("✓ 作者消息发送成功")

	// 7. 编辑回复作者
	fmt.Println("\n7. 编辑回复作者...")
	editorMessage := &Message{
		MessageID:    fmt.Sprintf("msg_%d_2", time.Now().Unix()),
		PaperID:      paperID,
		FromIdentity: editorIdentity,
		ToIdentity:   authorIdentity,
		Content:      "您的论文已分配给审稿人，预计两周内完成初审。",
		MessageType:  "REPLY",
		Phase:        string(PhaseReview),
	}
	err = client.SendMessage(editorMessage)
	if err != nil {
		log.Fatalf("发送消息失败: %v", err)
	}
	fmt.Println("✓ 编辑回复发送成功")

	// 8. 查询论文的消息列表
	fmt.Println("\n8. 查询论文的消息列表...")
	messages, err := client.GetMessagesByPaper(paperID)
	if err != nil {
		log.Fatalf("获取消息失败: %v", err)
	}
	fmt.Printf("✓ 获取到 %d 条消息:\n", len(messages))
	for i, msg := range messages {
		fmt.Printf("  消息 %d: 从 %s 到 %s - %s\n", 
			i+1, msg.FromIdentity, msg.ToIdentity, msg.Content)
	}

	// 9. 查询作者的论文列表
	fmt.Println("\n9. 查询作者的论文列表...")
	authorPapers, err := client.GetPapersByAuthor(authorIdentity)
	if err != nil {
		log.Fatalf("获取作者论文列表失败: %v", err)
	}
	fmt.Printf("✓ 作者共有 %d 篇论文\n", len(authorPapers))
	for i, p := range authorPapers {
		fmt.Printf("  论文 %d: %s (ID: %s)\n", i+1, p.Title, p.PaperID)
	}

	// 10. 查询论文历史
	fmt.Println("\n10. 查询论文历史...")
	history, err := client.GetPaperHistory(paperID)
	if err != nil {
		log.Fatalf("获取论文历史失败: %v", err)
	}
	fmt.Printf("✓ 论文历史记录共 %d 条\n", len(history))

	// 11. 查询所有论文
	fmt.Println("\n11. 查询所有论文...")
	allPapers, err := client.GetAllPapers()
	if err != nil {
		log.Fatalf("获取所有论文失败: %v", err)
	}
	fmt.Printf("✓ 系统中共有 %d 篇论文\n", len(allPapers))

	fmt.Println("\n=== 演示完成 ===")
}

// 为了解决链码和客户端之间的JSON标签不一致问题，我们需要修改Paper和Message结构体
// 以确保与链码中的大写字段名兼容

// Paper 论文信息 - 修改JSON标签以匹配链码
type Paper struct {
    PaperID        string            `json:"PaperID"`        // 大写匹配链码
    Title          string            `json:"Title"`          // 大写匹配链码
    Abstract       string            `json:"Abstract"`       // 大写匹配链码
    Content        string            `json:"Content"`        // 大写匹配链码
    ContentHash    string            `json:"ContentHash"`    // 大写匹配链码
    AuthorID       string            `json:"AuthorID"`       // 大写匹配链码
    AuthorIdentity string            `json:"AuthorIdentity"` // 大写匹配链码
    Status         string            `json:"Status"`         // 大写匹配链码
    Phase          string            `json:"Phase"`          // 大写匹配链码
    SubmittedAt    string            `json:"SubmittedAt"`    // 大写匹配链码
    UpdatedAt      string            `json:"UpdatedAt"`      // 大写匹配链码
    Metadata       map[string]string `json:"Metadata,omitempty"` // 大写匹配链码，添加omitempty
}

// UnmarshalJSON 自定义反序列化方法，处理Metadata为null的情况
func (p *Paper) UnmarshalJSON(data []byte) error {
	// 创建一个匿名结构体，与Paper结构相同但Metadata可以为null
	type PaperAlias Paper
	aux := struct {
		Metadata json.RawMessage `json:"Metadata"`
		*PaperAlias
	}{
		PaperAlias: (*PaperAlias)(p),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// 如果Metadata为null或空，初始化为空map
	if len(aux.Metadata) == 0 || string(aux.Metadata) == "null" {
		p.Metadata = make(map[string]string)
	} else {
		// 否则正常解析
		if err := json.Unmarshal(aux.Metadata, &p.Metadata); err != nil {
			return err
		}
	}

	return nil
}

// Message 消息交互 - 修改JSON标签以匹配链码
type Message struct {
	MessageID    string `json:"MessageID"`    // 大写匹配链码
	PaperID      string `json:"PaperID"`      // 大写匹配链码
	FromUserID   string `json:"fromUserID"`   // 保留小写，链下使用
	FromIdentity string `json:"FromIdentity"` // 大写匹配链码
	ToUserID     string `json:"toUserID"`     // 保留小写，链下使用
	ToIdentity   string `json:"ToIdentity"`   // 大写匹配链码
	Content      string `json:"Content"`      // 大写匹配链码
	MessageType  string `json:"MessageType"`  // 大写匹配链码
	Timestamp    string `json:"Timestamp"`    // 大写匹配链码
	Phase        string `json:"Phase"`        // 大写匹配链码
}

// Transaction 交易记录 - 修改JSON标签以匹配链码
type Transaction struct {
	TxID         string            `json:"TxID"`         // 大写匹配链码
	PaperID      string            `json:"PaperID"`      // 大写匹配链码
	UserID       string            `json:"userID"`       // 保留小写，链下使用
	UserIdentity string            `json:"UserIdentity"` // 大写匹配链码
	Action       string            `json:"Action"`       // 大写匹配链码
	Phase        string            `json:"Phase"`        // 大写匹配链码
	Timestamp    string            `json:"Timestamp"`    // 大写匹配链码
	Data         map[string]string `json:"Data"`         // 大写匹配链码
}

// UnmarshalJSON 自定义反序列化方法，处理Data为null的情况
func (t *Transaction) UnmarshalJSON(data []byte) error {
	// 创建一个匿名结构体，与Transaction结构相同但Data可以为null
	type TransactionAlias Transaction
	aux := struct {
		Data json.RawMessage `json:"Data"`
		*TransactionAlias
	}{
		TransactionAlias: (*TransactionAlias)(t),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// 如果Data为null或空，初始化为空map
	if len(aux.Data) == 0 || string(aux.Data) == "null" {
		t.Data = make(map[string]string)
	} else {
		// 否则正常解析
		if err := json.Unmarshal(aux.Data, &t.Data); err != nil {
			return err
		}
	}

	return nil
}

// 保留原有的枚举类型定义，以便在main函数中使用
type PaperStatus string

const (
	StatusSubmitted   PaperStatus = "SUBMITTED"     // 已提交
	StatusUnderReview PaperStatus = "UNDER_REVIEW"  // 审稿中
	StatusRevisionReq PaperStatus = "REVISION_REQ"  // 需要修改
	StatusAccepted    PaperStatus = "ACCEPTED"      // 已接受
	StatusRejected    PaperStatus = "REJECTED"      // 已拒绝
	StatusPublished   PaperStatus = "PUBLISHED"     // 已发表
)

type PublishingPhase string

const (
	PhaseSubmission  PublishingPhase = "SUBMISSION"  // 投稿阶段
	PhaseReview      PublishingPhase = "REVIEW"      // 审稿阶段
	PhasePublication PublishingPhase = "PUBLICATION" // 出版阶段
)