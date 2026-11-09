package main

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "sync"
    "time"
    "bytes"
    "crypto/x509"
    "encoding/json"
    "os"
    "path"
    
    "github.com/hyperledger/fabric-gateway/pkg/client"
    "github.com/hyperledger/fabric-gateway/pkg/identity"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// SubmissionManager 投稿管理器（集成区块链）
type SubmissionManager struct {
    papers          map[string]*Paper                   // 本地缓存
    papersByAuthor  map[string][]string                 
    messages        map[string][]*Message               
    transactions    []*Transaction
    userManager     *UserManager
    identityManager *EnhancedIdentityPolicyManager
    blockchainClient *AcademicPublishingClient          // 区块链客户端
    mutex           sync.RWMutex
}

// NewSubmissionManager 创建投稿管理器
func NewSubmissionManager(userManager *UserManager, identityManager *EnhancedIdentityPolicyManager, blockchainClient *AcademicPublishingClient) *SubmissionManager {
    return &SubmissionManager{
        papers:          make(map[string]*Paper),
        papersByAuthor:  make(map[string][]string),
        messages:        make(map[string][]*Message),
        transactions:    make([]*Transaction, 0),
        userManager:     userManager,
        identityManager: identityManager,
        blockchainClient: blockchainClient,
    }
}

// SubmitPaper 作者投稿（提交到区块链）
func (sm *SubmissionManager) SubmitPaper(authorID, title, abstract, pdfContent string, metadata map[string]string) (*Paper, error) {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    // 验证作者身份
    author, err := sm.userManager.GetUser(authorID)
    if err != nil {
        return nil, fmt.Errorf("author not found: %v", err)
    }

    if author.Role != RoleAuthor {
        return nil, fmt.Errorf("user is not an author: %s", authorID)
    }

    // 生成论文ID
    paperID := sm.generatePaperID(authorID, title)

    // 获取作者在投稿阶段的身份
    authorIdentity, err := sm.identityManager.GetOrCreatePhaseIdentity(
        authorID,
        RoleAuthor,
        PhaseSubmission,
        paperID,
        nil,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to get author identity: %v", err)
    }

    // 计算内容哈希
    contentHash := sm.calculateContentHash(pdfContent)

    // 创建论文记录
    paper := &Paper{
        PaperID:        paperID,
        Title:          title,
        Abstract:       abstract,
        ContentHash:    contentHash,
        AuthorIdentity: authorIdentity.Pseudonym,
        Status:         string(StatusSubmitted),
        Phase:          string(PhaseSubmission),
        SubmittedAt:    time.Now().Format(time.RFC3339),
        UpdatedAt:      time.Now().Format(time.RFC3339),
        Metadata:       metadata,
    }

    // 提交到区块链
    err = sm.blockchainClient.SubmitPaper(paper)
    if err != nil {
        return nil, fmt.Errorf("failed to submit paper to blockchain: %v", err)
    }

    // 本地存储
    sm.papers[paperID] = paper
    sm.papersByAuthor[authorID] = append(sm.papersByAuthor[authorID], paperID)

    // 记录交易到区块链
    transaction := &Transaction{
        TxID:         sm.generateTransactionID(),
        PaperID:      paperID,
        UserIdentity: authorIdentity.Pseudonym,
        Action:       "SUBMIT_PAPER",
        Phase:        string(PhaseSubmission),
        Timestamp:    time.Now().Format(time.RFC3339),
        Data: map[string]string{
            "title":       title,
            "contentHash": contentHash,
            "status":      string(StatusSubmitted),
        },
    }
    
    err = sm.blockchainClient.RecordTransaction(transaction)
    if err != nil {
        return nil, fmt.Errorf("failed to record transaction to blockchain: %v", err)
    }

    sm.transactions = append(sm.transactions, transaction)

    return paper, nil
}

// EditorReceivePaper 编辑接收稿件（更新区块链状态）
func (sm *SubmissionManager) EditorReceivePaper(editorID, paperID string) error {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    // 验证编辑身份
    editor, err := sm.userManager.GetUser(editorID)
    if err != nil {
        return fmt.Errorf("editor not found: %v", err)
    }

    if editor.Role != RoleEditor {
        return fmt.Errorf("user is not an editor: %s", editorID)
    }

    // 获取编辑在投稿阶段的身份
    editorIdentity, err := sm.identityManager.GetOrCreatePhaseIdentity(
        editorID,
        RoleEditor,
        PhaseSubmission,
        paperID,
        nil,
    )
    if err != nil {
        return fmt.Errorf("failed to get editor identity: %v", err)
    }

    // 更新区块链上的论文状态
    err = sm.blockchainClient.UpdatePaperStatus(paperID, string(StatusUnderReview), editorIdentity.Pseudonym)
    if err != nil {
        return fmt.Errorf("failed to update paper status on blockchain: %v", err)
    }

    // 更新本地缓存
    if paper, exists := sm.papers[paperID]; exists {
        paper.Status = string(StatusUnderReview)
        paper.UpdatedAt = time.Now().Format(time.RFC3339)
    }

    // 记录交易到区块链
    transaction := &Transaction{
        TxID:         sm.generateTransactionID(),
        PaperID:      paperID,
        UserIdentity: editorIdentity.Pseudonym,
        Action:       "RECEIVE_PAPER",
        Phase:        string(PhaseSubmission),
        Timestamp:    time.Now().Format(time.RFC3339),
        Data: map[string]string{
            "previousStatus": string(StatusSubmitted),
            "newStatus":      string(StatusUnderReview),
        },
    }
    
    err = sm.blockchainClient.RecordTransaction(transaction)
    if err != nil {
        return fmt.Errorf("failed to record transaction to blockchain: %v", err)
    }

    sm.transactions = append(sm.transactions, transaction)

    return nil
}

// SendMessage 发送消息（记录到区块链）
func (sm *SubmissionManager) SendMessage(fromUserID, toUserID, paperID, content, messageType string) (*Message, error) {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    // 验证论文存在（从区块链读取）
    _, err := sm.blockchainClient.ReadPaper(paperID)
    if err != nil {
        return nil, fmt.Errorf("paper not found on blockchain: %v", err)
    }

    // 验证发送者和接收者
    fromUser, err := sm.userManager.GetUser(fromUserID)
    if err != nil {
        return nil, fmt.Errorf("sender not found: %v", err)
    }

    toUser, err := sm.userManager.GetUser(toUserID)
    if err != nil {
        return nil, fmt.Errorf("recipient not found: %v", err)
    }

    // 获取发送者和接收者身份
    fromIdentity, err := sm.identityManager.GetOrCreatePhaseIdentity(
        fromUserID,
        fromUser.Role,
        PhaseSubmission,
        paperID,
        nil,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to get sender identity: %v", err)
    }

    toIdentity, err := sm.identityManager.GetOrCreatePhaseIdentity(
        toUserID,
        toUser.Role,
        PhaseSubmission,
        paperID,
        nil,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to get recipient identity: %v", err)
    }

    // 创建消息
    message := &Message{
        MessageID:    sm.generateMessageID(),
        PaperID:      paperID,
        FromIdentity: fromIdentity.Pseudonym,
        ToIdentity:   toIdentity.Pseudonym,
        Content:      content,
        MessageType:  messageType,
        Timestamp:    time.Now().Format(time.RFC3339),
        Phase:        string(PhaseSubmission),
    }

    // 发送到区块链
    err = sm.blockchainClient.SendMessage(message)
    if err != nil {
        return nil, fmt.Errorf("failed to send message to blockchain: %v", err)
    }

    // 本地存储
    sm.messages[paperID] = append(sm.messages[paperID], message)

    return message, nil
}

// GetPaper 获取论文信息（优先从区块链读取）
func (sm *SubmissionManager) GetPaper(paperID string) (*Paper, error) {
    // 从区块链读取最新数据
    paper, err := sm.blockchainClient.ReadPaper(paperID)
    if err != nil {
        return nil, fmt.Errorf("failed to read paper from blockchain: %v", err)
    }

    // 更新本地缓存
    sm.mutex.Lock()
    sm.papers[paperID] = paper
    sm.mutex.Unlock()

    return paper, nil
}

// GetPapersByAuthor 获取作者的论文列表（从区块链读取）
func (sm *SubmissionManager) GetPapersByAuthor(authorID string) ([]*Paper, error) {
    // 获取作者身份
    authorIdentity, err := sm.identityManager.GetUserMapping(authorID)
    if err != nil {
        return nil, fmt.Errorf("failed to get author identity: %v", err)
    }

    // 从区块链读取
    papers, err := sm.blockchainClient.GetPapersByAuthor(authorIdentity.OnChainIdentity)
    if err != nil {
        return nil, fmt.Errorf("failed to get papers from blockchain: %v", err)
    }

    return papers, nil
}

// GetMessages 获取论文的消息列表（从区块链读取）
func (sm *SubmissionManager) GetMessages(paperID string) ([]*Message, error) {
    messages, err := sm.blockchainClient.GetMessagesByPaper(paperID)
    if err != nil {
        return nil, fmt.Errorf("failed to get messages from blockchain: %v", err)
    }

    return messages, nil
}

// GetAllPapers 获取所有论文（从区块链读取）
func (sm *SubmissionManager) GetAllPapers() ([]*Paper, error) {
    return sm.blockchainClient.GetAllPapers()
}

// GetPaperHistory 获取论文历史记录
func (sm *SubmissionManager) GetPaperHistory(paperID string) ([]map[string]interface{}, error) {
    return sm.blockchainClient.GetPaperHistory(paperID)
}

// 辅助方法保持不变
func (sm *SubmissionManager) generatePaperID(authorID, title string) string {
    data := fmt.Sprintf("%s|%s|%d", authorID, title, time.Now().UnixNano())
    hash := sha256.Sum256([]byte(data))
    return "paper_" + hex.EncodeToString(hash[:8])
}

func (sm *SubmissionManager) generateTransactionID() string {
    data := fmt.Sprintf("tx_%d_%d", time.Now().UnixNano(), len(sm.transactions))
    hash := sha256.Sum256([]byte(data))
    return "tx_" + hex.EncodeToString(hash[:8])
}

func (sm *SubmissionManager) generateMessageID() string {
    data := fmt.Sprintf("msg_%d", time.Now().UnixNano())
    hash := sha256.Sum256([]byte(data))
    return "msg_" + hex.EncodeToString(hash[:8])
}

func (sm *SubmissionManager) calculateContentHash(content string) string {
    hash := sha256.Sum256([]byte(content))
    return hex.EncodeToString(hash[:])
}

// PublishingClient 区块链客户端接口，抽象学术出版链上操作
type PublishingClient interface {
    SubmitPaper(paper *Paper) error
    ReadPaper(paperID string) (*Paper, error)
    UpdatePaperStatus(paperID, newStatus, editorIdentity string) error
    UpdatePaperPhase(paperID, newPhase string) error
    GetPapersByAuthor(authorIdentity string) ([]*Paper, error)
    SendMessage(message *Message) error
    GetMessagesByPaper(paperID string) ([]*Message, error)
    RecordTransaction(transaction *Transaction) error
    GetAllPapers() ([]*Paper, error)
    GetPaperHistory(paperID string) ([]map[string]interface{}, error)
}

// integratedPublishingClient 内联实现（来源于 academicPublishingClient.go 的逻辑）
type integratedPublishingClient struct {
    clientConnection *grpc.ClientConn
    id               *identity.X509Identity
    sign             identity.Sign
    gateway          *client.Gateway
    network          *client.Network
    contract         *client.Contract
}

// —— 以下为连接与帮助函数（与 academicPublishingClient.go 保持一致） ——
const (
    mspID          = "Org1MSP"
    cryptoPath     = "..\\fabric-samples\\test-network\\organizations\\peerOrganizations\\org1.example.com\\users\\User1@org1.example.com\\msp"
    certPath       = cryptoPath + "\\signcerts\\cert.pem"
    keyPath        = cryptoPath + "\\keystore"
    tlsCertPath    = "..\\fabric-samples\\test-network\\organizations\\peerOrganizations\\org1.example.com\\peers\\peer0.org1.example.com\\tls\\ca.crt"
    peerEndpoint   = "localhost:7051"
    gatewayPeer    = "peer0.org1.example.com"
)

func readFirstFile(dir string) (string, error) {
    files, err := os.ReadDir(dir)
    if err != nil || len(files) == 0 {
        return "", err
    }
    return path.Join(dir, files[0].Name()), nil
}

func newGrpcConnection() (*grpc.ClientConn, error) {
    cert, err := os.ReadFile(tlsCertPath)
    if err != nil {
        return nil, err
    }
    cp := x509.NewCertPool()
    if !cp.AppendCertsFromPEM(cert) {
        return nil, fmt.Errorf("failed to add server CA's certificate")
    }
    creds := credentials.NewClientTLSFromCert(cp, gatewayPeer)
    return grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(creds))
}

func newIdentity() (*identity.X509Identity, error) {
    cert, err := os.ReadFile(certPath)
    if err != nil {
        return nil, err
    }
    id, err := identity.NewX509Identity(mspID, string(cert))
    if err != nil {
        return nil, err
    }
    return id, nil
}

func newSign() (identity.Sign, error) {
    keyFile, err := readFirstFile(keyPath)
    if err != nil {
        return nil, err
    }
    privateKeyPEM, err := os.ReadFile(keyFile)
    if err != nil {
        return nil, err
    }
    privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
    if err != nil {
        return nil, err
    }
    return identity.NewPrivateKeySign(privateKey)
}

func newGateway(conn *grpc.ClientConn, id *identity.X509Identity, sign identity.Sign) (*client.Gateway, error) {
    return client.Connect(id, client.WithSign(sign), client.WithClientConnection(conn))
}

func getNetwork(gw *client.Gateway, channelName string) *client.Network {
    return gw.GetNetwork(channelName)
}

func getContract(network *client.Network, chaincodeName string) *client.Contract {
    return network.GetContract(chaincodeName)
}

func formatJSON(data []byte) string {
    var buf bytes.Buffer
    _ = json.Indent(&buf, data, "", "  ")
    return buf.String()
}

// NewIntegratedPublishingClient 工厂方法（默认 channel=academicchannel, cc=academicPublishing）
func NewIntegratedPublishingClient() (*integratedPublishingClient, error) {
    conn, err := newGrpcConnection()
    if err != nil {
        return nil, err
    }
    id, err := newIdentity()
    if err != nil {
        return nil, err
    }
    sign, err := newSign()
    if err != nil {
        return nil, err
    }
    gw, err := newGateway(conn, id, sign)
    if err != nil {
        return nil, err
    }
    network := getNetwork(gw, "academicchannel")
    contract := getContract(network, "academicPublishing")
    return &integratedPublishingClient{
        clientConnection: conn,
        id:               id,
        sign:             sign,
        gateway:          gw,
        network:          network,
        contract:         contract,
    }, nil
}

// —— 交易方法实现（保持与AcademicPublishingClient一致的签名） ——
func (c *integratedPublishingClient) SubmitPaper(paper *Paper) error {
    metadataJSON, _ := json.Marshal(paper.Metadata)
    _, err := c.contract.SubmitTransaction("SubmitPaper",
        paper.PaperID,
        paper.Title,
        paper.Abstract,
        paper.ContentHash,
        paper.AuthorIdentity,
        paper.Status,
        paper.Phase,
        string(metadataJSON),
    )
    return err
}

func (c *integratedPublishingClient) ReadPaper(paperID string) (*Paper, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("ReadPaper", paperID)
    if err != nil {
        return nil, err
    }
    var paper Paper
    if err := json.Unmarshal(evaluateResult, &paper); err != nil {
        return nil, err
    }
    return &paper, nil
}

func (c *integratedPublishingClient) UpdatePaperStatus(paperID, newStatus, editorIdentity string) error {
    _, err := c.contract.SubmitTransaction("UpdatePaperStatus", paperID, newStatus, editorIdentity)
    return err
}

func (c *integratedPublishingClient) UpdatePaperPhase(paperID, newPhase string) error {
    _, err := c.contract.SubmitTransaction("UpdatePaperPhase", paperID, newPhase)
    return err
}

func (c *integratedPublishingClient) GetPapersByAuthor(authorIdentity string) ([]*Paper, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("GetPapersByAuthor", authorIdentity)
    if err != nil {
        return nil, err
    }
    var papers []*Paper
    if err := json.Unmarshal(evaluateResult, &papers); err != nil {
        return nil, err
    }
    return papers, nil
}

func (c *integratedPublishingClient) SendMessage(message *Message) error {
    _, err := c.contract.SubmitTransaction("SendMessage",
        message.MessageID,
        message.PaperID,
        message.FromIdentity,
        message.ToIdentity,
        message.Content,
        message.MessageType,
        message.Phase,
    )
    return err
}

func (c *integratedPublishingClient) GetMessagesByPaper(paperID string) ([]*Message, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("GetMessagesByPaper", paperID)
    if err != nil {
        return nil, err
    }
    var messages []*Message
    if err := json.Unmarshal(evaluateResult, &messages); err != nil {
        return nil, err
    }
    return messages, nil
}

func (c *integratedPublishingClient) RecordTransaction(transaction *Transaction) error {
    dataJSON, _ := json.Marshal(transaction.Data)
    _, err := c.contract.SubmitTransaction("RecordTransaction",
        transaction.TxID,
        transaction.PaperID,
        transaction.UserIdentity,
        transaction.Action,
        transaction.Phase,
        string(dataJSON),
    )
    return err
}

func (c *integratedPublishingClient) GetAllPapers() ([]*Paper, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("GetAllPapers")
    if err != nil {
        return nil, err
    }
    var papers []*Paper
    if err := json.Unmarshal(evaluateResult, &papers); err != nil {
        return nil, err
    }
    return papers, nil
}

func (c *integratedPublishingClient) GetPaperHistory(paperID string) ([]map[string]interface{}, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("GetPaperHistory", paperID)
    if err != nil {
        return nil, err
    }
    var history []map[string]interface{}
    if err := json.Unmarshal(evaluateResult, &history); err != nil {
        return nil, err
    }
    return history, nil
}

func (c *integratedPublishingClient) Close() {
    if c.gateway != nil {
        c.gateway.Close()
    }
    if c.clientConnection != nil {
        _ = c.clientConnection.Close()
    }
}

// SubmissionManager 投稿管理器（集成区块链）
type SubmissionManager struct {
    papers          map[string]*Paper
    papersByAuthor  map[string][]string
    messages        map[string][]*Message
    transactions    []*Transaction
    userManager     *UserManager
    identityManager *EnhancedIdentityPolicyManager
    blockchainClient PublishingClient // 接口替换具体类型
    mutex           sync.RWMutex
}

// NewSubmissionManager 创建投稿管理器（支持传入实现PublishingClient的客户端；为nil时使用内联实现）
func NewSubmissionManager(userManager *UserManager, identityManager *EnhancedIdentityPolicyManager, blockchainClient PublishingClient) *SubmissionManager {
    if blockchainClient == nil {
        if c, err := NewIntegratedPublishingClient(); err == nil {
            blockchainClient = c
        } else {
            fmt.Printf("warning: init integrated client failed: %v\n", err)
        }
    }
    return &SubmissionManager{
        papers:          make(map[string]*Paper),
        papersByAuthor:  make(map[string][]string),
        messages:        make(map[string][]*Message),
        transactions:    make([]*Transaction, 0),
        userManager:     userManager,
        identityManager: identityManager,
        blockchainClient: blockchainClient,
    }
}

// ... existing code ...