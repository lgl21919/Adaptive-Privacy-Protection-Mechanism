package blockchain

import (
    "github.com/tap-thesis/privacy-protection-identity/pkg/types"
    "bytes"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "os"
    "path"
    "time"
	"log"
	"encoding/pem"

    "github.com/hyperledger/fabric-gateway/pkg/client"
    "github.com/hyperledger/fabric-gateway/pkg/identity"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// BlockchainClientConfig 区块链客户端配置
type BlockchainClientConfig struct {
    MSPID         string
    CryptoPath    string
    CertPath      string
    KeyPath       string
    TLSCertPath   string
    PeerEndpoint  string
    GatewayPeer   string
    ChannelName   string
    ChaincodeName string
}

// AcademicPublishingClient 学术出版区块链客户端
type AcademicPublishingClient struct {
    mspID         string
    cryptoPath    string
    certPath      string
    keyPath       string
    tlsCertPath   string
    peerEndpoint  string
    gatewayPeer   string
    channelName   string
    chaincodeName string
    
    contract *client.Contract
    gateway  *client.Gateway
    network  *client.Network
}

// NewClientWithConfig 使用配置创建学术出版区块链客户端
func NewClientWithConfig(config BlockchainClientConfig) (*AcademicPublishingClient, error) {
    apclient := &AcademicPublishingClient{
        mspID:         config.MSPID,
        cryptoPath:    config.CryptoPath,
        certPath:      config.CertPath,
        keyPath:       config.KeyPath,
        tlsCertPath:   config.TLSCertPath,
        peerEndpoint:  config.PeerEndpoint,
        gatewayPeer:   config.GatewayPeer,
        channelName:   config.ChannelName,
        chaincodeName: config.ChaincodeName,
    }
    
    err := apclient.initialize()
    if err != nil {
        return nil, err
    }
    
    return apclient, nil
}

// NewClient 使用默认配置创建学术出版区块链客户端
func NewClient() (*AcademicPublishingClient, error) {
    config := BlockchainClientConfig{
        MSPID:         "Org1MSP",
        CryptoPath:    "../../test-network/organizations/peerOrganizations/org1.example.com",
        CertPath:      "../../test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts",
        KeyPath:       "../../test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore",
        TLSCertPath:   "../../test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
        PeerEndpoint:  "dns:///localhost:7051",
        GatewayPeer:   "peer0.org1.example.com",
        ChannelName:   "mychannel",
        ChaincodeName: "basic",
    }
    
    return NewClientWithConfig(config)
}

// initialize 初始化区块链客户端连接
func (c *AcademicPublishingClient) initialize() error {
    // gRPC连接
    clientConnection, err := c.newGrpcConnection()
    if err != nil {
        return fmt.Errorf("创建gRPC连接失败: %w", err)
    }

    // 身份和签名
    id, err := c.newIdentity()
    if err != nil {
        return fmt.Errorf("创建身份失败: %w", err)
    }
    
    sign, err := c.newSign()
    if err != nil {
        return fmt.Errorf("创建签名失败: %w", err)
    }

    // 创建Gateway连接
    gw, err := client.Connect(
        id,
        client.WithSign(sign),
        client.WithClientConnection(clientConnection),
        client.WithEvaluateTimeout(5*time.Second),
        client.WithEndorseTimeout(30*time.Second),
        client.WithSubmitTimeout(30*time.Second),
        client.WithCommitStatusTimeout(1*time.Minute),
    )
    if err != nil {
        return fmt.Errorf("连接Gateway失败: %w", err)
    }

    c.gateway = gw
    c.network = gw.GetNetwork(c.channelName)
    c.contract = c.network.GetContract(c.chaincodeName)

    return nil
}

// Close 关闭客户端连接
func (c *AcademicPublishingClient) Close() {
    if c.gateway != nil {
        c.gateway.Close()
    }
}

// SubmitPaper 提交论文到区块链
func (c *AcademicPublishingClient) SubmitPaper(paper *types.Paper) error {
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

// ReadPaper 从区块链读取论文
func (c *AcademicPublishingClient) ReadPaper(paperID string) (*types.Paper, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("ReadPaper", paperID)
    if err != nil {
        return nil, err
    }

    var paper types.Paper
    err = json.Unmarshal(evaluateResult, &paper)
    if err != nil {
        return nil, err
    }

    return &paper, nil
}

// UpdatePaperStatus 更新论文状态
func (c *AcademicPublishingClient) UpdatePaperStatus(paperID, newStatus, editorIdentity string) error {
    _, err := c.contract.SubmitTransaction("UpdatePaperStatus", paperID, newStatus, editorIdentity)
    return err
}

// UpdatePaperPhase 更新论文阶段
func (c *AcademicPublishingClient) UpdatePaperPhase(paperID, newPhase string) error {
    _, err := c.contract.SubmitTransaction("UpdatePaperPhase", paperID, newPhase)
    return err
}

// GetPapersByAuthor 获取作者的论文列表
func (c *AcademicPublishingClient) GetPapersByAuthor(authorIdentity string) ([]*types.Paper, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("GetPapersByAuthor", authorIdentity)
    if err != nil {
        return nil, err
    }

    var papers []*types.Paper
    err = json.Unmarshal(evaluateResult, &papers)
    if err != nil {
        return nil, err
    }

    return papers, nil
}

// SendMessage 发送消息到区块链
func (c *AcademicPublishingClient) SendMessage(message *types.Message) error {
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

// GetMessagesByPaper 获取论文的消息列表
func (c *AcademicPublishingClient) GetMessagesByPaper(paperID string) ([]*types.Message, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("GetMessagesByPaper", paperID)
    if err != nil {
        return nil, err
    }

    var messages []*types.Message
    err = json.Unmarshal(evaluateResult, &messages)
    if err != nil {
        return nil, err
    }

    return messages, nil
}

// RecordTransaction 记录交易到区块链
func (c *AcademicPublishingClient) RecordTransaction(transaction *types.Transaction) error {
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

// GetAllPapers 获取所有论文
func (c *AcademicPublishingClient) GetAllPapers() ([]*types.Paper, error) {
    fmt.Println("===== 开始调用GetAllPapers链码 =====")
    
    // 尝试捕获所有可能的错误
    defer func() {
        if r := recover(); r != nil {
            fmt.Printf("GetAllPapers发生严重错误: %v\n", r)
        }
    }()
    
    evaluateResult, err := c.contract.EvaluateTransaction("GetAllPapers")
    if err != nil {
        fmt.Printf("调用链码失败: %v\n", err)
        return nil, err
    }
    
    fmt.Println("链码调用成功，返回数据长度:", len(evaluateResult))
    
    // 打印原始返回数据以便调试
    fmt.Println("===== 区块链返回的原始数据 =====")
    fmt.Println(string(evaluateResult))
    fmt.Println("===============================")

    // 尝试直接解析为Paper数组
    var papers []*types.Paper
    err = json.Unmarshal(evaluateResult, &papers)
    if err != nil {
        fmt.Printf("解析失败，错误: %v\n", err)
        
        // 尝试解析为通用JSON结构，查看数据格式
        var rawData interface{}
        jsonErr := json.Unmarshal(evaluateResult, &rawData)
        if jsonErr == nil {
            rawJSON, _ := json.MarshalIndent(rawData, "", "  ")
            fmt.Println("===== 解析为通用JSON结构 =====")
            fmt.Println(string(rawJSON))
            fmt.Println("=============================")
        }
        
        // 尝试手动解析JSON，处理Metadata为null的情况
        var rawPapers []map[string]interface{}
        if jsonErr = json.Unmarshal(evaluateResult, &rawPapers); jsonErr == nil {
            fmt.Println("尝试手动处理Metadata为null的情况")
            for i, rawPaper := range rawPapers {
                paper := &types.Paper{}
                
                // 手动设置各个字段
                if v, ok := rawPaper["PaperID"].(string); ok {
                    paper.PaperID = v
                }
                if v, ok := rawPaper["Title"].(string); ok {
                    paper.Title = v
                }
                if v, ok := rawPaper["Abstract"].(string); ok {
                    paper.Abstract = v
                }
                if v, ok := rawPaper["Content"].(string); ok {
                    paper.Content = v
                }
                if v, ok := rawPaper["ContentHash"].(string); ok {
                    paper.ContentHash = v
                }
                if v, ok := rawPaper["AuthorID"].(string); ok {
                    paper.AuthorID = v
                }
                if v, ok := rawPaper["AuthorIdentity"].(string); ok {
                    paper.AuthorIdentity = v
                }
                if v, ok := rawPaper["Status"].(string); ok {
                    paper.Status = v
                }
                if v, ok := rawPaper["Phase"].(string); ok {
                    paper.Phase = v
                }
                if v, ok := rawPaper["SubmittedAt"].(string); ok {
                    paper.SubmittedAt = v
                }
                if v, ok := rawPaper["UpdatedAt"].(string); ok {
                    paper.UpdatedAt = v
                }
                
                // 确保Metadata不为nil
                paper.Metadata = make(map[string]string)
                if metadata, ok := rawPaper["Metadata"].(map[string]interface{}); ok {
                    for k, v := range metadata {
                        if strVal, ok := v.(string); ok {
                            paper.Metadata[k] = strVal
                        }
                    }
                }
                
                papers = append(papers, paper)
                fmt.Printf("手动解析论文 %d: ID=%s\n", i, paper.PaperID)
            }
            
            if len(papers) > 0 {
                fmt.Println("手动解析成功，返回论文数量:", len(papers))
                return papers, nil
            }
        }
        
        return nil, err
    }

    // 确保每个Paper的Metadata不为nil
    for i, paper := range papers {
        fmt.Printf("论文 %d: ID=%s, Metadata类型=%T\n", i, paper.PaperID, paper.Metadata)
        if paper.Metadata == nil {
            paper.Metadata = make(map[string]string)
            fmt.Printf("论文 %d: 初始化了空的Metadata\n", i)
        }
    }

    return papers, nil
}

// GetPaperHistory 获取论文历史记录
func (c *AcademicPublishingClient) GetPaperHistory(paperID string) ([]map[string]interface{}, error) {
    evaluateResult, err := c.contract.EvaluateTransaction("GetPaperHistory", paperID)
    if err != nil {
        return nil, err
    }

    var history []map[string]interface{}
    err = json.Unmarshal(evaluateResult, &history)
    if err != nil {
        return nil, err
    }

    return history, nil
}

// 辅助函数：从map中安全获取字符串值
func getString(m map[string]interface{}, key string) string {
    if val, ok := m[key]; ok {
        if str, ok := val.(string); ok {
            return str
        }
    }
    return ""
}

// 辅助函数
func (c *AcademicPublishingClient) newGrpcConnection() (*grpc.ClientConn, error) {
    certificatePEM, err := os.ReadFile(c.tlsCertPath)
    if err != nil {
        return nil, fmt.Errorf("读取TLS证书文件失败: %w", err)
    }

    certificate, err := identity.CertificateFromPEM(certificatePEM)
    if err != nil {
        return nil, err
    }

    certPool := x509.NewCertPool()
    certPool.AddCert(certificate)
    transportCredentials := credentials.NewClientTLSFromCert(certPool, c.gatewayPeer)

    connection, err := grpc.Dial(c.peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
    if err != nil {
        return nil, fmt.Errorf("创建gRPC连接失败: %w", err)
    }

    return connection, nil
}

func (c *AcademicPublishingClient) newIdentity() (*identity.X509Identity, error) {
    certificatePEM, err := c.readFirstFile(c.certPath)
    if err != nil {
        return nil, fmt.Errorf("读取证书文件失败: %w", err)
    }

    certificate, err := identity.CertificateFromPEM(certificatePEM)
    if err != nil {
        return nil, err
    }

    id, err := identity.NewX509Identity(c.mspID, certificate)
    if err != nil {
        return nil, err
    }

    return id, nil
}

func (c *AcademicPublishingClient) newSign() (identity.Sign, error) {
    log.Printf("开始创建签名，密钥路径: %s", c.keyPath)
    
    privateKeyPEM, err := c.readFirstFile(c.keyPath)
    if err != nil {
        log.Printf("读取私钥文件失败: %v", err)
        return nil, fmt.Errorf("读取私钥文件失败: %w", err)
    }
    log.Printf("成功读取私钥文件，长度: %d 字节", len(privateKeyPEM))

    // 解码PEM格式
    block, _ := pem.Decode(privateKeyPEM)
    if block == nil {
        return nil, fmt.Errorf("无法解码PEM格式的私钥")
    }
    
    // 直接使用ParseECPrivateKey解析
    privateKey, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil {
        log.Printf("解析EC私钥失败: %v", err)
        return nil, fmt.Errorf("解析EC私钥失败: %w", err)
    }
    log.Printf("成功解析EC私钥")

    // 使用解析出的EC私钥创建签名
    sign, err := identity.NewPrivateKeySign(privateKey)
    if err != nil {
        log.Printf("创建签名失败: %v", err)
        return nil, fmt.Errorf("创建签名失败: %w", err)
    }
    log.Printf("成功创建签名")

    return sign, nil
}

// 修改readFirstFile函数，使其与旧版本一致
func (c *AcademicPublishingClient) readFirstFile(dirPath string) ([]byte, error) {
    dir, err := os.Open(dirPath)
    if err != nil {
        return nil, err
    }
    defer dir.Close()

    fileNames, err := dir.Readdirnames(1)
    if err != nil {
        return nil, err
    }

    return os.ReadFile(path.Join(dirPath, fileNames[0]))
}

func formatJSON(data []byte) string {
    var prettyJSON bytes.Buffer
    if err := json.Indent(&prettyJSON, data, "", "  "); err != nil {
        return string(data)
    }
    return prettyJSON.String()
}