package blockchain

import (
	"github.com/tap-thesis/privacy-protection-identity/internal/db"
	"github.com/tap-thesis/privacy-protection-identity/pkg/types"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// IdentityPolicyClient 身份策略区块链客户端
type IdentityPolicyClient struct {
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

// NewIdentityPolicyClient 创建身份策略区块链客户端（使用Org1 User身份）
func NewIdentityPolicyClient(chaincodeName string) (*IdentityPolicyClient, error) {
	// 使用Org1 User身份
	orgBasePath := "../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	
	client := &IdentityPolicyClient{
		mspID:         "Org1MSP",
		cryptoPath:    orgBasePath,
		certPath:      path.Join(orgBasePath, "users/User1@org1.example.com/msp/signcerts"),
		keyPath:       path.Join(orgBasePath, "users/User1@org1.example.com/msp/keystore"),
		tlsCertPath:   path.Join(orgBasePath, "peers/peer0.org1.example.com/tls/ca.crt"),
		peerEndpoint:  "dns:///localhost:7051",
		gatewayPeer:   "peer0.org1.example.com",
		channelName:   "mychannel",
		chaincodeName: chaincodeName,
	}

	err := client.initialize()
	if err != nil {
		return nil, err
	}

	return client, nil
}

// initialize 初始化区块链客户端连接
func (c *IdentityPolicyClient) initialize() error {
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

	// 创建Gateway
	c.gateway, err = client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("创建Gateway失败: %w", err)
	}

	// 获取网络和合约
	c.network = c.gateway.GetNetwork(c.channelName)
	c.contract = c.network.GetContract(c.chaincodeName)

	return nil
}

// newGrpcConnection 创建gRPC连接
func (c *IdentityPolicyClient) newGrpcConnection() (*grpc.ClientConn, error) {
	tlsCert, err := os.ReadFile(c.tlsCertPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(tlsCert)

	transportCredentials := credentials.NewClientTLSFromCert(certPool, c.gatewayPeer)
	connection, err := grpc.Dial(c.peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return connection, nil
}

// newIdentity 创建身份
func (c *IdentityPolicyClient) newIdentity() (*identity.X509Identity, error) {
	certPath := path.Join(c.certPath, "cert.pem")
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
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

// newSign 创建签名
func (c *IdentityPolicyClient) newSign() (identity.Sign, error) {
	files, err := os.ReadDir(c.keyPath)
	if err != nil {
		return nil, err
	}

	privateKeyPEM, err := os.ReadFile(path.Join(c.keyPath, files[0].Name()))
	if err != nil {
		return nil, err
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, err
	}

	return sign, nil
}

// Close 关闭连接
func (c *IdentityPolicyClient) Close() {
	if c.gateway != nil {
		c.gateway.Close()
	}
}

// SaveUserIdentity 保存用户身份信息到链上
func (c *IdentityPolicyClient) SaveUserIdentity(userInfo db.UserIdentityInfo) error {
	// 转换为链码需要的格式（使用大写的 JSON 字段名）
	chaincodeUserInfo := map[string]interface{}{
		"Username":        userInfo.Username,
		"OffChainID":      userInfo.OffChainID,
		"OnChainIdentity": userInfo.OnChainIdentity,
		"PseudonymBase":   userInfo.PseudonymBase,
		"PhasePseudonym":  userInfo.PhasePseudonym,
		"Role":            userInfo.Role,
		"Phase":           userInfo.Phase,
		"ReviewMode":      userInfo.ReviewMode,
		"Attributes":      userInfo.Attributes,
		// CreatedAt 和 UpdatedAt 由链码自动设置
	}

	userInfoJSON, err := json.Marshal(chaincodeUserInfo)
	if err != nil {
		return fmt.Errorf("序列化用户身份信息失败: %w", err)
	}

	// 调用链码
	_, err = c.contract.SubmitTransaction("SaveUserIdentity", string(userInfoJSON))
	if err != nil {
		// 提供更详细的错误信息
		return fmt.Errorf("调用SaveUserIdentity链码失败 (OffChainID: %s, Phase: %s, Role: %s): %w", 
			userInfo.OffChainID, userInfo.Phase, userInfo.Role, err)
	}

	return nil
}

// GetUserIdentity 获取用户身份信息
func (c *IdentityPolicyClient) GetUserIdentity(offChainID, phase, reviewMode string) (*db.UserIdentityInfo, error) {
	// 调用链码
	result, err := c.contract.EvaluateTransaction("GetUserIdentity", offChainID, phase, reviewMode)
	if err != nil {
		return nil, fmt.Errorf("调用GetUserIdentity链码失败: %w", err)
	}

	var userInfo db.UserIdentityInfo
	err = json.Unmarshal(result, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("反序列化用户身份信息失败: %w", err)
	}

	return &userInfo, nil
}

// SaveIdentityPolicy 保存身份保护策略到链上
func (c *IdentityPolicyClient) SaveIdentityPolicy(
	offChainID string,
	phase types.PublishingPhase,
	role types.UserRole,
	reviewMode types.ReviewMode,
	requiredVisibility types.IdentityVisibility,
	description string,
) error {
	// 构建策略对象
	policy := map[string]interface{}{
		"OffChainID":        offChainID,
		"Phase":             string(phase),
		"Role":              string(role),
		"ReviewMode":        string(reviewMode),
		"RequiredVisibility": string(requiredVisibility),
		"Description":       description,
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("序列化身份策略失败: %w", err)
	}

	// 调用链码
	_, err = c.contract.SubmitTransaction("SaveIdentityPolicy", string(policyJSON))
	if err != nil {
		return fmt.Errorf("调用SaveIdentityPolicy链码失败: %w", err)
	}

	return nil
}

// GetIdentityPolicy 获取身份保护策略
func (c *IdentityPolicyClient) GetIdentityPolicy(offChainID, phase, role, reviewMode string) (map[string]interface{}, error) {
	// 调用链码
	result, err := c.contract.EvaluateTransaction("GetIdentityPolicy", offChainID, phase, role, reviewMode)
	if err != nil {
		return nil, fmt.Errorf("调用GetIdentityPolicy链码失败: %w", err)
	}

	var policy map[string]interface{}
	err = json.Unmarshal(result, &policy)
	if err != nil {
		return nil, fmt.Errorf("反序列化身份策略失败: %w", err)
	}

	return policy, nil
}

// BatchSaveUserIdentities 批量保存用户身份信息
func (c *IdentityPolicyClient) BatchSaveUserIdentities(userInfos []db.UserIdentityInfo) error {
	for _, userInfo := range userInfos {
		err := c.SaveUserIdentity(userInfo)
		if err != nil {
			return fmt.Errorf("保存用户身份信息失败 (OffChainID: %s, Phase: %s): %w", userInfo.OffChainID, userInfo.Phase, err)
		}
	}
	return nil
}

