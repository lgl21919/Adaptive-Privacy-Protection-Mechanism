package types

// UserRole 用户角色枚举
type UserRole string

const (
    RoleAuthor   UserRole = "AUTHOR"   // 作者
    RoleEditor   UserRole = "EDITOR"   // 编辑
    RoleReviewer UserRole = "REVIEWER" // 审稿人
)

// IdentityVisibility 身份可见性枚举
type IdentityVisibility string

const (
    VisibilityReal      IdentityVisibility = "REAL_IDENTITY" // 真实身份
    VisibilityPseudonym IdentityVisibility = "PSEUDONYMOUS"  // 伪名
    VisibilityAnonymous IdentityVisibility = "ANONYMOUS"     // 匿名
)

// IdentityPolicy 身份策略
type IdentityPolicy struct {
    Phase              PublishingPhase    `json:"phase"`
    Role               UserRole           `json:"role"`
    RequiredVisibility IdentityVisibility `json:"requiredVisibility"`
    Description        string             `json:"description"`
}

// User 用户信息
type User struct {
    UserID      string            `json:"userID"`
    Name        string            `json:"name"`
    Email       string            `json:"email"`
    Institution string            `json:"institution"`
    Role        UserRole          `json:"role"`
    Attributes  map[string]string `json:"attributes"`
    CreatedAt   string            `json:"createdAt"`
}

// PaperStatus 论文状态
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

// DataSecurityLevel 数据安全级别枚举
type DataSecurityLevel int

const (
	DataSecLevel0 DataSecurityLevel = 0 // 不加密（公开）
	DataSecLevel1 DataSecurityLevel = 1 // 基础加密
	DataSecLevel2 DataSecurityLevel = 2 // 高级加密
	DataSecLevel3 DataSecurityLevel = 3 // 强加密
)

// DataType 数据类型枚举
type DataType string

const (
	DataTypeManuscript          DataType = "MANUSCRIPT"           // 稿件
	DataTypeMessage             DataType = "MESSAGE"              // 交互消息
	DataTypeEncryptionKey       DataType = "ENCRYPTION_KEY"       // 加密密钥
	DataTypeSupplementaryData   DataType = "SUPPLEMENTARY_DATA"    // 补充数据
	DataTypeFinalRecommendation DataType = "FINAL_RECOMMENDATION" // 最终建议/投票
)
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
    UpdatedAt      string            `json:"UpdatedAt"`
	Version        int               `json:"Version"`      // 大写匹配链码
    Metadata       map[string]string `json:"Metadata,omitempty"` // 大写匹配链码，添加omitempty
}

// 添加到现有的 types.go 文件中

// EncryptedData 加密数据结构
type EncryptedData struct {
	DataID       string              `json:"data_id"`
	PaperID      string              `json:"paper_id,omitempty"`
	FromUserID   string              `json:"fromUserID"`     // 保留小写，链下使用
	FromIdentity string              `json:"FromIdentity"`   // 大写匹配链码
	ToUserIDs    []string            `json:"toUserIDs"`      // 修改为列表，支持群发，保留小写，链下使用
	ToIdentities []string            `json:"ToIdentities"`   // 修改为列表，支持群发，大写匹配链码
	L1Content    []byte              `json:"l1_content"`     // Layer1加密内容-被re-encry加密的数据或AES密钥
	L1Encrypted  bool                `json:"l1_encrypted"`   // 标记L1内容是否加密
	L1EncryptionType string          `json:"l1_encryption_type,omitempty"` // 加密类型（Re-encry、Public）
	L2Content    []byte              `json:"l2_content,omitempty"` // Layer2加密内容-被AES加密的数据
	L2Encrypted  bool                `json:"l2_encrypted"`   // 标记L2内容是否加密
	L2EncryptionType string          `json:"l2_encryption_type,omitempty"` // 加密类型（如ECDH、SSS）
	DataType     DataType            `json:"data_type,omitempty"` // 数据类型
	SecurityLevel DataSecurityLevel  `json:"security_level,omitempty"` // 数据安全级别（0-3）
	Phase        PublishingPhase     `json:"phase"`
	Timestamp    int64               `json:"timestamp"`
	Metadata     map[string][]byte   `json:"metadata"`
	AccessControl map[string]string  `json:"access_control,omitempty"`  // 访问控制信息
}

// EncryptedPaper 加密的论文结构体，用于存储到区块链
type EncryptedPaper struct {
	PaperID        string            `json:"PaperID"`        // 大写匹配链码
	Version        int               `json:"Version"`        // 版本号
	Title          string            `json:"Title"`          // 大写匹配链码
	Abstract       string            `json:"Abstract"`       // 大写匹配链码
	ContentHash    string            `json:"ContentHash"`    // 大写匹配链码
	AuthorID       string            `json:"AuthorID"`       // 大写匹配链码
	AuthorIdentity string            `json:"AuthorIdentity"` // 大写匹配链码
	FromUserID     string            `json:"fromUserID"`     // 保留小写，链下使用
	FromIdentity   string            `json:"FromIdentity"`   // 大写匹配链码
	ToUserIDs      []string          `json:"toUserIDs"`      // 修改为列表，支持群发，保留小写，链下使用
	ToIdentities   []string          `json:"ToIdentities"`   // 修改为列表，支持群发，大写匹配链码
	L1Content      []byte            `json:"l1_content"`     // Layer1加密内容，被re-encry加密的AES密钥或密钥分片
	L1Encrypted    bool              `json:"l1_encrypted"`   // 标记L1内容是否加密
	L1EncryptionType string          `json:"l1_encryption_type,omitempty"` // 加密类型（Re-encry、Public）
	L2Content      map[string][]byte `json:"l2_content,omitempty"` // Layer2加密内容，key为用户ID，value为该用户对应的重加密密钥
	L2Encrypted    bool              `json:"l2_encrypted"`   // 标记L2内容是否加密
	L2EncryptionType string          `json:"l2_encryption_type,omitempty"` // 加密类型（如ECDH、SSS）
	DataType       DataType          `json:"data_type,omitempty"` // 数据类型（MANUSCRIPT等）
	SecurityLevel  DataSecurityLevel `json:"security_level,omitempty"` // 数据安全级别（0-3）
	Status         string            `json:"Status"`         // 大写匹配链码
	Phase          string            `json:"Phase"`          // 大写匹配链码
	SubmittedAt    string            `json:"SubmittedAt"`    // 大写匹配链码
	UpdatedAt      string            `json:"UpdatedAt"`      // 大写匹配链码
	Metadata       map[string][]byte `json:"Metadata,omitempty"` // 加密元数据
	AccessControl  map[string]string `json:"AccessControl,omitempty"`  // 访问控制信息
}


// EncryptedMessage 加密的用户间消息
type EncryptedMessage struct {
	MessageID    string              `json:"message_id"`
	PaperID      string              `json:"paper_id,omitempty"`
	FromUserID   string              `json:"fromUserID"`     // 保留小写，链下使用
	FromIdentity string              `json:"FromIdentity"`   // 大写匹配链码
	ToUserIDs    []string            `json:"toUserIDs"`      // 修改为列表，支持群发，保留小写，链下使用
	ToIdentities []string            `json:"ToIdentities"`   // 修改为列表，支持群发，大写匹配链码
	L1Content    []byte              `json:"l1_content"`     // Layer1加密内容-被re-encry加密的数据或AES密钥
	L1Encrypted  bool                `json:"l1_encrypted"`   // 标记L1内容是否加密
	L1EncryptionType string          `json:"l1_encryption_type,omitempty"` // 加密类型（Re-encry、Public）
	L2Content    []byte              `json:"l2_content,omitempty"` // Layer2加密内容-被AES加密的数据
	L2Encrypted  bool                `json:"l2_encrypted"`   // 标记L2内容是否加密
	L2EncryptionType string          `json:"l2_encryption_type,omitempty"` // 加密类型（如ECDH、SSS）
	DataType     DataType            `json:"data_type,omitempty"` // 数据类型（MESSAGE、SUPPLEMENTARY_DATA、FINAL_RECOMMENDATION等）
	SecurityLevel DataSecurityLevel  `json:"security_level,omitempty"` // 数据安全级别（0-3）
	Phase        PublishingPhase     `json:"phase"`
	Timestamp    int64               `json:"timestamp"`
	Metadata     map[string][]byte   `json:"metadata"`
	AccessControl map[string]string  `json:"access_control,omitempty"`  // 访问控制信息
}

// OrganizationInfo 表示组织的详细信息
type OrganizationInfo struct {
    // 基本组织信息
    OrgName    string `json:"org_name"`              // 组织名称（如"出版社"、"某某出版集团"等）
    OrgID      string `json:"org_id"`                // 组织唯一标识符
    OrgType    string `json:"org_type"`              // 组织类型（如"publisher"、"university"等）
    
    // 组织结构信息
    Department string `json:"department,omitempty"`  // 部门（如"审稿部门"、"出版部门"等）
    Branch     string `json:"branch,omitempty"`      // 分支机构（如"北京分社"）
    Unit       string `json:"unit,omitempty"`        // 单位
    
    // 职位信息
    Position        string `json:"position,omitempty"`        // 职位（如"审稿编辑"、"主编"等）
    Level           string `json:"level,omitempty"`           // 级别（如"junior"、"senior"等）
    Responsibilities string `json:"responsibilities,omitempty"` // 职责范围
    
    // 其他信息
    JoinDate      string `json:"join_date,omitempty"`      // 加入组织日期
    Certification  string `json:"certification,omitempty"`  // 相关资质认证
    Status         string `json:"status,omitempty"`         // 状态（如"active"、"inactive"）
    
    // 扩展字段，用于存储其他可能需要的组织信息
    ExtraInfo      map[string]string `json:"extra_info,omitempty"`
}

// UserIdentityInfo 用户身份信息
type UserIdentityInfo struct {
    // 基本身份信息
    Username        string            `json:"username,omitempty"`  // 用户名（链下使用，链上不保存明文）
    HashedUsername  string            `json:"hashed_username"`     // 哈希处理后的用户名（链上使用）
	OffChainID      string            `json:"off_chain_id"`        // 链下ID
    OnChainIdentity string            `json:"on_chain_identity"`   // 链上身份标识
    
    // Fabric 特有身份信息
    MSPID           string            `json:"msp_id"`              // 成员服务提供商ID
    CertSerialNum   string            `json:"cert_serial_num,omitempty"` // 证书序列号
    PublicKey       string            `json:"public_key,omitempty"`      // 用户公钥
    
    // 组织与角色信息
    OrgInfo         *OrganizationInfo `json:"org_info,omitempty"`        // 组织信息，包含组织名称、组织单位等
    Role            string            `json:"role"`                // 用户角色
    Phase           string            `json:"phase"`               // 阶段信息
    
    // 权限与访问控制
    Channels        []string          `json:"channels,omitempty"`        // 可访问的通道列表
    Contracts       []string          `json:"contracts,omitempty"`       // 可调用的合约列表
    AccessLevel     int               `json:"access_level,omitempty"`    // 访问权限级别
    
    // 证书与时间信息
    CertValidFrom   int64             `json:"cert_valid_from,omitempty"` // 证书有效期起始
    CertValidTo     int64             `json:"cert_valid_to,omitempty"`   // 证书有效期结束
    RegisteredAt    int64             `json:"registered_at,omitempty"`   // 注册时间
    UpdatedAt       int64             `json:"updated_at,omitempty"`      // 更新时间
    
    // 隐私与扩展信息
    PrivacyLevel    int               `json:"privacy_level,omitempty"`   // 隐私保护级别
    IsRevoked       bool              `json:"is_revoked,omitempty"`      // 是否已撤销
    Attributes      map[string]string `json:"attributes,omitempty"`      // 自定义属性
    Salt            string            `json:"-"`                   // 哈希盐值（不序列化）
}