# 学术出版系统 - 基于Fabric的隐私保护实现

## 系统概述

本系统实现了一个基于Hyperledger Fabric的学术出版平台，支持三个阶段的出版流程：投稿、审稿、出版，并为三类用户角色（作者、编辑、审稿人）提供身份策略管理。

## 核心功能

### 1. 用户身份管理
- **线下注册**: 用户通过应用程序注册线下身份
- **链上映射**: 自动生成链上身份，实现一对一映射
- **身份策略**: 根据不同阶段和角色应用相应的身份可见性策略

### 2. 投稿阶段功能
- **作者投稿**: 上传PDF论文到区块链，记录论文哈希、时间戳等信息
- **编辑接收**: 编辑接收稿件并更新状态
- **消息交互**: 作者和编辑之间的消息交互上链记录

### 3. 身份策略
- **投稿阶段**: 作者和编辑使用真实身份
- **审稿阶段**: 作者和审稿人使用伪名，编辑使用真实身份
- **出版阶段**: 所有角色公开真实身份

## 文件结构
===================测试FABRIC 用户测试============
fabricCAclient-Test.go
user/fabricCAClient.go
config/config.go
config/config.yaml
fabricCAclient-Test.go
===================测试FABRIC 用户上传论文与消息发送============
academicpublishing-main.go
academicPublishingClient.go
chaincode/academicPublishing.go
types.go
go.mod
--------------------------
module academic-publishing

go 1.19

require (
	github.com/hyperledger/fabric-gateway v1.3.0
	github.com/hyperledger/fabric-sdk-go v1.0.0
	github.com/pkg/errors v0.9.1
	google.golang.org/grpc v1.54.0
)

require (
	github.com/golang/protobuf v1.5.3
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1
	google.golang.org/protobuf v1.30.0
)

replace google.golang.org/grpc => google.golang.org/grpc v1.54.0
---------------------------------------

===========接下来是动态身份策略管理=====================

因为用于fabric 用户注册和登记的fabric SDK protobuf 版本与用户连接链码fabric gateway  fabric SDK protobuf 版本不一致，同时运行两个实例会报错，此版本把main 分成两个文件，一个用于用户注册和登记，用于身份管理。另一个用户访问区块链，上传论文和消息。为了在用访问区块链main中获取身份main 生成的链上伪用户信息，增加了线下数据库，用于存储用户注册和登记信息，以及用户连接链码时使用的身份信息。同时修改了项目的结构。
academic-publishing/
├── cmd/
│   ├── identity_manager/
│   │   └── main.go         # 身份管理入口
│   └── paper_manager/
│       └── main.go         # 论文管理入口
├── internal/
│   ├── config/             # 配置相关
│   │   ├── config.go
│   │   └── config.yaml
│   ├── db/                 # 数据库相关
│   │   ├── db.go           # 数据库初始化和连接
│   │   └── models.go       # 数据模型定义
│   ├── blockchain/         # 区块链相关
│   │   └── client.go       # 区块链客户端
│   └── identity/           # 身份管理相关
│       └── manager.go      # 身份策略管理器
├── pkg/
│   └── types/              # 共享类型定义
│       └── types.go
└── go.mod
## 运行说明
1. 1.
   首先运行身份管理程序：
```
go run ./cmd/identity_manager/main.
go
```
1. 2.
   然后运行论文管理程序：
```
go run ./cmd/paper_manager/main.go
```
这种项目结构遵循了Go项目的最佳实践，具有以下优点：

1. 1.
   关注点分离 ：数据库操作、区块链交互、身份管理等功能被清晰地分离到不同的包中
2. 2.
   可维护性 ：每个包都有明确的职责，便于维护和扩展
3. 3.
   可测试性 ：各个组件可以独立测试
4. 4.
   可重用性 ：核心功能被封装在内部包中，可以被多个命令行工具共享
5. 5.
   避免循环依赖 ：通过合理的包结构设计，避免了循环依赖问题
这样的结构也有助于解决之前的 protobuf 命名空间冲突问题，因为现在我们可以将不同的功能分散到不同的可执行文件中运行

功能分离后，academicPublishingClient.go执行有问题，但newsign（）函数与academicPublishingClient-old.go（单独执行成功）一致，奇怪了，估计是gateway版本有变化，增加X.509 解析方式，就可以执行成功。
-----------------------------------------
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
    -------------------------------------------
       paper_manager/main.go 报错，sqlite3-binding.c: In function ‘sqlite3SelectNew’:

sqlite3-binding.c:123303:10: warning: function may return address of local variable [-Wreturn-local-addr]

123303 |   return pNew;

|          ^~~~

sqlite3-binding.c:123263:10: note: declared here

123263 |   Select standin;
---------------------------------------------
go get -u github.com/mattn/go-sqlite3 数据库不报错，但main2 执行提交论文阶段，却提示背书问题
docker logs peer0.org1.example.com 2>&1 | grep -i "error\|fail\|endors"
可以看到失败原因PAPER-user_010" 已经存在
2025-10-06 20:05:04.758 UTC 02ff WARN [gateway] func1 -> Endorse call to endorser failed channel=mychannel chaincode=basic txID=867b9972111372fd1119f82793d9aced4356f40d19fd6c1752ae8acf08d99d0c endorserAddress=peer0.org1.example.com:7051 endorserMspid=Org1MSP error="chaincode response 500, paper already exists: PAPER-user_010"
2025-10-06 20:05:04.759 UTC 0300 INFO [comm.grpc.server] 1 -> unary call completed grpc.service=gateway.Gateway grpc.method=Endorse grpc.request_deadline=2025-10-06T20:05:34.742Z grpc.peer_address=172.18.0.1:58222 error="rpc error: code = Aborted desc = failed to endorse transaction, see attached details for more info" grpc.code=Aborted grpc.call_duration=7.426951ms
2025-10-06 20:05:35.089 UTC 0301 INFO [endorser] callChaincode -> finished chaincode: basic duration: 2ms channel=mychannel txID=cce0166a
2025-10-06 20:05:35.089 UTC 0302 WARN [gateway] func1 -> Endorse call to endorser failed channel=mychannel chaincode=basic txID=cce0166af300f32ddf4182313ee6720be2e08e92860870f5d9551cd6be9dba12 endorserAddress=peer0.org1.example.com:7051 endorserMspid=Org1MSP error="chaincode response 500, paper already exists: PAPER-user_010"
----------解决方案，测试阶段需要不断的运行代码，增加一个技术器PAPERxxxx-user_010，每次运行都会生成PAPERxxxx-user_010 编号，解决PAPERID 相同，背书失败问题。


Trae
===================身份策略伪代码===============
提取IdentityPolicyManager中，最重要一个或多个函数，以伪代码形式展示在论文中

Trae

根据IdentityPolicyManager的实现，我提取了以下最重要的函数，并以伪代码形式展示，适合在论文中呈现：

## 算法1：身份策略管理器初始化
```
算法：
NewEnhancedIdentityPolicyManager
输入：无
输出：IdentityPolicyManager实例

函数 
NewEnhancedIdentityPolicyManager():
    manager = 新建 
    EnhancedIdentityPolicyManager 对
    象
    
    // 初始化身份策略
    manager.policies = [
        {Phase: "SUBMISSION", Role: 
        "AUTHOR", 
        RequiredVisibility: "REAL", 
         Description: "作者在投稿时必
         须使用真实身份"},
        {Phase: "SUBMISSION", Role: 
        "EDITOR", 
        RequiredVisibility: "REAL", 
         Description: "编辑在处理投稿
         时使用真实身份"},
        {Phase: "REVIEW", Role: 
        "AUTHOR", 
        RequiredVisibility: 
        "PSEUDONYM", 
         Description: "作者在审稿阶段
         使用伪名"},
        {Phase: "REVIEW", Role: 
        "REVIEWER", 
        RequiredVisibility: 
        "PSEUDONYM", 
         Description: "审稿人在双盲评
         审中使用伪名"},
        {Phase: "REVIEW", Role: 
        "EDITOR", 
        RequiredVisibility: "REAL", 
         Description: "编辑在审稿管理
         中使用真实身份"},
        {Phase: "PUBLICATION", 
        Role: "AUTHOR", 
        RequiredVisibility: "REAL", 
         Description: "出版时公开作者
         真实身份"},
        {Phase: "PUBLICATION", 
        Role: "REVIEWER", 
        RequiredVisibility: "REAL", 
         Description: "可选择公开致谢
         审稿人"}
    ]
    
    // 初始化存储映射
    manager.userMappings = 创建空映射
    表      // 链下ID到用户映射
    manager.phaseIdentities = 创建空
    映射表   // 上下文哈希到阶段身份
    manager.pseudonymRegistry = 创建
    空映射表 // 伪名到链下ID
    
    返回 manager
```
## 算法2：用户注册
```
算法：RegisterUser
输入：
    offChainUserID: 链下用户ID
    userAttributes: 用户属性
输出：
    userMapping: 用户身份映射

函数 RegisterUser(offChainUserID, 
userAttributes):
    // 检查用户是否已注册
    如果 offChainUserID 在 
    userMappings 中存在:
        userMapping = userMappings
        [offChainUserID]
        userMapping.LastAccessed = 
        当前时间
        返回 userMapping
    
    // 生成链上固定身份
    data = offChainUserID
    如果 userAttributes 包含 
    "institution":
        data += "|" + userAttributes
        ["institution"]
    如果 userAttributes 包含 "email":
        data += "|" + userAttributes
        ["email"]
    
    hash = SHA256(data)
    onChainIdentity = "user_" + hex
    (hash[0:12])  // 截取前12字节
    
    // 生成伪名基础
    pseudonymBase = hex(SHA256
    (offChainUserID + "|
    pseudonym_base")[0:16])
    
    // 创建映射
    userMapping = {
        OffChainUserID: 
        offChainUserID,
        OnChainIdentity: 
        onChainIdentity,
        PseudonymBase: 
        pseudonymBase,
        CreatedAt: 当前时间,
        LastAccessed: 当前时间
    }
    
    // 存储映射
    userMappings[offChainUserID] = 
    userMapping
    pseudonymRegistry
    [onChainIdentity] = 
    offChainUserID
    
    返回 userMapping
```
## 算法3：获取或创建阶段特定身份
```
算法：GetOrCreatePhaseIdentity
输入：
    offChainUserID: 链下用户ID
    userRole: 用户角色
    phase: 出版阶段
    paperID: 论文ID
    contextAttributes: 上下文属性
输出：
    phaseIdentity: 阶段特定身份

函数 GetOrCreatePhaseIdentity
(offChainUserID, userRole, phase, 
paperID, contextAttributes):
    // 验证用户是否已注册
    如果 offChainUserID 不在 
    userMappings 中:
        返回错误("用户未注册")
    
    userMapping = userMappings
    [offChainUserID]
    
    // 生成上下文哈希
    contextHash = SHA256
    (offChainUserID + "|" + phase + 
    "|" + paperID + "|" + userRole)
    
    // 检查是否已存在阶段身份
    如果 contextHash 在 
    phaseIdentities 中:
        phaseIdentity = 
        phaseIdentities[contextHash]
        phaseIdentity.Visibility = 
        GetVisibilityPolicy(phase, 
        userRole)
        返回 phaseIdentity
    
    // 获取可见性策略
    visibility = GetVisibilityPolicy
    (phase, userRole)
    
    // 根据策略生成相应的身份标识
    如果 visibility == "REAL":
        pseudonym = userMapping.
        OnChainIdentity  // 使用链上
        固定身份
    否则如果 visibility == 
    "PSEUDONYM":
        // 生成确定性伪名
        context = phase + "|" + 
        paperID + "|" + userRole
        data = userMapping.
        PseudonymBase + "|" + 
        context
        hash = SHA256(data)
        
        // 根据角色生成不同的前缀
        如果 userRole == "AUTHOR":
            prefix = "author"
        否则如果 userRole == 
        "REVIEWER":
            prefix = "reviewer"
        否则如果 userRole == 
        "EDITOR":
            prefix = "editor"
        否则:
            prefix = "user"
        
        pseudonym = prefix + "_" + 
        hex(hash[0:8])
        
        // 注册伪名映射（仅编辑可解析）
        pseudonymRegistry
        [pseudonym] = offChainUserID
    否则:  // visibility == 
    "ANONYMOUS"
        // 生成匿名身份
        anonymousHash = SHA256
        (phase + "|" + paperID + "|
        " + userRole + "|" + 随机字符
        串)
        pseudonym = "anon_" + hex
        (anonymousHash[0:8])
        // 匿名身份不注册映射
    
    // 创建阶段身份
    phaseIdentity = {
        Phase: phase,
        PaperID: paperID,
        Pseudonym: pseudonym,
        Visibility: visibility,
        ContextHash: contextHash
    }
    
    // 存储阶段身份
    phaseIdentities[contextHash] = 
    phaseIdentity
    userMapping.LastAccessed = 当前
    时间
    
    返回 phaseIdentity
```
## 算法4：解析伪名（仅编辑可用）
```
算法：ResolvePseudonym
输入：
    pseudonym: 伪名
    requesterRole: 请求者角色
输出：
    offChainUserID: 链下用户ID

函数 ResolvePseudonym(pseudonym, 
requesterRole):
    // 验证请求者权限
    如果 requesterRole != "EDITOR":
        返回错误("无权限解析伪名，仅编辑
        可用")
    
    // 查找伪名映射
    如果 pseudonym 不在 
    pseudonymRegistry 中:
        返回错误("未找到对应的伪名映射")
    
    offChainUserID = 
    pseudonymRegistry[pseudonym]
    返回 offChainUserID
```
## 算法5：获取可见性策略
```
算法：GetVisibilityPolicy
输入：
    phase: 出版阶段
    role: 用户角色
输出：
    visibility: 可见性策略

函数 GetVisibilityPolicy(phase, 
role):
    // 遍历策略列表查找匹配项
    对于每个 policy 在 policies 中:
        如果 policy.Phase == phase 
        且 policy.Role == role:
            返回 policy.
            RequiredVisibility
    
    // 默认为匿名可见性
    返回 "ANONYMOUS"
```
这些伪代码展示了IdentityPolicyManager的核心功能，包括身份策略管理器的初始化、用户注册、阶段特定身份生成和伪名解析等关键算法。这些算法清晰地表达了系统如何根据不同的出版阶段和用户角色管理身份可见性，以及如何实现伪名生成和解析过程。


========================伪代码========================
提取DataPolicyManager.go 中，最重要一个或多个函数，以伪代码形式展示在论文中

根据DataPolicyManager.go的实现，我提取了以下最重要的函数，并以伪代码形式展示，适合在论文中呈现：

## 算法1：数据策略管理器初始化
```
算法：NewEnhancedDataPolicyManager
输入：无
输出：DataPolicyManager实例

函数 NewEnhancedDataPolicyManager():
    manager = 新建 
    EnhancedDataPolicyManager 对象
    manager.policies = 创建空映射表
    
    // 初始化各种加密策略
    ecdhPolicy = 新建 
    ECDHEncryptionPolicy()
    sssPolicy = 新建 
    SSSEncryptionPolicy()
    publicPolicy = 新建 
    PublicEncryptionPolicy()
    
    // 配置各阶段和数据类型的加密策略
    // 提交阶段：论文和消息都使用ECDH加
    密
    manager.policies
    ["SUBMISSION_PAPER"] = 
    ecdhPolicy
    manager.policies
    ["SUBMISSION_MESSAGE"] = 
    ecdhPolicy
    
    // 审稿阶段：论文使用SSS加密，消息使
    用ECDH加密
    manager.policies
    ["REVIEW_PAPER"] = sssPolicy
    manager.policies
    ["REVIEW_MESSAGE"] = ecdhPolicy
    
    // 出版阶段：论文和消息都使用公开策略
    （不加密）
    manager.policies
    ["PUBLICATION_PAPER"] = 
    publicPolicy
    manager.policies
    ["PUBLICATION_MESSAGE"] = 
    publicPolicy
    
    返回 manager
```
## 算法2：数据加密
```
算法：EncryptData
输入：
    data: 待加密数据
    phase: 出版阶段
    dataType: 数据类型
    participants: 参与者列表
输出：
    encryptedData: 加密后的数据
    metadata: 元数据

函数 EncryptData(data, phase, 
dataType, participants):
    // 获取对应的加密策略
    policyKey = phase + "_" + 
    dataType
    policy = 从policies映射表中获取
    policyKey对应的策略
    
    如果 policy不存在:
        返回错误("未找到对应的加密策略")
    
    // 使用策略加密数据
    encryptedData, metadata = 
    policy.Encrypt(data, 
    participants)
    
    返回 encryptedData, metadata
```
## 算法3：数据解密
```
算法：DecryptData
输入：
    encryptedData: 加密数据
    metadata: 元数据
    phase: 出版阶段
    dataType: 数据类型
    participantID: 参与者ID
输出：
    decryptedData: 解密后的数据

函数 DecryptData(encryptedData, 
metadata, phase, dataType, 
participantID):
    // 获取对应的加密策略
    policyKey = phase + "_" + 
    dataType
    policy = 从policies映射表中获取
    policyKey对应的策略
    
    如果 policy不存在:
        返回错误("未找到对应的加密策略")
    
    // 使用策略解密数据
    decryptedData = policy.Decrypt
    (encryptedData, metadata, 
    participantID)
    
    返回 decryptedData
```
## 算法4：ECDH加密策略实现
```
算法：ECDH_Encrypt
输入：
    data: 待加密数据
    participants: 参与者列表
输出：
    encryptedData: 加密后的数据
    metadata: 元数据

函数 ECDH_Encrypt(data, 
participants):
    // 生成临时密钥对
    ephemeralKey = 生成ECDSA密钥对
    (P256曲线)
    
    // 生成AES加密密钥
    aesKey = 生成随机字节(32)  // 256
    位密钥
    
    // 使用AES-GCM加密数据
    nonce = 生成随机字节(12)
    ciphertext = AES_GCM_Encrypt
    (aesKey, nonce, data)
    
    // 将nonce附加到密文
    encryptedData = nonce + 
    ciphertext
    
    // 为每个参与者生成密钥元数据
    metadata = 创建空映射表
    ephemeralPubKeyBytes = 序列化
    (ephemeralKey.PublicKey)
    
    对于每个 participant 在 
    participants 中:
        // 获取参与者的公钥
        recipientKey = 获取参与者公钥
        (participant)
        
        // 计算共享密钥
        sharedSecret = 
        ECDH_ComputeSecret
        (ephemeralKey.PrivateKey, 
        recipientKey)
        
        // 使用HKDF从共享密钥派生加密密
        钥
        derivedKey = HKDF_SHA256
        (sharedSecret, 32)
        
        // 使用派生密钥加密AES密钥
        encryptedAESKey = 
        AES_Encrypt(derivedKey, 
        aesKey)
        
        // 存储元数据
        metadata[participant] = 
        ephemeralPubKeyBytes + 
        encryptedAESKey
    
    返回 encryptedData, metadata
```
## 算法5：ECDH解密策略实现
```
算法：ECDH_Decrypt
输入：
    encryptedData: 加密数据
    metadata: 元数据
    participantID: 参与者ID
输出：
    decryptedData: 解密后的数据

函数 ECDH_Decrypt(encryptedData, 
metadata, participantID):
    // 提取参与者的元数据
    participantMetadata = metadata
    [participantID]
    如果 participantMetadata不存在:
        返回错误("未找到参与者元数据")
    
    // 解析元数据
    ephemeralPubKeyBytes, 
    encryptedAESKey = 解析
    (participantMetadata)
    ephemeralPubKey = 反序列化公钥
    (ephemeralPubKeyBytes)
    
    // 获取参与者的私钥
    privateKey = 获取参与者私钥
    (participantID)
    
    // 计算共享密钥
    sharedSecret = 
    ECDH_ComputeSecret(privateKey, 
    ephemeralPubKey)
    
    // 使用HKDF从共享密钥派生解密密钥
    derivedKey = HKDF_SHA256
    (sharedSecret, 32)
    
    // 解密AES密钥
    aesKey = AES_Decrypt
    (derivedKey, encryptedAESKey)
    
    // 从加密数据中提取nonce和密文
    nonce = encryptedData[0:12]
    ciphertext = encryptedData[12:]
    
    // 使用AES-GCM解密数据
    decryptedData = AES_GCM_Decrypt
    (aesKey, nonce, ciphertext)
    
    返回 decryptedData
```
这些伪代码展示了DataPolicyManager的核心功能，包括策略管理器的初始化、数据加密和解密的通用接口，以及ECDH加密策略的具体实现。这些算法清晰地表达了系统如何根据不同的出版阶段和数据类型选择合适的加密策略，以及如何实现端到端的加密和解密过程。
==================链码伪代码===================
# 从 academicPublishingClient.go 提取的关键函数伪代码
## 1. 初始化区块链客户端
```
算法：NewClientWithConfig
输入：区块链配置信息 config
输出：学术出版区块链客户端实例

函数 NewClientWithConfig(config):
    // 创建客户端实例
    client = 新建 
    AcademicPublishingClient 对象
    client.mspID = config.MSPID
    client.cryptoPath = config.
    CryptoPath
    client.certPath = config.
    CertPath
    client.keyPath = config.KeyPath
    client.tlsCertPath = config.
    TLSCertPath
    client.peerEndpoint = config.
    PeerEndpoint
    client.gatewayPeer = config.
    GatewayPeer
    client.channelName = config.
    ChannelName
    client.chaincodeName = config.
    ChaincodeName
    
    // 初始化连接
    err = client.initialize()
    如果 err 不为空:
        返回 空, err
    
    返回 client, 空
```
## 2. 加密提交论文
```
算法：SubmitPaperWithEncryption
输入：论文对象 paper, 用户ID userID, 发
布阶段 phase
输出：加密后的论文对象

函数 SubmitPaperWithEncryption
(paper, userID, phase):
    // 获取数据策略管理器
    policyManager = 获取数据策略管理器
    ()
    
    // 根据阶段和数据类型加密论文内容
    encryptedContent, metadata, err 
    = policyManager.EncryptData(
        paper.Content的字节数组,
        userID,
        phase的字符串表示,
        "paper_content"
    )
    如果 err 不为空:
        返回 空, "加密论文内容失败"错误
    
    // 创建加密论文对象
    encryptedPaper = 新建 
    EncryptedPaper 对象
    encryptedPaper.PaperID = paper.
    PaperID
    encryptedPaper.Title = paper.
    Title
    encryptedPaper.Abstract = paper.
    Abstract
    encryptedPaper.Content = 
    encryptedContent
    encryptedPaper.ContentHash = 
    paper.ContentHash
    encryptedPaper.AuthorID = paper.
    AuthorID
    encryptedPaper.AuthorIdentity = 
    paper.AuthorIdentity
    encryptedPaper.Status = paper.
    Status
    encryptedPaper.Phase = paper.
    Phase
    encryptedPaper.SubmittedAt = 
    paper.SubmittedAt
    encryptedPaper.UpdatedAt = 
    paper.UpdatedAt
    encryptedPaper.Version = paper.
    Version
    encryptedPaper.Metadata = 
    metadata
    encryptedPaper.Encrypted = true
    encryptedPaper.EncryptionType = 
    policyManager.
    GetEncryptionPolicy(
        userID, 
        phase的字符串表示, 
        "paper_content"
    ).GetPolicyType()
    encryptedPaper.AccessControl = 
    [userID]  // 初始只有作者可以访问
    
    返回 encryptedPaper, 空
```
# 从 academicPublishingClient-old.go 提取的关键函数伪代码
## 1. 创建学术出版客户端
```
算法：NewAcademicPublishingClient
输入：无
输出：学术出版区块链客户端实例

函数 NewAcademicPublishingClient():
    // 创建gRPC连接
    clientConnection = 
    newGrpcConnection()
    
    // 获取身份和签名
    id = newIdentity()
    sign = newSign()
    
    // 创建Gateway连接
    gw, err = client.Connect(
        id,
        client.WithSign(sign),
        client.WithClientConnection
        (clientConnection),
        client.WithEvaluateTimeout(5
        秒),
        client.WithEndorseTimeout(15
        秒),
        client.WithSubmitTimeout(5
        秒),
        client.
        WithCommitStatusTimeout(1分
        钟)
    )
    如果 err 不为空:
        返回 空, "连接gateway失败"错误
    
    // 获取网络和合约
    network = gw.GetNetwork
    (channelName)
    contract = network.GetContract
    (chaincodeName)
    
    // 创建并返回客户端实例
    client = 新建 
    AcademicPublishingClient 对象
    client.contract = contract
    client.gateway = gw
    client.network = network
    
    返回 client, 空
```
## 2. 获取所有论文
```
算法：GetAllPapers
输入：无
输出：论文对象数组

函数 GetAllPapers():
    // 调用链码获取所有论文
    evaluateResult, err = contract.
    EvaluateTransaction
    ("GetAllPapers")
    如果 err 不为空:
        返回 空, err
    
    // 解析返回的JSON数据
    papers = 空的论文对象数组
    err = 将evaluateResult解析为
    papers
    如果 err 不为空:
        // 尝试处理特殊情况，如Metadata
        为null
        rawPapers = 空的map数组
        jsonErr = 将evaluateResult解
        析为rawPapers
        如果 jsonErr 为空:
            // 手动构建论文对象
            对于 rawPapers 中的每个 
            rawPaper:
                paper = 新建 Paper 
                对象
                paper.PaperID = 
                getString(rawPaper, 
                "PaperID")
                paper.Title = 
                getString(rawPaper, 
                "Title")
                paper.Abstract = 
                getString(rawPaper, 
                "Abstract")
                paper.ContentHash = 
                getString(rawPaper, 
                "ContentHash")
                paper.
                AuthorIdentity = 
                getString(rawPaper, 
                "AuthorIdentity")
                paper.Status = 
                getString(rawPaper, 
                "Status")
                paper.Phase = 
                getString(rawPaper, 
                "Phase")
                
                // 处理Metadata
                如果 rawPaper
                ["Metadata"] 不为 
                null:
                    metadataJSON = 
                    将rawPaper
                    ["Metadata"]转换
                    为JSON字符串
                    paper.Metadata 
                    = 解析
                    metadataJSON
                
                将paper添加到papers中
            
            返回 papers, 空
    
    返回 papers, 空
```
## 3. 记录交易
```
算法：RecordTransaction
输入：交易对象 transaction
输出：错误信息

函数 RecordTransaction(transaction):
    // 将交易数据转换为JSON
    dataJSON = 将transaction.Data转
    换为JSON字符串
    
    // 调用链码记录交易
    _, err = contract.
    SubmitTransaction(
        "RecordTransaction",
        transaction.TxID,
        transaction.PaperID,
        transaction.UserIdentity,
        transaction.Action,
        transaction.Phase,
        dataJSON
    )
    
    返回 err
```
这些伪代码展示了学术出版区块链客户端的核心功能，包括客户端初始化、论文加密提交、获取论文列表以及记录交易等关键操作，适合在论文中展示系统的主要功能和工作流程。

Trae

参考了 1 个上下文

I'll extract the most important functions from both academicPublishingClient.go and academicPublishingClient-old.go files and present them as pseudocode for your paper. Let me first locate and examine these files.

在工作区搜索 'academicPublishingClient.go academicPublishingClient-old.go'

I'll extract the most important functions from both academicPublishingClient.go and academicPublishingClient-old.go files and present them as pseudocode for your paper.

internal\blockchain\academicPublishingClient.go 1 - 200

I'll extract the most important functions from both academicPublishingClient.go and academicPublishingClient-old.go and present them as pseudocode for your paper.

# 从 academicPublishingClient.go 提取的关键函数伪代码
## 1. 初始化区块链客户端
```
算法：NewClientWithConfig
输入：区块链配置信息 config
输出：学术出版区块链客户端实例

函数 NewClientWithConfig(config):
    // 创建客户端实例
    client = 新建 
    AcademicPublishingClient 对象
    client.mspID = config.MSPID
    client.cryptoPath = config.
    CryptoPath
    client.certPath = config.
    CertPath
    client.keyPath = config.KeyPath
    client.tlsCertPath = config.
    TLSCertPath
    client.peerEndpoint = config.
    PeerEndpoint
    client.gatewayPeer = config.
    GatewayPeer
    client.channelName = config.
    ChannelName
    client.chaincodeName = config.
    ChaincodeName
    
    // 初始化连接
    err = client.initialize()
    如果 err 不为空:
        返回 空, err
    
    返回 client, 空
```
## 2. 加密提交论文
```
算法：SubmitPaperWithEncryption
输入：论文对象 paper, 用户ID userID, 发
布阶段 phase
输出：加密后的论文对象

函数 SubmitPaperWithEncryption
(paper, userID, phase):
    // 获取数据策略管理器
    policyManager = 获取数据策略管理器
    ()
    
    // 根据阶段和数据类型加密论文内容
    encryptedContent, metadata, err 
    = policyManager.EncryptData(
        paper.Content的字节数组,
        userID,
        phase的字符串表示,
        "paper_content"
    )
    如果 err 不为空:
        返回 空, "加密论文内容失败"错误
    
    // 创建加密论文对象
    encryptedPaper = 新建 
    EncryptedPaper 对象
    encryptedPaper.PaperID = paper.
    PaperID
    encryptedPaper.Title = paper.
    Title
    encryptedPaper.Abstract = paper.
    Abstract
    encryptedPaper.Content = 
    encryptedContent
    encryptedPaper.ContentHash = 
    paper.ContentHash
    encryptedPaper.AuthorID = paper.
    AuthorID
    encryptedPaper.AuthorIdentity = 
    paper.AuthorIdentity
    encryptedPaper.Status = paper.
    Status
    encryptedPaper.Phase = paper.
    Phase
    encryptedPaper.SubmittedAt = 
    paper.SubmittedAt
    encryptedPaper.UpdatedAt = 
    paper.UpdatedAt
    encryptedPaper.Version = paper.
    Version
    encryptedPaper.Metadata = 
    metadata
    encryptedPaper.Encrypted = true
    encryptedPaper.EncryptionType = 
    policyManager.
    GetEncryptionPolicy(
        userID, 
        phase的字符串表示, 
        "paper_content"
    ).GetPolicyType()
    encryptedPaper.AccessControl = 
    [userID]  // 初始只有作者可以访问
    
    返回 encryptedPaper, 空
```
# 从 academicPublishingClient-old.go 提取的关键函数伪代码
## 1. 创建学术出版客户端
```
算法：NewAcademicPublishingClient
输入：无
输出：学术出版区块链客户端实例

函数 NewAcademicPublishingClient():
    // 创建gRPC连接
    clientConnection = 
    newGrpcConnection()
    
    // 获取身份和签名
    id = newIdentity()
    sign = newSign()
    
    // 创建Gateway连接
    gw, err = client.Connect(
        id,
        client.WithSign(sign),
        client.WithClientConnection
        (clientConnection),
        client.WithEvaluateTimeout(5
        秒),
        client.WithEndorseTimeout(15
        秒),
        client.WithSubmitTimeout(5
        秒),
        client.
        WithCommitStatusTimeout(1分
        钟)
    )
    如果 err 不为空:
        返回 空, "连接gateway失败"错误
    
    // 获取网络和合约
    network = gw.GetNetwork
    (channelName)
    contract = network.GetContract
    (chaincodeName)
    
    // 创建并返回客户端实例
    client = 新建 
    AcademicPublishingClient 对象
    client.contract = contract
    client.gateway = gw
    client.network = network
    
    返回 client, 空
```
## 2. 获取所有论文
```
算法：GetAllPapers
输入：无
输出：论文对象数组

函数 GetAllPapers():
    // 调用链码获取所有论文
    evaluateResult, err = contract.
    EvaluateTransaction
    ("GetAllPapers")
    如果 err 不为空:
        返回 空, err
    
    // 解析返回的JSON数据
    papers = 空的论文对象数组
    err = 将evaluateResult解析为
    papers
    如果 err 不为空:
        // 尝试处理特殊情况，如Metadata
        为null
        rawPapers = 空的map数组
        jsonErr = 将evaluateResult解
        析为rawPapers
        如果 jsonErr 为空:
            // 手动构建论文对象
            对于 rawPapers 中的每个 
            rawPaper:
                paper = 新建 Paper 
                对象
                paper.PaperID = 
                getString(rawPaper, 
                "PaperID")
                paper.Title = 
                getString(rawPaper, 
                "Title")
                paper.Abstract = 
                getString(rawPaper, 
                "Abstract")
                paper.ContentHash = 
                getString(rawPaper, 
                "ContentHash")
                paper.
                AuthorIdentity = 
                getString(rawPaper, 
                "AuthorIdentity")
                paper.Status = 
                getString(rawPaper, 
                "Status")
                paper.Phase = 
                getString(rawPaper, 
                "Phase")
                
                // 处理Metadata
                如果 rawPaper
                ["Metadata"] 不为 
                null:
                    metadataJSON = 
                    将rawPaper
                    ["Metadata"]转换
                    为JSON字符串
                    paper.Metadata 
                    = 解析
                    metadataJSON
                
                将paper添加到papers中
            
            返回 papers, 空
    
    返回 papers, 空
```
## 3. 记录交易
```
算法：RecordTransaction
输入：交易对象 transaction
输出：错误信息

函数 RecordTransaction(transaction):
    // 将交易数据转换为JSON
    dataJSON = 将transaction.Data转
    换为JSON字符串
    
    // 调用链码记录交易
    _, err = contract.
    SubmitTransaction(
        "RecordTransaction",
        transaction.TxID,
        transaction.PaperID,
        transaction.UserIdentity,
        transaction.Action,
        transaction.Phase,
        dataJSON
    )
    
    返回 err
```
这些伪代码展示了学术出版区块链客户端的核心功能，包括客户端初始化、论文加密提交、获取论文列表以及记录交易等关键操作，适合在论文中展示系统的主要功能和工作流程。

lgl21919

复制

删除

分别提取academicPublishing.go和academicPublishing copy.go区块链智能合约代码 中最重要一个或多个函数，以伪代码形式展示在论文中

Trae

我将查找并提取 academicPublishing.go 和 academicPublishing copy.go 智能合约中的关键函数，以伪代码形式展示。

在工作区搜索 'academicPublishing.go academicPublishing copy.go'

I'll extract the most important functions from both academicPublishing.go and academicPublishing copy.go 智能合约代码，并以伪代码形式展示。

# academicPublishing.go 智能合约关键函数伪代码
## 1. 提交论文函数
```
算法：SubmitPaper
输入：交易上下文 ctx, 论文ID paperID, 
标题 title, 摘要 abstract, 内容哈希 
contentHash, 
     作者身份 authorIdentity, 状态 
     status, 阶段 phase, 元数据JSON 
     metadataJSON, 版本 version
输出：错误信息

函数 SubmitPaper(ctx, paperID, 
title, abstract, contentHash, 
authorIdentity, status, phase, 
metadataJSON, version):
    // 检查论文是否已存在
    exists, err = PaperExists(ctx, 
    paperID)
    如果 err 不为空:
        返回 err
    如果 exists 为真:
        返回 "论文已存在"错误
    
    // 解析版本号
    versionInt = 将version转换为整数
    如果 转换失败:
        versionInt = 1  // 默认版本为
        1
    
    // 创建论文对象
    paper = 新建 Paper 对象
    paper.PaperID = paperID
    paper.Title = title
    paper.Abstract = abstract
    paper.ContentHash = contentHash
    paper.AuthorIdentity = 
    authorIdentity
    paper.Status = status
    paper.Phase = phase
    paper.SubmittedAt = 当前时间的
    RFC3339格式
    paper.UpdatedAt = 当前时间的
    RFC3339格式
    paper.Version = versionInt
    
    // 解析元数据
    如果 metadataJSON 不为空:
        metadata = 解析 
        metadataJSON 为map[string]
        string
        如果 解析失败:
            返回 解析错误
        paper.Metadata = metadata
    
    // 将论文保存到状态数据库
    paperJSON = 将paper序列化为JSON
    如果 序列化失败:
        返回 序列化错误
    
    返回 ctx.GetStub().PutState
    (paperID, paperJSON)
```
## 2. 获取所有论文函数
```
算法：GetAllPapers
输入：交易上下文 ctx
输出：论文对象数组, 错误信息

函数 GetAllPapers(ctx):
    // 获取所有状态数据
    resultsIterator = ctx.GetStub().
    GetStateByRange("", "")
    如果 获取失败:
        返回 空, 错误信息
    延迟关闭 resultsIterator
    
    papers = 空的论文对象数组
    
    // 遍历所有状态数据
    当 resultsIterator.HasNext() 为
    真:
        queryResponse = 
        resultsIterator.Next()
        如果 获取失败:
            返回 空, 错误信息
        
        // 尝试将状态数据解析为论文对象
        paper = 新建 Paper 对象
        err = 将 queryResponse.
        Value 解析为 paper
        如果 解析失败:
            继续下一次循环  // 跳过非论
            文数据
        
        // 简单检查是否为论文数据
        如果 paper.PaperID 不为空:
            // 确保Metadata不为nil
            如果 paper.Metadata 为空:
                paper.Metadata = 创
                建空的map[string]
                string
            将 paper 添加到 papers 数
            组
    
    返回 papers, 空
```
# academicPublishing copy.go 智能合约关键函数伪代码
## 1. 发送消息函数
```
算法：SendMessage
输入：交易上下文 ctx, 消息ID 
messageID, 论文ID paperID, 发送者身份 
fromIdentity, 
     接收者身份 toIdentity, 内容 
     content, 消息类型 messageType, 
     阶段 phase
输出：错误信息

函数 SendMessage(ctx, messageID, 
paperID, fromIdentity, toIdentity, 
content, messageType, phase):
    // 验证论文存在
    exists, err = PaperExists(ctx, 
    paperID)
    如果 err 不为空:
        返回 err
    如果 exists 为假:
        返回 "论文不存在"错误
    
    // 创建消息对象
    message = 新建 Message 对象
    message.MessageID = messageID
    message.PaperID = paperID
    message.FromIdentity = 
    fromIdentity
    message.ToIdentity = toIdentity
    message.Content = content
    message.MessageType = 
    messageType
    message.Timestamp = 当前时间的
    RFC3339格式
    message.Phase = phase
    
    // 序列化并存储
    messageJSON = 将message序列化为
    JSON
    如果 序列化失败:
        返回 序列化错误
    
    err = ctx.GetStub().PutState
    (messageID, messageJSON)
    如果 err 不为空:
        返回 "存储消息失败"错误
    
    // 创建复合键用于按论文查询消息
    paperMessageKey = ctx.GetStub().
    CreateCompositeKey
    ("paper~message", [paperID, 
    messageID])
    如果 创建失败:
        返回 "创建复合键失败"错误
    
    返回 ctx.GetStub().PutState
    (paperMessageKey, [0x00])
```
## 2. 获取论文历史记录函数
```
算法：GetPaperHistory
输入：交易上下文 ctx, 论文ID paperID
输出：历史记录数组, 错误信息

函数 GetPaperHistory(ctx, paperID):
    // 获取论文的历史记录
    resultsIterator = ctx.GetStub().
    GetHistoryForKey(paperID)
    如果 获取失败:
        返回 空, 错误信息
    延迟关闭 resultsIterator
    
    history = 空的历史记录数组
    
    // 遍历历史记录
    当 resultsIterator.HasNext() 为
    真:
        queryResponse = 
        resultsIterator.Next()
        如果 获取失败:
            返回 空, 错误信息
        
        // 解析历史记录中的论文数据
        paper = 新建 Paper 对象
        err = 将 queryResponse.
        Value 解析为 paper
        如果 解析失败:
            继续下一次循环
        
        // 创建历史记录条目
        record = 新建 map[string]
        interface{}
        record["txId"] = 
        queryResponse.TxId
        record["timestamp"] = 
        queryResponse.Timestamp
        record["isDelete"] = 
        queryResponse.IsDelete
        record["paper"] = paper
        
        将 record 添加到 history 数组
    
    返回 history, 空
```
这些伪代码展示了学术出版区块链智能合约的核心功能，包括论文提交、获取所有论文、发送消息以及获取论文历史记录等关键操作，适合在论文中展示系统的主要功能和工作流程。