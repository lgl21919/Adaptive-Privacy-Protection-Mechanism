package main

import (
    "academic-publishing/config"
    "academic-publishing/user"
    "fmt"
    "log"
    
    "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
)

func main() {
    // 配置文件路径
    configPath := "./config/config.yaml"
    orgName := "Org1" // 可以选择 "Org1" 或 "Org2"
    usersPath := "../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users"
    caCertPath := "../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem"
    caCertFile := "localhost-7054-ca-org1.pem"
    
    // 初始化SDK
    sdk, err := config.InitializeSDK(configPath)
    if err != nil {
        log.Fatalf("Failed to initialize SDK: %v", err)
    }
    defer sdk.Close()
    
    // 创建用户管理器
    FabricCAClient, err := user.NewFabricCAClient(sdk, orgName, usersPath, caCertPath, caCertFile)
    if err != nil {
        log.Fatalf("Failed to create user manager: %v", err)
    }
    
    // 示例：注册和登记用户
    username := "testuser11"
    userType := "client"
    
    // 定义用户属性
    attributes := []msp.Attribute{
        {
            Name:  "role",
            Value: "user",
            ECert: true,
        },
        {
            Name:  "department",
            Value: "IT",
            ECert: true,
        },
    }
    
    // 1. 注册用户
    fmt.Println("=== 注册用户到test-network ===")
    enrollmentSecret, err := FabricCAClient.RegisterUser(username, userType, attributes)
    if err != nil {
        log.Printf("Failed to register user: %v", err)
        return
    }
    
    // 2. 登记用户
    fmt.Println("=== 登记用户 ===")
    err = FabricCAClient.EnrollUser(username, enrollmentSecret)
    if err != nil {
        log.Printf("Failed to enroll user: %v", err)
        return
    }
    
    // 3. 获取用户签名身份
    fmt.Println("=== 获取用户签名身份 ===")
    signingIdentity, err := FabricCAClient.GetSigningIdentity(username)
    if err != nil {
        log.Printf("Failed to get signing identity: %v", err)
        return
    }
    
    fmt.Printf("User %s signing identity obtained successfully from test-network\n", signingIdentity.Identifier().ID)
    
    fmt.Println("成功连接到test-network并完成用户管理操作！")
}