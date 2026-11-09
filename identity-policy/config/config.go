package config

import (
    "os"
    "path/filepath"
    "strings"
    
    "github.com/hyperledger/fabric-sdk-go/pkg/core/config"
    "github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

// SDKConfig 定义SDK配置结构
type SDKConfig struct {
    ConfigPath string
    OrgName    string
    UserName   string
}

// InitializeSDK 初始化Fabric SDK（使用默认配置）
func InitializeSDK(configPath string) (*fabsdk.FabricSDK, error) {
    sdk, err := fabsdk.New(config.FromFile(configPath))
    if err != nil {
        return nil, err
    }
    return sdk, nil
}

// InitializeSDKForOrg 为特定组织初始化Fabric SDK，使用该组织的 credentialStore 路径
func InitializeSDKForOrg(configPath string, orgName string, usersPath string) (*fabsdk.FabricSDK, error) {
    // 读取配置文件
    configBytes, err := os.ReadFile(configPath)
    if err != nil {
        return nil, err
    }
    
    configContent := string(configBytes)
    
    // 获取绝对路径
    absUsersPath, err := filepath.Abs(usersPath)
    if err != nil {
        absUsersPath = usersPath
    }
    // 统一路径分隔符
    absUsersPath = filepath.ToSlash(absUsersPath)
    
    // 替换 credentialStore 路径
    // 查找并替换 credentialStore 的 path
    lines := strings.Split(configContent, "\n")
    inCredentialStore := false
    inCryptoStore := false
    for i, line := range lines {
        trimmed := strings.TrimSpace(line)
        if strings.HasPrefix(trimmed, "credentialStore:") {
            inCredentialStore = true
            inCryptoStore = false
        } else if strings.HasPrefix(trimmed, "cryptoStore:") {
            inCryptoStore = true
        } else if inCredentialStore && strings.HasPrefix(trimmed, "path:") {
            // 替换 credentialStore 的 path
            lines[i] = "    path: " + absUsersPath
            inCredentialStore = false
        } else if inCryptoStore && strings.HasPrefix(trimmed, "path:") {
            // 替换 cryptoStore 的 path
            lines[i] = "      path: " + absUsersPath
            inCryptoStore = false
        } else if trimmed == "" || (!strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "\t")) {
            // 遇到新的顶级键，重置状态
            inCredentialStore = false
            inCryptoStore = false
        }
    }
    
    modifiedConfig := strings.Join(lines, "\n")
    
    // 将修改后的配置写入临时文件
    tempConfigPath := filepath.Join(os.TempDir(), "fabric-config-"+orgName+".yaml")
    if err := os.WriteFile(tempConfigPath, []byte(modifiedConfig), 0644); err != nil {
        return nil, err
    }
    
    // 使用临时配置文件初始化 SDK
    sdk, err := fabsdk.New(config.FromFile(tempConfigPath))
    if err != nil {
        return nil, err
    }
    
    return sdk, nil
}