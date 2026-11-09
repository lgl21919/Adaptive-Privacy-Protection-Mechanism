package db
import (
    "encoding/json"
    "fmt"
)
// UserIdentityInfo 用户身份信息结构体
type UserIdentityInfo struct {
    Username        string
    OffChainID      string
    OnChainIdentity string
    PseudonymBase   string
    PhasePseudonym  string // 阶段特定伪名（根据策略生成）
    Role            string
    Phase           string // 添加阶段信息
    ReviewMode      string // 审稿模式（仅在审稿阶段使用）
    Attributes      map[string]string
}

// SaveUser 保存用户身份信息到数据库 (保持向后兼容)
func SaveUser(user UserIdentityInfo) error {
    // 如果没有指定阶段，默认为投稿阶段
    if user.Phase == "" {
        user.Phase = "SUBMISSION"
    }
    return SavePhaseUser(user)
}

// SavePhaseUser 保存特定阶段的用户身份信息到数据库
func SavePhaseUser(user UserIdentityInfo) error {
    db, err := GetDB()
    if err != nil {
        return err
    }
    
    // 将属性转换为JSON字符串
    attributesJSON, err := json.Marshal(user.Attributes)
    if err != nil {
        return err
    }
    
    _, err = db.Exec(
        "INSERT OR REPLACE INTO users (username, off_chain_id, on_chain_identity, pseudonym_base, phase_pseudonym, role, phase, review_mode, attributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        user.Username, user.OffChainID, user.OnChainIdentity, user.PseudonymBase, user.PhasePseudonym, user.Role, user.Phase, user.ReviewMode, string(attributesJSON),
    )
    return err
}

// GetUserByOffChainID 通过链下ID获取用户信息 (保持向后兼容)
func GetUserByOffChainID(offChainID string) (*UserIdentityInfo, error) {
    return GetPhaseUserByOffChainID(offChainID, "SUBMISSION")
}

// GetPhaseUserByOffChainID 通过链下ID和阶段获取用户信息
func GetPhaseUserByOffChainID(offChainID string, phase string) (*UserIdentityInfo, error) {
    db, err := GetDB()
    if err != nil {
        return nil, err
    }
    
    var user UserIdentityInfo
    var attributesJSON string
    
    err = db.QueryRow(
        "SELECT username, off_chain_id, on_chain_identity, pseudonym_base, phase_pseudonym, role, phase, review_mode, attributes FROM users WHERE off_chain_id = ? AND phase = ?",
        offChainID, phase,
    ).Scan(&user.Username, &user.OffChainID, &user.OnChainIdentity, &user.PseudonymBase, &user.PhasePseudonym, &user.Role, &user.Phase, &user.ReviewMode, &attributesJSON)
    
    if err != nil {
        return nil, fmt.Errorf("查询用户失败: %w", err)
    }
    
    // 解析JSON属性
    user.Attributes = make(map[string]string)
    err = json.Unmarshal([]byte(attributesJSON), &user.Attributes)
    if err != nil {
        return nil, fmt.Errorf("解析用户属性失败: %w", err)
    }
    
    return &user, nil
}

// GetUserByOnChainID 通过链上ID获取用户信息 (保持向后兼容)
func GetUserByOnChainID(onChainID string) (*UserIdentityInfo, error) {
    return GetPhaseUserByOnChainID(onChainID, "SUBMISSION")
}

// GetPhaseUserByOnChainID 通过链上ID和阶段获取用户信息
func GetPhaseUserByOnChainID(onChainID string, phase string) (*UserIdentityInfo, error) {
    db, err := GetDB()
    if err != nil {
        return nil, err
    }
    
    var user UserIdentityInfo
    var attributesJSON string
    
    err = db.QueryRow(
        "SELECT username, off_chain_id, on_chain_identity, pseudonym_base, phase_pseudonym, role, phase, review_mode, attributes FROM users WHERE on_chain_identity = ? AND phase = ?",
        onChainID, phase,
    ).Scan(&user.Username, &user.OffChainID, &user.OnChainIdentity, &user.PseudonymBase, &user.PhasePseudonym, &user.Role, &user.Phase, &user.ReviewMode, &attributesJSON)
    
    if err != nil {
        return nil, fmt.Errorf("查询用户失败: %w", err)
    }
    
    // 解析JSON属性
    user.Attributes = make(map[string]string)
    err = json.Unmarshal([]byte(attributesJSON), &user.Attributes)
    if err != nil {
        return nil, fmt.Errorf("解析用户属性失败: %w", err)
    }
    
    return &user, nil
}

// GetAllUsers 获取所有用户
func GetAllUsers() ([]UserIdentityInfo, error) {
    db, err := GetDB()
    if err != nil {
        return nil, err
    }
    
    rows, err := db.Query("SELECT username, off_chain_id, on_chain_identity, pseudonym_base, phase_pseudonym, role, phase, review_mode, attributes FROM users")
    if err != nil {
        return nil, fmt.Errorf("查询所有用户失败: %w", err)
    }
    defer rows.Close()
    
    var users []UserIdentityInfo
    for rows.Next() {
        var user UserIdentityInfo
        var attributesJSON string
        
        err := rows.Scan(&user.Username, &user.OffChainID, &user.OnChainIdentity, &user.PseudonymBase, &user.PhasePseudonym, &user.Role, &user.Phase, &user.ReviewMode, &attributesJSON)
        if err != nil {
            return nil, fmt.Errorf("读取用户数据失败: %w", err)
        }
        
        // 解析JSON属性
        user.Attributes = make(map[string]string)
        err = json.Unmarshal([]byte(attributesJSON), &user.Attributes)
        if err != nil {
            return nil, fmt.Errorf("解析用户属性失败: %w", err)
        }
        
        users = append(users, user)
    }
    
    return users, nil
}

// GetUsersByPhase 获取特定阶段的所有用户
func GetUsersByPhase(phase string) ([]UserIdentityInfo, error) {
    db, err := GetDB()
    if err != nil {
        return nil, err
    }
    
    rows, err := db.Query("SELECT username, off_chain_id, on_chain_identity, pseudonym_base, phase_pseudonym, role, phase, review_mode, attributes FROM users WHERE phase = ?", phase)
    if err != nil {
        return nil, fmt.Errorf("查询阶段用户失败: %w", err)
    }
    defer rows.Close()
    
    var users []UserIdentityInfo
    for rows.Next() {
        var user UserIdentityInfo
        var attributesJSON string
        
        err := rows.Scan(&user.Username, &user.OffChainID, &user.OnChainIdentity, &user.PseudonymBase, &user.PhasePseudonym, &user.Role, &user.Phase, &user.ReviewMode, &attributesJSON)
        if err != nil {
            return nil, fmt.Errorf("读取用户数据失败: %w", err)
        }
        
        // 解析JSON属性
        user.Attributes = make(map[string]string)
        err = json.Unmarshal([]byte(attributesJSON), &user.Attributes)
        if err != nil {
            return nil, fmt.Errorf("解析用户属性失败: %w", err)
        }
        
        users = append(users, user)
    }
    
    return users, nil
}
// DebugPrintAllUsers 打印所有用户记录，用于调试
func DebugPrintAllUsers() error {
    db, err := GetDB()
    if err != nil {
        return err
    }
    
    // 查询所有用户记录
    rows, err := db.Query("SELECT username, off_chain_id, on_chain_identity, pseudonym_base, phase_pseudonym, role, phase, review_mode, attributes FROM users")
    if err != nil {
        return fmt.Errorf("查询所有用户失败: %w", err)
    }
    defer rows.Close()
    
    fmt.Println("\n=== 所有用户记录 ===")
    recordCount := 0
    for rows.Next() {
        recordCount++
        var username, offChainID, onChainIdentity, pseudonymBase, phasePseudonym, role, phase, reviewMode, attributesJSON string
        
        err := rows.Scan(&username, &offChainID, &onChainIdentity, &pseudonymBase, &phasePseudonym, &role, &phase, &reviewMode, &attributesJSON)
        if err != nil {
            return fmt.Errorf("读取用户数据失败: %w", err)
        }
        
        fmt.Printf("记录 %d:\n", recordCount)
        fmt.Printf("  用户名: %s\n", username)
        fmt.Printf("  链下ID: %s\n", offChainID)
        fmt.Printf("  链上身份: %s\n", onChainIdentity)
        fmt.Printf("  伪名基础: %s\n", pseudonymBase)
        fmt.Printf("  阶段伪名: %s\n", phasePseudonym)
        fmt.Printf("  角色: %s\n", role)
        fmt.Printf("  阶段: %s\n", phase)
        fmt.Printf("  审稿模式: %s\n", reviewMode)
        fmt.Printf("  属性: %s\n", attributesJSON)
        fmt.Println()
    }
    
    if recordCount == 0 {
        fmt.Println("数据库中没有用户记录!")
    } else {
        fmt.Printf("共找到 %d 条用户记录\n", recordCount)
    }
    
    return nil
}