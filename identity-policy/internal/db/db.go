package db

import (
    "database/sql"
    //"fmt"
    "log"
    "sync"
    
    _ "github.com/mattn/go-sqlite3"
)

var (
    instance *sql.DB
    once     sync.Once
)

// InitDB 初始化数据库连接和表结构
func InitDB(dbPath string) (*sql.DB, error) {
    var err error
    
    once.Do(func() {
        instance, err = sql.Open("sqlite3", dbPath)
        if err != nil {
            log.Printf("数据库连接失败: %v", err)
            return
        }
        
        // 创建用户表（如果不存在）
        _, err = instance.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT,
            off_chain_id TEXT,
            on_chain_identity TEXT,
            pseudonym_base TEXT,
            phase_pseudonym TEXT,
            role TEXT,
            phase TEXT DEFAULT 'SUBMISSION',
            review_mode TEXT,
            attributes TEXT,
            PRIMARY KEY (off_chain_id, phase, review_mode)
        )`)
        
        if err != nil {
            log.Printf("创建用户表失败: %v", err)
            return
        }
        
        // 如果表已存在，尝试添加新字段（兼容旧数据库，忽略错误）
        instance.Exec("ALTER TABLE users ADD COLUMN phase_pseudonym TEXT")
        instance.Exec("ALTER TABLE users ADD COLUMN review_mode TEXT")
        
        // 创建论文表
        _, err = instance.Exec(`
        CREATE TABLE IF NOT EXISTS papers (
            paper_id TEXT PRIMARY KEY,
            title TEXT,
            abstract TEXT,
            content_hash TEXT,
            author_identity TEXT,
            status TEXT,
            phase TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`)
        
        if err != nil {
            log.Printf("创建论文表失败: %v", err)
            return
        }
    })
    
    return instance, err
}

// GetDB 获取数据库连接实例
func GetDB() (*sql.DB, error) {
    if instance == nil {
        return InitDB("./academic_publishing.db")
    }
    return instance, nil
}

// CloseDB 关闭数据库连接
func CloseDB() {
    if instance != nil {
        instance.Close()
        instance = nil
    }
}