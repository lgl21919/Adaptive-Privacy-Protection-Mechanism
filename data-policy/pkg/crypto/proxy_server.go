package crypto

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// ProxyServer 代理重加密服务器
type ProxyServer struct {
	pre    *ProxyReEncryption
	mu     sync.RWMutex
	config *ServerConfig
	// 请求日志
	requestLog []RequestLog
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port           string        // 服务端口
	MaxRequests    int           // 最大并发请求数
	RequestTimeout time.Duration // 请求超时时间
	LogRequests    bool          // 是否记录请求日志
}

// RequestLog 请求日志
type RequestLog struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	FromID    string    `json:"from_id"`
	ToID      string    `json:"to_id"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// ReEncryptRequest 重加密请求
type ReEncryptRequest struct {
	Ciphertext *Ciphertext `json:"ciphertext"`
	FromID     string      `json:"from_id"`
	ToID       string      `json:"to_id"`
}

// ReEncryptResponse 重加密响应
type ReEncryptResponse struct {
	Success           bool                   `json:"success"`
	ReEncryptedCt     *ReEncryptedCiphertext `json:"re_encrypted_ciphertext,omitempty"`
	Error             string                 `json:"error,omitempty"`
	ProcessingTime    time.Duration          `json:"processing_time"`
}

// KeyGenerationRequest 密钥生成请求
type KeyGenerationRequest struct {
	UserID string `json:"user_id"`
}

// KeyGenerationResponse 密钥生成响应
type KeyGenerationResponse struct {
	Success    bool   `json:"success"`
	PublicKeyX string `json:"public_key_x,omitempty"`
	PublicKeyY string `json:"public_key_y,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ReKeyGenerationRequest 重加密密钥生成请求
type ReKeyGenerationRequest struct {
	FromID     string        `json:"from_id"`
	ToID       string        `json:"to_id"`
	Expiration time.Duration `json:"expiration"`
}

// ReKeyGenerationResponse 重加密密钥生成响应
type ReKeyGenerationResponse struct {
	Success bool   `json:"success"`
	KeyID   string `json:"key_id,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ReEncryptionPolicy 重加密策略
type ReEncryptionPolicy struct {
	// 策略ID
	PolicyID string
	// 源用户ID
	FromID string
	// 目标用户ID
	ToID string
	// 策略创建时间
	CreatedAt time.Time
	// 策略过期时间
	ExpiresAt time.Time
	// 是否启用
	Enabled bool
	// 使用次数限制
	MaxUsage int
	// 当前使用次数
	CurrentUsage int
}

// ServerStats 服务器统计信息
type ServerStats struct {
	// 总重加密次数
	TotalReEncryptions int64
	// 成功重加密次数
	SuccessfulReEncryptions int64
	// 失败重加密次数
	FailedReEncryptions int64
	// 策略违规次数
	PolicyViolations int64
	// 服务器启动时间
	StartTime time.Time
	// 最后活动时间
	LastActivity time.Time
}

// NewProxyServer 创建新的代理服务器
func NewProxyServer(pre *ProxyReEncryption, config *ServerConfig) *ProxyServer {
	if config == nil {
		config = &ServerConfig{
			Port:           ":8080",
			MaxRequests:    100,
			RequestTimeout: 30 * time.Second,
			LogRequests:    true,
		}
	}

	return &ProxyServer{
		pre:        pre,
		config:     config,
		requestLog: make([]RequestLog, 0),
	}
}

// SetupRoutes 设置路由并返回HTTP处理器
func (ps *ProxyServer) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// 注册路由
	mux.HandleFunc("/api/v1/reencrypt", ps.handleReEncrypt)
	mux.HandleFunc("/api/v1/keygen", ps.handleKeyGeneration)
	mux.HandleFunc("/api/v1/rekeygen", ps.handleReKeyGeneration)
	mux.HandleFunc("/api/v1/status", ps.handleStatus)
	mux.HandleFunc("/api/v1/logs", ps.handleLogs)

	// 添加中间件
	handler := ps.loggingMiddleware(ps.timeoutMiddleware(mux))
	return handler
}

// Start 启动代理服务器
func (ps *ProxyServer) Start() error {
	handler := ps.SetupRoutes()
	log.Printf("代理重加密服务器启动在端口 %s", ps.config.Port)
	return http.ListenAndServe(ps.config.Port, handler)
}

// handleReEncrypt 处理重加密请求
func (ps *ProxyServer) handleReEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()
	var req ReEncryptRequest
	var resp ReEncryptResponse

	// 解析请求
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp = ReEncryptResponse{
			Success:        false,
			Error:          fmt.Sprintf("解析请求失败: %v", err),
			ProcessingTime: time.Since(start),
		}
		ps.logRequest("reencrypt", req.FromID, req.ToID, false, resp.Error)
		ps.sendResponse(w, resp)
		return
	}

	// 获取重加密密钥
	reKey, err := ps.pre.GetReEncryptionKey(req.FromID, req.ToID)
	if err != nil {
		resp = ReEncryptResponse{
			Success:        false,
			Error:          fmt.Sprintf("获取重加密密钥失败: %v", err),
			ProcessingTime: time.Since(start),
		}
		ps.logRequest("reencrypt", req.FromID, req.ToID, false, resp.Error)
		ps.sendResponse(w, resp)
		return
	}

	// 执行重加密
	reEncryptedCt, err := ps.pre.ReEncrypt(req.Ciphertext, reKey)
	if err != nil {
		resp = ReEncryptResponse{
			Success:        false,
			Error:          fmt.Sprintf("重加密失败: %v", err),
			ProcessingTime: time.Since(start),
		}
		ps.logRequest("reencrypt", req.FromID, req.ToID, false, resp.Error)
		ps.sendResponse(w, resp)
		return
	}

	resp = ReEncryptResponse{
		Success:        true,
		ReEncryptedCt:  reEncryptedCt,
		ProcessingTime: time.Since(start),
	}

	ps.logRequest("reencrypt", req.FromID, req.ToID, true, "")
	ps.sendResponse(w, resp)
}

// handleKeyGeneration 处理密钥生成请求
func (ps *ProxyServer) handleKeyGeneration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
		return
	}

	var req KeyGenerationRequest
	var resp KeyGenerationResponse

	// 解析请求
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp = KeyGenerationResponse{
			Success: false,
			Error:   fmt.Sprintf("解析请求失败: %v", err),
		}
		ps.logRequest("keygen", req.UserID, "", false, resp.Error)
		ps.sendResponse(w, resp)
		return
	}

	// 生成密钥对
	_, publicKey, err := ps.pre.GenerateKeyPair(req.UserID)
	if err != nil {
		resp = KeyGenerationResponse{
			Success: false,
			Error:   fmt.Sprintf("生成密钥对失败: %v", err),
		}
		ps.logRequest("keygen", req.UserID, "", false, resp.Error)
		ps.sendResponse(w, resp)
		return
	}

	resp = KeyGenerationResponse{
		Success:    true,
		PublicKeyX: publicKey.X.String(),
		PublicKeyY: publicKey.Y.String(),
	}

	ps.logRequest("keygen", req.UserID, "", true, "")
	ps.sendResponse(w, resp)
}

// handleReKeyGeneration 处理重加密密钥生成请求
func (ps *ProxyServer) handleReKeyGeneration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
		return
	}

	var req ReKeyGenerationRequest
	var resp ReKeyGenerationResponse

	// 解析请求
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp = ReKeyGenerationResponse{
			Success: false,
			Error:   fmt.Sprintf("解析请求失败: %v", err),
		}
		ps.logRequest("rekeygen", req.FromID, req.ToID, false, resp.Error)
		ps.sendResponse(w, resp)
		return
	}

	// 生成重加密密钥（无需使用返回值，避免未使用变量）
	_, err := ps.pre.GenerateReEncryptionKey(req.FromID, req.ToID, req.Expiration)
	if err != nil {
		resp = ReKeyGenerationResponse{
			Success: false,
			Error:   fmt.Sprintf("生成重加密密钥失败: %v", err),
		}
		ps.logRequest("rekeygen", req.FromID, req.ToID, false, resp.Error)
		ps.sendResponse(w, resp)
		return
	}

	keyID := fmt.Sprintf("%s->%s", req.FromID, req.ToID)
	resp = ReKeyGenerationResponse{
		Success: true,
		KeyID:   keyID,
	}

	ps.logRequest("rekeygen", req.FromID, req.ToID, true, "")
	ps.sendResponse(w, resp)
}

// handleStatus 处理状态查询请求
func (ps *ProxyServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只支持GET方法", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"status":      "running",
		"timestamp":   time.Now(),
		"requests":    len(ps.requestLog),
		"config":      ps.config,
	}

	ps.sendResponse(w, status)
}

// handleLogs 处理日志查询请求
func (ps *ProxyServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只支持GET方法", http.StatusMethodNotAllowed)
		return
	}

	ps.mu.RLock()
	logs := make([]RequestLog, len(ps.requestLog))
	copy(logs, ps.requestLog)
	ps.mu.RUnlock()

	response := map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	}

	ps.sendResponse(w, response)
}

// logRequest 记录请求日志
func (ps *ProxyServer) logRequest(operation, fromID, toID string, success bool, errorMsg string) {
	if !ps.config.LogRequests {
		return
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	logEntry := RequestLog{
		Timestamp: time.Now(),
		Operation: operation,
		FromID:    fromID,
		ToID:      toID,
		Success:   success,
		Error:     errorMsg,
	}

	ps.requestLog = append(ps.requestLog, logEntry)

	// 限制日志数量，保留最近的1000条
	if len(ps.requestLog) > 1000 {
		ps.requestLog = ps.requestLog[len(ps.requestLog)-1000:]
	}
}

// sendResponse 发送响应
func (ps *ProxyServer) sendResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("发送响应失败: %v", err)
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
	}
}

// loggingMiddleware 日志中间件
func (ps *ProxyServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// timeoutMiddleware 超时中间件
func (ps *ProxyServer) timeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, ps.config.RequestTimeout, "请求超时")
}

// GetStats 获取服务器统计信息
func (ps *ProxyServer) GetStats() map[string]interface{} {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	successCount := 0
	errorCount := 0
	operationCounts := make(map[string]int)

	for _, log := range ps.requestLog {
		if log.Success {
			successCount++
		} else {
			errorCount++
		}
		operationCounts[log.Operation]++
	}

	return map[string]interface{}{
		"total_requests":    len(ps.requestLog),
		"success_requests":  successCount,
		"error_requests":    errorCount,
		"operation_counts":  operationCounts,
		"server_start_time": time.Now(), // 这里应该记录实际的启动时间
	}
}