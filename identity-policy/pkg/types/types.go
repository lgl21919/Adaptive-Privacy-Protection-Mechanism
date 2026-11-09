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
    ReviewMode         ReviewMode         `json:"reviewMode,omitempty"` // 审稿模式（仅在审稿阶段使用）
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

// ReviewMode 审稿模式枚举
type ReviewMode string

const (
	ReviewModeDoubleBlind ReviewMode = "DOUBLE_BLIND" // 双盲模式：作者和审稿人身份不可见，编辑身份可见
	ReviewModeSingleBlind ReviewMode = "SINGLE_BLIND" // 单盲模式：审稿人身份不可见，作者和编辑身份可见
	ReviewModeOpen        ReviewMode = "OPEN"         // 开放模式：审稿人、作者和编辑身份都可见
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
    UpdatedAt      string            `json:"UpdatedAt"`      // 大写匹配链码
    Metadata       map[string]string `json:"Metadata,omitempty"` // 大写匹配链码，添加omitempty
}