// Package context implements the Context-Awareness Module: captures workflow
// state vector C = (s, m, r, q, d, l, cfg) and semantically encodes discrete
// states for the Logical Reasoning Engine and UC strategy functionalities.
package context

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// State dimensions (discrete tokens used by the rule base).
const (
	DimAny = "*"
)

// ContextVector C = (s, m, r, q, d, l, cfg) — workflow state vector.
//
//   - s: system/submission phase (SUBMISSION, REVIEW, PUBLICATION)
//   - m: member role (AUTHOR, EDITOR, REVIEWER)
//   - r: review context (DOUBLE_BLIND, SINGLE_BLIND, OPEN)
//   - q: request content type (SUBMIT, REVIEW_REPORT, QUERY, PUBLISH, …)
//   - d: data type (MANUSCRIPT, MESSAGE, …)
//   - l: security level (0–3)
//   - cfg: mode-config digest (public journal parameters)
type ContextVector struct {
	S   string `json:"s" yaml:"s"`
	M   string `json:"m" yaml:"m"`
	R   string `json:"r" yaml:"r"`
	Q   string `json:"q" yaml:"q"`
	D   string `json:"d" yaml:"d"`
	L   string `json:"l" yaml:"l"`
	Cfg string `json:"cfg,omitempty" yaml:"cfg,omitempty"`
}

// SemanticState is the standardized encoding of C for rule matching.
type SemanticState struct {
	Vector   ContextVector     `json:"vector"`
	Tokens   map[string]string `json:"tokens"`
	StateKey string            `json:"state_key"`
}

// ModeConfig is the public journal/session configuration that may raise
// (never lower) the protection floor. The strategy function is public;
// confidentiality of cfg is not required.
type ModeConfig struct {
	ForceAnonymous   bool `json:"force_anonymous" yaml:"force_anonymous"`
	MinSecurityLevel int  `json:"min_security_level" yaml:"min_security_level"`
	AllowComposition bool `json:"allow_composition" yaml:"allow_composition"`
	RequireSTE       bool `json:"require_ste" yaml:"require_ste"`
}

// ContextInput raw workflow inputs before semantic normalization.
type ContextInput struct {
	SessionID      string
	Phase          string
	Role           string
	ReviewMode     string
	RequestContent string
	DataType       string
	SecurityLevel  int
	ModeConfig     ModeConfig
	// AuthenticatedPhase is the phase maintained by the publication
	// state machine (system-internal). If set, claimed Phase must match.
	AuthenticatedPhase string
	// RegisteredRole is the role bound to the caller's credential.
	RegisteredRole string
	// IntegrityKey optionally authenticates strategy inputs (HMAC).
	IntegrityKey []byte
	IntegrityMAC string
}

// ContextAwarenessModule captures and semantically encodes workflow context.
type ContextAwarenessModule struct{}

func NewContextAwarenessModule() *ContextAwarenessModule {
	return &ContextAwarenessModule{}
}

// Capture assembles C from raw workflow inputs and returns a semantic state.
func (cam *ContextAwarenessModule) Capture(in ContextInput) *SemanticState {
	vec := ContextVector{
		S:   normalizeToken(in.Phase),
		M:   normalizeToken(in.Role),
		R:   normalizeReviewMode(in.Phase, in.ReviewMode),
		Q:   normalizeRequest(in.RequestContent),
		D:   normalizeDataType(in.DataType),
		L:   normalizeLevel(in.SecurityLevel),
		Cfg: digestModeConfig(in.ModeConfig),
	}

	tokens := map[string]string{
		"s":   vec.S,
		"m":   vec.M,
		"r":   vec.R,
		"q":   vec.Q,
		"d":   vec.D,
		"l":   vec.L,
		"cfg": vec.Cfg,
	}
	return &SemanticState{
		Vector:   vec,
		Tokens:   tokens,
		StateKey: hashStateKey(vec),
	}
}

// ValidPhases / roles / review modes used by F-strategy input validation.
var (
	ValidPhases      = map[string]bool{"SUBMISSION": true, "REVIEW": true, "PUBLICATION": true}
	ValidRoles       = map[string]bool{"AUTHOR": true, "EDITOR": true, "REVIEWER": true}
	ValidReviewModes = map[string]bool{"DOUBLE_BLIND": true, "SINGLE_BLIND": true, "OPEN": true}
	PhaseOrder       = map[string]int{"SUBMISSION": 1, "REVIEW": 2, "PUBLICATION": 3}
)

// ValidateStrategyInput checks well-formedness and integrity of strategy
// metadata. Tampered phase/role fail closed (caller applies safest fallback).
func ValidateStrategyInput(in ContextInput) error {
	phase := normalizeToken(in.Phase)
	if phase != DimAny && !ValidPhases[phase] {
		return fmt.Errorf("invalid phase: %s", in.Phase)
	}
	role := normalizeToken(in.Role)
	if role != DimAny && role != "" && !ValidRoles[role] {
		return fmt.Errorf("invalid role: %s", in.Role)
	}
	if phase == "REVIEW" {
		rm := normalizeToken(in.ReviewMode)
		if rm != DimAny && rm != "" && !ValidReviewModes[rm] {
			return fmt.Errorf("invalid review mode: %s", in.ReviewMode)
		}
	}
	if in.AuthenticatedPhase != "" {
		auth := normalizeToken(in.AuthenticatedPhase)
		if auth != phase {
			return fmt.Errorf("phase tamper: claimed %s authenticated %s", phase, auth)
		}
	}
	if in.RegisteredRole != "" && role != DimAny && role != "" {
		if normalizeToken(in.RegisteredRole) != role {
			return fmt.Errorf("role tamper: claimed %s registered %s", role, in.RegisteredRole)
		}
	}
	if len(in.IntegrityKey) > 0 {
		expect := MACStrategyInput(in.IntegrityKey, in)
		if in.IntegrityMAC == "" || !hmac.Equal([]byte(expect), []byte(in.IntegrityMAC)) {
			return fmt.Errorf("strategy-input MAC verification failed")
		}
	}
	return nil
}

// MACStrategyInput authenticates the public strategy inputs (not secrets).
func MACStrategyInput(key []byte, in ContextInput) string {
	mac := hmac.New(sha256.New, key)
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d",
		in.SessionID, in.Phase, in.Role, in.ReviewMode, in.RequestContent, in.DataType, in.SecurityLevel)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func normalizeToken(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return DimAny
	}
	return strings.ToUpper(v)
}

func normalizeDataType(v string) string {
	v = normalizeToken(v)
	if v == "" || v == DimAny {
		return DimAny
	}
	if v == "PAPER" {
		return "MANUSCRIPT"
	}
	return v
}

func normalizeReviewMode(phase, reviewMode string) string {
	if normalizeToken(phase) != "REVIEW" {
		return DimAny
	}
	rm := normalizeToken(reviewMode)
	if rm == "" || rm == DimAny {
		return "DOUBLE_BLIND"
	}
	return rm
}

func normalizeLevel(level int) string {
	if level < 0 {
		return DimAny
	}
	return strconv.Itoa(level)
}

func normalizeRequest(v string) string {
	v = normalizeToken(v)
	if v == "" {
		return DimAny
	}
	return v
}

func digestModeConfig(cfg ModeConfig) string {
	raw := fmt.Sprintf("fa=%t|min=%d|comp=%t|ste=%t",
		cfg.ForceAnonymous, cfg.MinSecurityLevel, cfg.AllowComposition, cfg.RequireSTE)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:4])
}

func hashStateKey(vec ContextVector) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", vec.S, vec.M, vec.R, vec.Q, vec.D, vec.L, vec.Cfg)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}
