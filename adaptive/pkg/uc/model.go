// Package uc implements the Universal Composability (UC) layering of the
// adaptive privacy mechanism.
//
// Core ideals (do not instantiate one F per identity×algorithm pair):
//
//	F_nym  — identity (real / π_pseudo / π_anon are candidate realisations)
//	F_SC   — secure messages (π_ECDH→F_KE, π_SSS→F_DKG, π_PRE→F_PRE, then F_SC)
//	ρ_app  — unified application protocol calling only F_nym and F_SC
//
// The four-layer business wrap remains:
//
//	F_adaptive = F_id-strategy ∘ F_id-protect ∘ F_enc-strategy ∘ F_enc
//
// F_id-protect is F_nym; F_enc is F_SC. Strategy maps f_id and f_enc are public.
// Identity keys and encryption keys are independent, so standard UC (not JUC) applies.
// MonitorController observes hot-path IAPP/DAPP events, queries VerificationMap
// (UC IdealSpec ⊕ monitor marks), and on miss triggers FeedbackGovernor /
// UC verify. IdealSpec owns F-port bindings; VerificationMap owns Verified marks.
package uc

import (
	"errors"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/identity"
	"privacy-protection/adaptive/pkg/reasoning"
)

// ErrFailClosedAbort is returned when strategy-input integrity fails.
// Business identity generation and encryption must not run.
var ErrFailClosedAbort = errors.New("strategy-input rejected: abort identity and encryption")

// AdversaryModel is the UC corruption model declared for the proof.
type AdversaryModel string

const (
	StaticCorruption   AdversaryModel = "STATIC"
	AdaptiveCorruption AdversaryModel = "ADAPTIVE_ERASURE"
)

// PublicTrace is the environment Z's view of public strategy I/O.
type PublicTrace struct {
	SID            string             `json:"sid"`
	Phase          string             `json:"phase"`
	Role           string             `json:"role"`
	ReviewMode     string             `json:"review_mode"`
	RequestContent string             `json:"request_content"`
	DataType       string             `json:"data_type"`
	SecurityLevel  int                `json:"security_level"`
	ModeConfig     context.ModeConfig `json:"mode_config"`
	IAPP           string             `json:"iapp"`
	DAPP           string             `json:"dapp"`
	EncSchemeID    string             `json:"enc_scheme_id"`
	FallbackUsed   bool               `json:"fallback_used"`
	IntegrityOK    bool               `json:"integrity_ok"`
}

// AdaptiveRequest is a session call into π_adaptive / F_adaptive.
type AdaptiveRequest struct {
	SID       string
	UserID    string
	Input     context.ContextInput
	Plaintext []byte
	Adversary AdversaryModel
	// OnlineStrategy, when set, pins π to the production hot-path decision
	// (IAPP/DAPP already chosen online). Ideal F ignores this and re-selects
	// the ideal strategy for the same C — CompareRealIdeal then checks
	// online π vs ideal F.
	OnlineStrategy *OnlineStrategy
}

// OnlineStrategy is the IAPP/DAPP (and optional enc detail) emitted by the
// live business path. Closed-loop UC feeds this into π only.
type OnlineStrategy struct {
	IAPP          string
	DAPP          string
	EncAlgorithms []string
	ComposeMode   string
	SecurityLevel int
}

// AdaptiveResponse is the output of one adaptive invocation.
type AdaptiveResponse struct {
	Trace    PublicTrace               `json:"trace"`
	Identity identity.Handle           `json:"identity"`
	Scheme   crypto.Scheme             `json:"scheme"`
	Cipher   crypto.Ciphertext         `json:"cipher"`
	Decision *reasoning.PolicyDecision `json:"decision"`
}

func publicTrace(sid string, in context.ContextInput, dec *reasoning.PolicyDecision, scheme crypto.Scheme) PublicTrace {
	return PublicTrace{
		SID:            sid,
		Phase:          in.Phase,
		Role:           in.Role,
		ReviewMode:     in.ReviewMode,
		RequestContent: in.RequestContent,
		DataType:       in.DataType,
		SecurityLevel:  in.SecurityLevel,
		ModeConfig:     in.ModeConfig,
		IAPP:           dec.IAPPStrategy,
		DAPP:           dec.DAPPStrategy,
		EncSchemeID:    scheme.ID(),
		FallbackUsed:   dec.FallbackUsed,
		IntegrityOK:    dec.IntegrityOK,
	}
}

func schemeFromDecision(dec *reasoning.PolicyDecision) crypto.Scheme {
	algs := append([]string(nil), dec.EncAlgorithms...)
	if len(algs) == 0 && dec.DAPPStrategy != "" {
		algs = []string{dec.DAPPStrategy}
	}
	return crypto.Scheme{
		Token:         dec.DAPPStrategy,
		Algorithms:    algs,
		ComposeMode:   dec.ComposeMode,
		SecurityLevel: dec.SecurityLevel,
	}
}

// decisionFromOnline builds a PolicyDecision from a production-emitted strategy.
// Integrity is assumed already validated by the caller.
func decisionFromOnline(in context.ContextInput, o *OnlineStrategy) *reasoning.PolicyDecision {
	if o == nil {
		return nil
	}
	level := o.SecurityLevel
	if level <= 0 {
		level = in.SecurityLevel
	}
	if level <= 0 && o.DAPP != "" && o.DAPP != reasoning.DAPPPublic {
		level = 1
	}
	algs := append([]string(nil), o.EncAlgorithms...)
	compose := o.ComposeMode
	if len(algs) == 0 || compose == "" {
		da, dc := reasoning.DefaultEncSchemeFor(o.DAPP, level)
		if len(algs) == 0 {
			algs = da
		}
		if compose == "" {
			compose = dc
		}
	}
	state := context.NewContextAwarenessModule().Capture(in)
	return &reasoning.PolicyDecision{
		IAPPStrategy:   o.IAPP,
		DAPPStrategy:   o.DAPP,
		EncAlgorithms:  algs,
		ComposeMode:    compose,
		SecurityLevel:  level,
		SecurityWeight: 0,
		RuleID:         "online_production",
		Description:    "pinned to online business strategy for UC π",
		StateKey:       state.StateKey,
		Vector:         state.Vector,
		IntegrityOK:    true,
	}
}
