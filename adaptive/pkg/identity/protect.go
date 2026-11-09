// Package identity implements F_id-protect(mode): real / pseudonymous / anonymous
// handles. Pseudonyms are PRF-derived (linkable within a phase/mode, unlinkable
// across phases). Anonymous handles are fresh random credentials (unlinkable).
package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	ModeReal      = "REAL_IDENTITY"
	ModePseudonym = "PSEUDONYMOUS"
	ModeAnonymous = "ANONYMOUS"
)

// Handle is the externally visible identity token.
type Handle struct {
	Mode      string `json:"mode"`
	Value     string `json:"value"`
	LinkScope string `json:"link_scope,omitempty"`
}

// Protector is the real-world realization of F_id-protect.
type Protector struct {
	master []byte
}

func NewProtector(master []byte) *Protector {
	if len(master) == 0 {
		master = make([]byte, 32)
		_, _ = rand.Read(master)
	}
	out := make([]byte, len(master))
	copy(out, master)
	return &Protector{master: out}
}

// Protect issues a handle for (uid, session, phase, mode, role).
func (p *Protector) Protect(mode, uid, session, phase, reviewMode, role string) Handle {
	switch mode {
	case ModeReal:
		return Handle{Mode: ModeReal, Value: p.realID(uid), LinkScope: "global"}
	case ModePseudonym:
		scope := fmt.Sprintf("%s|%s|%s", phase, reviewMode, role)
		return Handle{Mode: ModePseudonym, Value: p.pseudonym(uid, session, scope), LinkScope: scope}
	default:
		return Handle{Mode: ModeAnonymous, Value: p.anonymous(), LinkScope: ""}
	}
}

func (p *Protector) realID(uid string) string {
	mac := hmac.New(sha256.New, p.master)
	mac.Write([]byte("real|" + uid))
	return "user_" + hex.EncodeToString(mac.Sum(nil)[:12])
}

func (p *Protector) pseudonym(uid, session, scope string) string {
	mac := hmac.New(sha256.New, p.master)
	mac.Write([]byte("pseudo|" + uid + "|" + session + "|" + scope))
	return "pseudo_" + hex.EncodeToString(mac.Sum(nil)[:10])
}

func (p *Protector) anonymous() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	sum := sha256.Sum256(buf)
	return "anon_" + hex.EncodeToString(sum[:8])
}

// SimulatedAnonymous issues a dummy credential used by the UC simulator S.
func SimulatedAnonymous() Handle {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	sum := sha256.Sum256(append([]byte("sim|"), buf...))
	return Handle{Mode: ModeAnonymous, Value: "anon_" + hex.EncodeToString(sum[:8])}
}
