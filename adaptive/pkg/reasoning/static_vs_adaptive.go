package reasoning

import "privacy-protection/adaptive/pkg/context"

// Static vs adaptive comparison uses a journal gold spec (predicates), not a rubric.
// Gold is the minimum identity/data strength required by double-blind / open-review
// practice and by the declared security level ℓ. It is not a copy of YAML outputs.

// IdStrength: REAL=0 < PSEUDONYMOUS=1 < ANONYMOUS=2.
func IdStrength(iapp string) int {
	switch iapp {
	case IAPPAnonymous:
		return 2
	case IAPPPseudonym:
		return 1
	default:
		return 0
	}
}

// DataStrength: PUBLIC=0 < ECDH=1 < PRE/SSS=2 < MPC=3.
func DataStrength(dapp string) int {
	switch dapp {
	case DAPPMPC:
		return 3
	case DAPPSSS, DAPPPRE:
		return 2
	case DAPPECDH:
		return 1
	default:
		return 0
	}
}

// GoldMinIdentity: double/single-blind reviewers (and DB authors) must not be REAL.
func GoldMinIdentity(phase, role, mode string) int {
	if phase != "REVIEW" {
		return 0
	}
	switch mode {
	case "DOUBLE_BLIND":
		if role == "AUTHOR" || role == "REVIEWER" {
			return 1
		}
	case "SINGLE_BLIND":
		if role == "REVIEWER" {
			return 1
		}
	}
	return 0
}

// GoldRequireReal: open review identities must be disclosed (accountability).
func GoldRequireReal(phase, role, mode string) bool {
	return phase == "REVIEW" && mode == "OPEN" && (role == "AUTHOR" || role == "REVIEWER")
}

// GoldMinData is the workflow security level ℓ (0–3).
func GoldMinData(level int) int {
	if level < 0 {
		return 0
	}
	if level > 3 {
		return 3
	}
	return level
}

// StaticB1: one-size ECDH and real names at every step (paper baseline B1).
func StaticB1() (iapp, dapp string) {
	return IAPPReal, DAPPECDH
}

// StaticB2: phase-frozen Level-1; no SSS/PRE/MPC (paper baseline B2).
func StaticB2(phase, dataType string) (iapp, dapp string) {
	iapp = IAPPReal
	if phase == "PUBLICATION" && dataType == "MESSAGE" {
		return iapp, DAPPPublic
	}
	return iapp, DAPPECDH
}

// StaticB2SSS freezes REAL+SSS at every step (stronger static crypto baseline).
func StaticB2SSS() (iapp, dapp string) {
	return IAPPReal, DAPPSSS
}

// FitnessCase is one (C, gold) evaluation row.
type FitnessCase struct {
	Phase, Role, Mode, DataType string
	Level                       int
}

// DefaultFitnessCases: 3×3×3 identity grid at ℓ=1 plus the 8-step high-sensitivity data profile.
func DefaultFitnessCases() []FitnessCase {
	var out []FitnessCase
	for _, s := range []string{"SUBMISSION", "REVIEW", "PUBLICATION"} {
		for _, r := range []string{"AUTHOR", "EDITOR", "REVIEWER"} {
			if s == "SUBMISSION" && r == "REVIEWER" {
				continue
			}
			for _, m := range []string{"DOUBLE_BLIND", "SINGLE_BLIND", "OPEN"} {
				out = append(out, FitnessCase{s, r, m, "MANUSCRIPT", 1})
			}
		}
	}
	dataProfile := []FitnessCase{
		{"SUBMISSION", "AUTHOR", "DOUBLE_BLIND", "MANUSCRIPT", 2},
		{"SUBMISSION", "AUTHOR", "DOUBLE_BLIND", "MESSAGE", 2},
		{"REVIEW", "REVIEWER", "DOUBLE_BLIND", "MANUSCRIPT", 2},
		{"REVIEW", "REVIEWER", "DOUBLE_BLIND", "SUPPLEMENTARY_DATA", 2},
		{"REVIEW", "REVIEWER", "DOUBLE_BLIND", "MESSAGE", 2},
		{"REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3},
		{"PUBLICATION", "AUTHOR", "OPEN", "MANUSCRIPT", 2},
		{"PUBLICATION", "EDITOR", "OPEN", "MESSAGE", 0},
	}
	return append(out, dataProfile...)
}

// SchemePick is one baseline or adaptive decision.
type SchemePick struct {
	Name, IAPP, DAPP string
}

// CaseVerdict is objective (binary) violations — no rubric weights.
type CaseVerdict struct {
	UnderID, UnderData, AccountFail bool
	EditorSeesAuthor, KeySinglePoint, NoThreshold bool
}

func Judge(c FitnessCase, p SchemePick) CaseVerdict {
	v := CaseVerdict{}
	if IdStrength(p.IAPP) < GoldMinIdentity(c.Phase, c.Role, c.Mode) {
		v.UnderID = true
	}
	if DataStrength(p.DAPP) < GoldMinData(c.Level) {
		v.UnderData = true
	}
	if GoldRequireReal(c.Phase, c.Role, c.Mode) && p.IAPP != IAPPReal {
		v.AccountFail = true
	}
	if c.Phase == "REVIEW" && c.Mode == "DOUBLE_BLIND" && c.Role == "AUTHOR" && p.IAPP == IAPPReal {
		v.EditorSeesAuthor = true
	}
	if GoldMinData(c.Level) >= 2 && DataStrength(p.DAPP) < 2 {
		v.KeySinglePoint = true
	}
	if GoldMinData(c.Level) >= 3 && DataStrength(p.DAPP) < 3 {
		v.NoThreshold = true
	}
	return v
}

// FitnessReport aggregates rates over a case list.
type FitnessReport struct {
	N                                              int
	UnderID, UnderData, AccountFail                int
	EditorSeesAuthor, KeySinglePoint, NoThreshold int
}

func (r FitnessReport) Rate(n int) float64 {
	if r.N == 0 {
		return 0
	}
	return float64(n) / float64(r.N)
}

func Accumulate(r *FitnessReport, v CaseVerdict) {
	r.N++
	if v.UnderID {
		r.UnderID++
	}
	if v.UnderData {
		r.UnderData++
	}
	if v.AccountFail {
		r.AccountFail++
	}
	if v.EditorSeesAuthor {
		r.EditorSeesAuthor++
	}
	if v.KeySinglePoint {
		r.KeySinglePoint++
	}
	if v.NoThreshold {
		r.NoThreshold++
	}
}

func BindInput(c FitnessCase) context.ContextInput {
	return context.ContextInput{
		SessionID: "fit-" + c.Phase, Phase: c.Phase, Role: c.Role, ReviewMode: c.Mode,
		DataType: c.DataType, SecurityLevel: c.Level,
		RegisteredRole: c.Role, AuthenticatedPhase: c.Phase,
	}
}

func AdaptivePick(coord *AdaptiveCoordinator, c FitnessCase) (SchemePick, error) {
	dec, err := coord.EvaluatePolicy(BindInput(c))
	if err != nil {
		return SchemePick{Name: "Adaptive"}, err
	}
	return SchemePick{Name: "Adaptive", IAPP: dec.IAPPStrategy, DAPP: dec.DAPPStrategy}, nil
}
