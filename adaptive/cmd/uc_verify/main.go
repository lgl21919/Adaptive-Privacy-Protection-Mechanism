package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"privacy-protection/adaptive/pkg/context"
	"privacy-protection/adaptive/pkg/uc"
)

func main() {
	outDir := flag.String("out", "./benchmark_output", "output directory")
	trials := flag.Int("trials", 64, "trials per randomized experiment")
	auditMode := flag.String("audit", "golden", "UC sampling wiring: golden (π=production coordinator, F=DefaultRuleSet) | synced")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	pair, err := uc.NewAuditPair(uc.AuditMode(*auditMode))
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit pair: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("audit mode=%s coord_path=%q (empty=DefaultRuleSet)\n", pair.Mode, pair.CoordPath)

	rep, snap, err := uc.RunVerificationWithSnapshot(*trials)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		os.Exit(1)
	}

	js, _ := json.MarshalIndent(rep, "", "  ")
	jsonPath := filepath.Join(*outDir, "uc_verification_report.json")
	if err := os.WriteFile(jsonPath, js, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write json: %v\n", err)
		os.Exit(1)
	}
	texPath := filepath.Join(*outDir, "uc_verification_table.tex")
	if err := os.WriteFile(texPath, []byte(latexTable(rep)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write tex: %v\n", err)
		os.Exit(1)
	}
	snapOut := snap
	snapOut.Report = nil
	snapJS, _ := json.MarshalIndent(snapOut, "", "  ")
	snapPath := filepath.Join(*outDir, "uc_pillar_snapshot.json")
	if err := os.WriteFile(snapPath, snapJS, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write snapshot: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("UC adaptive verification: %d/%d passed (all_ok=%v)\n", rep.Passed, rep.Total, rep.AllOK)
	for _, e := range rep.Results {
		mark := "PASS"
		if !e.Passed {
			mark = "FAIL"
		}
		fmt.Printf("  [%s] %s %s  metric=%.4f  %s\n", mark, e.ID, e.Name, e.Metric, e.Detail)
	}
	p := snap.Pillars
	fmt.Printf("  UC-oriented pillars: modeling=%v protocol=%v crypto=%v composition=%v\n",
		p.ModelingAssumptions.Verified, p.ProtocolCode.Verified,
		p.CryptoAssumptions.Verified, p.Composition.Verified)
	fmt.Printf("  ideal stack: id_strat=%v id_prot=%v enc_strat=%v enc=%v\n",
		p.Composition.IdealStack.IDStrategy.Verified, p.Composition.IdealStack.IDProtect.Verified,
		p.Composition.IdealStack.EncStrategy.Verified, p.Composition.IdealStack.EncProtect.Verified)
	fmt.Printf("  verified IAPP=%v\n  verified DAPP=%v\n  verified pairs=%d\n",
		snap.VerifiedIAPP, snap.VerifiedDAPP, len(snap.VerifiedPairs))

	sample := uc.AdaptiveRequest{
		SID: "uc-verify-sample", UserID: "audit-u",
		Input: context.ContextInput{
			Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
			DataType: "MANUSCRIPT", SecurityLevel: 1,
			RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
		},
		Plaintext: []byte("uc-verify-sample"),
	}
	rec, err := pair.Compare(sample)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit compare: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  audit sample consistent=%v reason=%q real_iapp=%s ideal_iapp=%s\n",
		rec.Consistent, rec.Reason, rec.RealTrace.IAPP, rec.IdealTrace.IAPP)
	fmt.Printf("  JSON: %s\n  TeX:  %s\n  Snapshot: %s\n", jsonPath, texPath, snapPath)
	if !rep.AllOK {
		os.Exit(1)
	}
	if *auditMode == string(uc.AuditModeGolden) && pair.CoordPath != "" && !rec.Consistent {
		fmt.Fprintf(os.Stderr, "golden audit: production rules drifted from DefaultRuleSet F\n")
		os.Exit(2)
	}
}

func latexTable(rep *uc.Report) string {
	var b strings.Builder
	b.WriteString("% Auto-generated " + time.Now().UTC().Format(time.RFC3339) + "\n")
	b.WriteString("\\begin{table}[htbp]\n\\centering\n")
	b.WriteString("\\caption{UC-oriented effectiveness verification of the adaptive mechanism.}\n")
	b.WriteString("\\label{tab:uc-adaptive-verify}\n")
	b.WriteString("\\begin{tabular}{llccc}\n\\hline\n")
	b.WriteString("ID & Experiment & Metric & Threshold & Result \\\\\n\\hline\n")
	for _, e := range rep.Results {
		res := "pass"
		if !e.Passed {
			res = "fail"
		}
		b.WriteString(fmt.Sprintf("%s & %s & %.3f & %.3f & %s \\\\\n",
			e.ID, latexEscape(e.Name), e.Metric, e.Threshold, res))
	}
	b.WriteString("\\hline\n\\end{tabular}\n")
	b.WriteString(fmt.Sprintf("\\end{table}\n%% %d/%d passed\n", rep.Passed, rep.Total))
	return b.String()
}

func latexEscape(s string) string {
	s = strings.ReplaceAll(s, "_", "\\_")
	s = strings.ReplaceAll(s, "%", "\\%")
	return s
}
