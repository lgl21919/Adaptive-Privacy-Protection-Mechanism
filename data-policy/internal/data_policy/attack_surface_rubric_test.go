package data_policy

import "testing"

func TestAttackSurfaceRubric_AdaptiveExceedsBaselines(t *testing.T) {
	m := NewEnhancedDataPolicyManager()
	report := BuildAttackSurfaceReport(m)

	if !report.OrderingHolds {
		t.Fatalf("expected adaptive mitigation total > B1 and B2: ad=%.0f b1=%.0f b2=%.0f",
			report.AdaptiveTotal, report.B1Total, report.B2Total)
	}
	if report.AdaptiveShared <= report.B1Shared || report.AdaptiveShared <= report.B2Shared {
		t.Fatalf("shared vectors: adaptive=%.0f b1=%.0f b2=%.0f",
			report.AdaptiveShared, report.B1Shared, report.B2Shared)
	}
	if report.AdaptiveExposure >= report.B1Exposure || report.AdaptiveExposure >= report.B2Exposure {
		t.Fatalf("exposure index should be lower for adaptive: ad=%.1f b1=%.1f b2=%.1f",
			report.AdaptiveExposure, report.B1Exposure, report.B2Exposure)
	}
	t.Logf("attack-surface totals: Adaptive=%.0f B1=%.0f B2=%.0f (shared: %.0f/%.0f/%.0f)",
		report.AdaptiveTotal, report.B1Total, report.B2Total,
		report.AdaptiveShared, report.B1Shared, report.B2Shared)
	t.Logf("workflow exposure index (lower better): Adaptive=%.1f B1=%.1f B2=%.1f",
		report.AdaptiveExposure, report.B1Exposure, report.B2Exposure)
}

func TestAttackSurfaceRubric_LegacyWeightsUnchanged(t *testing.T) {
	w := DefaultRubricWeights()
	if w["ECDH_HKDF"] != 3.0 || w["MPC"] != 5.5 {
		t.Fatalf("legacy rubric weights must remain unchanged: %+v", w)
	}
}

func TestExportAttackSurfaceLaTeX_NonEmpty(t *testing.T) {
	m := NewEnhancedDataPolicyManager()
	report := BuildAttackSurfaceReport(m)
	tex := ExportAttackSurfaceLaTeX(report)
	if len(tex) < 200 {
		t.Fatal("latex export too short")
	}
	legacy := ExportLegacyRubricLaTeX(nil)
	if len(legacy) < 100 {
		t.Fatal("legacy rubric latex too short")
	}
}
