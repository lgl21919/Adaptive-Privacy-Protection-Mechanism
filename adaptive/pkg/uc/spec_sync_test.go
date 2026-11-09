package uc_test

import (
	"testing"

	"privacy-protection/adaptive/pkg/reasoning"
	"privacy-protection/adaptive/pkg/uc"
)

func TestHotPathIdealSpecConfigSync(t *testing.T) {
	spec := uc.DefaultIdealSpec()
	rs := reasoning.DefaultRuleSet()
	if err := uc.CheckHotPathSpecSync(spec, rs); err != nil {
		t.Fatal(err)
	}
	if spec.Version() != reasoning.ConfigCatalogVersion {
		t.Fatalf("spec version %q != catalog %q", spec.Version(), reasoning.ConfigCatalogVersion)
	}
	if rs.Version != reasoning.ConfigCatalogVersion {
		t.Fatalf("rules version %q != catalog %q", rs.Version, reasoning.ConfigCatalogVersion)
	}
}
