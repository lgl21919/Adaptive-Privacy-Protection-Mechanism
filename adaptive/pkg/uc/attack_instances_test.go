package uc

import (
	"crypto/rand"
	"testing"

	"privacy-protection/adaptive/pkg/reasoning"
)

func TestAttackInstancesStaticWorseThanAdaptive(t *testing.T) {
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	keys := make([][]byte, 3)
	for i := range keys {
		keys[i] = make([]byte, 32)
		_, _ = rand.Read(keys[i])
	}
	mac := make([]byte, 32)
	_, _ = rand.Read(mac)

	a1 := AttackA1ReviewerSeesDBAuthor(master)
	a2 := AttackA2CrossPhaseLink(master)
	a3, err := AttackA3SinglePointKey(keys, mac, master)
	if err != nil {
		t.Fatal(err)
	}
	a4, err := AttackA4NoThreshold(keys, mac, master)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []AttackResult{a1, a2, a3, a4} {
		t.Logf("%s %s | static_success=%v (%s) | adaptive_success=%v (%s)",
			r.ID, r.Name, r.StaticOK, r.StaticDetail, r.AdaptOK, r.AdaptDetail)
		if !r.AdaptiveBetter() {
			t.Errorf("%s: expected static success and adaptive failure", r.ID)
		}
	}
}

func TestAttackInstancesB2SSSVsAdaptive(t *testing.T) {
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	keys := make([][]byte, 3)
	for i := range keys {
		keys[i] = make([]byte, 32)
		_, _ = rand.Read(keys[i])
	}
	mac := make([]byte, 32)
	_, _ = rand.Read(mac)

	a1 := AttackA1ReviewerSeesDBAuthor(master)
	a2 := AttackA2CrossPhaseLink(master)
	a3, err := AttackA3SinglePointKeyAgainst(keys, mac, master, reasoning.DAPPSSS, 2)
	if err != nil {
		t.Fatal(err)
	}
	a4, err := AttackA4NoThresholdAgainst(keys, mac, master, reasoning.DAPPSSS, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []AttackResult{a1, a2, a3, a4} {
		t.Logf("B2-SSS %s | static_success=%v (%s) | adaptive_success=%v (%s) | adaptive_better=%v",
			r.ID, r.StaticOK, r.StaticDetail, r.AdaptOK, r.AdaptDetail, r.AdaptiveBetter())
	}
	if !a1.AdaptiveBetter() || !a2.AdaptiveBetter() {
		t.Fatal("identity attacks A1--A2 must still favour adaptive when B2 freezes SSS")
	}
	if a3.StaticOK || a4.StaticOK {
		t.Fatalf("SSS cascade should resist one layer-0 key: A3=%v A4=%v", a3.StaticOK, a4.StaticOK)
	}
}

func TestMeasureTauTableECDHSSSAdaptive(t *testing.T) {
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	keys := make([][]byte, 3)
	for i := range keys {
		keys[i] = make([]byte, 32)
		_, _ = rand.Read(keys[i])
	}
	mac := make([]byte, 32)
	_, _ = rand.Read(mac)
	rows, err := MeasureTauTable(keys, mac, master)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		t.Logf("ℓ=%d %-22s ECDH τ=%d  SSS τ=%d  Adapt τ=%d (%s)  ≥ECDH=%v ≥SSS=%v",
			r.Level, r.Scene, r.TauECDH, r.TauSSS, r.TauAdapt, r.AdaptDAPP,
			r.TauAdapt >= r.TauECDH, r.TauAdapt >= r.TauSSS)
	}
}

func TestStageKeyReuseAndComposition(t *testing.T) {
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	keys := make([][]byte, 3)
	for i := range keys {
		keys[i] = make([]byte, 32)
		_, _ = rand.Read(keys[i])
	}
	mac := make([]byte, 32)
	_, _ = rand.Read(mac)
	ecdh, sss, adapt, err := StageLeakTable(keys, mac, master)
	if err != nil {
		t.Fatal(err)
	}
	π := newKeyedProtocol(keys, mac, master)
	for i := range adapt {
		t.Logf("S%d adapt DAPP=%s τ=%d | ECDH τ=%d open_k0=%v | SSS τ=%d open_k0=%v | Adapt open_k0=%v open_k0k1=%v",
			i+1, adapt[i].DAPP, adapt[i].Tau, ecdh[i].Tau,
			opensWith(π.enc, ecdh[i], 1, keys, mac),
			sss[i].Tau, opensWith(π.enc, sss[i], 1, keys, mac),
			opensWith(π.enc, adapt[i], 1, keys, mac),
			opensWith(π.enc, adapt[i], 2, keys, mac))
	}
	if adapt[0].Tau != 1 || adapt[1].Tau < 2 || adapt[2].Tau < 2 {
		t.Fatalf("adaptive stage schemes should differ in τ, got %d,%d,%d DAPP %s/%s/%s",
			adapt[0].Tau, adapt[1].Tau, adapt[2].Tau, adapt[0].DAPP, adapt[1].DAPP, adapt[2].DAPP)
	}
	if adapt[0].DAPP == adapt[1].DAPP || adapt[1].DAPP == adapt[2].DAPP || adapt[0].DAPP == adapt[2].DAPP {
		t.Fatalf("expected distinct DAPP per stage, got %s/%s/%s", adapt[0].DAPP, adapt[1].DAPP, adapt[2].DAPP)
	}
	if !opensWith(π.enc, ecdh[0], 1, keys, mac) || !opensWith(π.enc, ecdh[1], 1, keys, mac) || !opensWith(π.enc, ecdh[2], 1, keys, mac) {
		t.Fatal("static ECDH: k0 must open submission, review, and publication")
	}
	if opensWith(π.enc, adapt[1], 1, keys, mac) || opensWith(π.enc, adapt[2], 1, keys, mac) {
		t.Fatal("adaptive: k0 from submission must not open review or publication")
	}
}

func TestCompositionVsSingleStaticECDH(t *testing.T) {
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	keys := make([][]byte, 3)
	for i := range keys {
		keys[i] = make([]byte, 32)
		_, _ = rand.Read(keys[i])
	}
	mac := make([]byte, 32)
	_, _ = rand.Read(mac)
	rows, err := MeasureCompositionVsSingleECDH(keys, mac, master)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		t.Logf("%s staticECDH τ=%d k1=%v | adapt %s τ=%d k1=%v scheme=%s",
			r.Scene, r.TauStatic, r.K1Static, r.AdaptDAPP, r.TauAdapt, r.K1Adapt, r.AdaptScheme)
		if r.TauAdapt <= r.TauStatic {
			t.Fatalf("adaptive cascade should need more keys than single ECDH")
		}
		if !r.K1Static || r.K1Adapt {
			t.Fatalf("k=1 should open static only")
		}
	}
}
