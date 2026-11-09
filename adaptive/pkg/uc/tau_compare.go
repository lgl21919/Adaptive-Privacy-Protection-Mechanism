package uc

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"privacy-protection/adaptive/pkg/crypto"
	"privacy-protection/adaptive/pkg/reasoning"
)

// TauRow is one scenario's measured decrypt threshold (min leaked layer keys).
type TauRow struct {
	Scene              string
	Level              int
	AdaptDAPP          string
	TauECDH, TauSSS, TauAdapt int
}

func keyedAttacker(full [][]byte, mac []byte, leaked int) *crypto.Executor {
	use := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		if i < leaked {
			use[i] = append([]byte(nil), full[i]...)
			continue
		}
		use[i] = make([]byte, 32)
		_, _ = rand.Read(use[i])
	}
	return crypto.NewExecutorWithKeys(use, mac)
}

func minKeysToDecrypt(enc *crypto.Executor, scheme crypto.Scheme, ct crypto.Ciphertext, pt []byte, full [][]byte, mac []byte) int {
	if scheme.ComposeMode == crypto.ComposeNone || (len(scheme.Algorithms) == 1 && scheme.Algorithms[0] == reasoning.DAPPPublic) {
		got, err := enc.Decrypt(scheme, ct)
		if err == nil && bytes.Equal(got, pt) {
			return 0
		}
	}
	for k := 1; k <= 3; k++ {
		att := keyedAttacker(full, mac, k)
		got, err := att.Decrypt(scheme, ct)
		if err == nil && bytes.Equal(got, pt) {
			return k
		}
	}
	return -1
}

func measurePinnedTau(π *Protocol, req AdaptiveRequest, dapp string, level int, keys [][]byte, mac []byte, pt []byte) (int, string, error) {
	pin := req
	if dapp != "" {
		pin = staticPinDAPP(req, dapp, level)
	}
	resp, err := π.Invoke(pin)
	if err != nil {
		return -1, "", err
	}
	return minKeysToDecrypt(π.enc, resp.Scheme, resp.Cipher, pt, keys, mac), resp.Trace.DAPP, nil
}

// MeasureTauTable encrypts the same plaintext under ECDH, SSS, and adaptive DAPP.
func MeasureTauTable(keys [][]byte, mac, master []byte) ([]TauRow, error) {
	π := newKeyedProtocol(keys, mac, master)
	pt := []byte("payload-tau-compare")
	scenes := []struct {
		name, phase, role, mode, dtype string
		level                          int
	}{
		{"review manuscript", "REVIEW", "REVIEWER", "DOUBLE_BLIND", "MANUSCRIPT", 1},
		{"review manuscript", "REVIEW", "REVIEWER", "DOUBLE_BLIND", "MANUSCRIPT", 2},
		{"final recommendation", "REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3},
		{"publication message", "PUBLICATION", "EDITOR", "OPEN", "MESSAGE", 0},
	}
	var out []TauRow
	for _, s := range scenes {
		req := baseReq(s.phase, s.role, s.mode, s.dtype, s.level, "u", "sid-"+s.name, pt)
		te, _, err := measurePinnedTau(π, req, reasoning.DAPPECDH, 1, keys, mac, pt)
		if err != nil {
			return nil, fmt.Errorf("ECDH %s: %w", s.name, err)
		}
		ts, _, err := measurePinnedTau(π, req, reasoning.DAPPSSS, 2, keys, mac, pt)
		if err != nil {
			return nil, fmt.Errorf("SSS %s: %w", s.name, err)
		}
		ta, dapp, err := measurePinnedTau(π, req, "", 0, keys, mac, pt)
		if err != nil {
			return nil, fmt.Errorf("adapt %s: %w", s.name, err)
		}
		out = append(out, TauRow{
			Scene: s.name, Level: s.level, AdaptDAPP: dapp,
			TauECDH: te, TauSSS: ts, TauAdapt: ta,
		})
	}
	return out, nil
}

// StageCipher is one workflow ciphertext under a named policy.
type StageCipher struct {
	Name, DAPP string
	Level, Tau int
	Scheme     crypto.Scheme
	CT         crypto.Ciphertext
	PT         []byte
}

func opensWith(enc *crypto.Executor, st StageCipher, leaked int, keys [][]byte, mac []byte) bool {
	if st.Tau == 0 {
		got, err := enc.Decrypt(st.Scheme, st.CT)
		return err == nil && bytes.Equal(got, st.PT)
	}
	att := keyedAttacker(keys, mac, leaked)
	got, err := att.Decrypt(st.Scheme, st.CT)
	return err == nil && bytes.Equal(got, st.PT)
}

func encryptWorkflow(π *Protocol, dapp string, pinLevel int, keys [][]byte, mac []byte) ([]StageCipher, error) {
	steps := []struct {
		name, phase, role, mode, dtype string
		level                          int
		pt                             []byte
	}{
		{"S1 submission", "SUBMISSION", "AUTHOR", "DOUBLE_BLIND", "MANUSCRIPT", 1, []byte("submit-v1")},
		{"S2 review", "REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3, []byte("review-v2")},
		{"S3 publication", "PUBLICATION", "AUTHOR", "OPEN", "MANUSCRIPT", 2, []byte("publish-v3")},
	}
	var out []StageCipher
	for _, s := range steps {
		req := baseReq(s.phase, s.role, s.mode, s.dtype, s.level, "u", "wf-"+s.name, s.pt)
		var resp *AdaptiveResponse
		var err error
		if dapp != "" {
			resp, err = π.Invoke(staticPinDAPP(req, dapp, pinLevel))
		} else {
			resp, err = π.Invoke(req)
		}
		if err != nil {
			return nil, err
		}
		tau := minKeysToDecrypt(π.enc, resp.Scheme, resp.Cipher, s.pt, keys, mac)
		out = append(out, StageCipher{
			Name: s.name, DAPP: resp.Trace.DAPP, Level: s.level, Tau: tau,
			Scheme: resp.Scheme, CT: resp.Cipher, PT: s.pt,
		})
	}
	return out, nil
}

// StageLeakTable: same keying material across S1(ℓ=1)→S2(ℓ=2)→S3(ℓ=3).
// Angle 1: a k0 leak after S1 must not open later stages under adaptive.
// Angle 2: composition raises τ along the workflow (1 then 2 then 3).
func StageLeakTable(keys [][]byte, mac, master []byte) (ecdh, sss, adapt []StageCipher, err error) {
	π := newKeyedProtocol(keys, mac, master)
	ecdh, err = encryptWorkflow(π, reasoning.DAPPECDH, 1, keys, mac)
	if err != nil {
		return nil, nil, nil, err
	}
	sss, err = encryptWorkflow(π, reasoning.DAPPSSS, 2, keys, mac)
	if err != nil {
		return nil, nil, nil, err
	}
	adapt, err = encryptWorkflow(π, "", 0, keys, mac)
	return ecdh, sss, adapt, err
}

// CompositionTauRow compares a single-algorithm static pin with adaptive cascade.
type CompositionTauRow struct {
	Scene, AdaptDAPP, AdaptScheme string
	Level, TauStatic, TauAdapt    int
	K1Static, K1Adapt             bool
}

func MeasureCompositionVsSingleECDH(keys [][]byte, mac, master []byte) ([]CompositionTauRow, error) {
	π := newKeyedProtocol(keys, mac, master)
	cases := []struct {
		name, phase, role, mode, dtype string
		level                          int
		pt                             []byte
	}{
		{"ℓ=2 review manuscript", "REVIEW", "REVIEWER", "DOUBLE_BLIND", "MANUSCRIPT", 2, []byte("ms-l2")},
		{"ℓ=3 final recommendation", "REVIEW", "REVIEWER", "DOUBLE_BLIND", "FINAL_RECOMMENDATION", 3, []byte("rec-l3")},
	}
	var out []CompositionTauRow
	for _, s := range cases {
		req := baseReq(s.phase, s.role, s.mode, s.dtype, s.level, "u", "cmp-"+s.name, s.pt)
		st, err := π.Invoke(staticPinDAPP(req, reasoning.DAPPECDH, 1))
		if err != nil {
			return nil, err
		}
		ad, err := π.Invoke(req)
		if err != nil {
			return nil, err
		}
		ts := minKeysToDecrypt(π.enc, st.Scheme, st.Cipher, s.pt, keys, mac)
		ta := minKeysToDecrypt(π.enc, ad.Scheme, ad.Cipher, s.pt, keys, mac)
		out = append(out, CompositionTauRow{
			Scene: s.name, Level: s.level,
			AdaptDAPP: ad.Trace.DAPP, AdaptScheme: ad.Scheme.ID(),
			TauStatic: ts, TauAdapt: ta,
			K1Static: ts == 1, K1Adapt: ta == 1,
		})
	}
	return out, nil
}
