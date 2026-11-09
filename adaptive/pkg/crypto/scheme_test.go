package crypto_test

import (
	"bytes"
	"testing"

	"privacy-protection/adaptive/pkg/crypto"
)

func TestSingleAndCascadeRoundTrip(t *testing.T) {
	ex := crypto.NewExecutor()
	msg := []byte("peer-review manuscript")
	single := crypto.Scheme{Token: "ECDH_HKDF", Algorithms: []string{"ECDH_HKDF"}, ComposeMode: crypto.ComposeSingle}
	ct, err := ex.Encrypt(single, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ex.Decrypt(single, ct)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("single: %v %q", err, pt)
	}

	cascade := crypto.Scheme{
		Token: "MPC", Algorithms: []string{"ECDH_HKDF", "SSS", "PROXY_REENCRYPTION"},
		ComposeMode: crypto.ComposeCascade,
	}
	ct2, err := ex.Encrypt(cascade, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := ex.Decrypt(cascade, ct2)
	if err != nil || !bytes.Equal(pt2, msg) {
		t.Fatalf("cascade: %v %q", err, pt2)
	}
}

func TestSignThenEncryptRoundTrip(t *testing.T) {
	ex := crypto.NewExecutor()
	msg := []byte("editor decision")
	ste := crypto.Scheme{Token: "STE", Algorithms: []string{"ECDH_HKDF", "HMAC-SHA256"}, ComposeMode: crypto.ComposeSTE}
	ct, err := ex.Encrypt(ste, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ex.Decrypt(ste, ct)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("ste: %v %q", err, pt)
	}
}
