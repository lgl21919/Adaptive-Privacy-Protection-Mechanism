package crypto

import (
	"testing"
	"time"
)

func BenchmarkPRE_Encryption(b *testing.B) {
	pre := NewProxyReEncryption(nil)
	pre.GenerateKeyPair("alice")
	data := []byte("benchmark payload for PRE encrypt")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pre.Encrypt(data, "alice"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPRE_Decryption(b *testing.B) {
	pre := NewProxyReEncryption(nil)
	pre.GenerateKeyPair("alice")
	data := []byte("benchmark payload for PRE decrypt")
	ct, err := pre.Encrypt(data, "alice")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pre.Decrypt(ct, "alice"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPRE_ReEncryption(b *testing.B) {
	pre := NewProxyReEncryption(nil)
	pre.GenerateKeyPair("alice")
	pre.GenerateKeyPair("bob")
	data := []byte("benchmark payload for PRE re-encrypt")
	ct, err := pre.Encrypt(data, "alice")
	if err != nil {
		b.Fatal(err)
	}
	reKey, err := pre.GenerateReEncryptionKey("alice", "bob", time.Hour)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pre.ReEncrypt(ct, reKey); err != nil {
			b.Fatal(err)
		}
	}
}
