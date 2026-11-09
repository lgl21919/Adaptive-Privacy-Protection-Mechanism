// Package crypto implements F_enc(scheme): IND-CCA style AES-GCM as a base
// primitive, plus CASCADE and SIGN_THEN_ENCRYPT compositions.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	ComposeNone   = "NONE"
	ComposeSingle = "SINGLE"
	ComposeCascade = "CASCADE"
	ComposeSTE    = "SIGN_THEN_ENCRYPT"
)

// Scheme is the public encryption-scheme identifier produced by F_enc-strategy.
type Scheme struct {
	Token         string   `json:"token"`
	Algorithms    []string `json:"algorithms"`
	ComposeMode   string   `json:"compose_mode"`
	SecurityLevel int      `json:"security_level"`
}

func (s Scheme) ID() string {
	if s.ComposeMode == "" || s.ComposeMode == ComposeSingle || s.ComposeMode == ComposeNone {
		if len(s.Algorithms) == 0 {
			return s.Token
		}
		return s.Algorithms[0]
	}
	return s.ComposeMode + "(" + strings.Join(s.Algorithms, " ∘ ") + ")"
}

// Ciphertext is a labelled composition ciphertext.
type Ciphertext struct {
	SchemeID string `json:"scheme_id"`
	Blob     []byte `json:"blob"`
}

// Executor is the real-world realization of F_enc.
type Executor struct {
	keys [][]byte
	mac  []byte
}

func NewExecutor() *Executor {
	keys := make([][]byte, 3)
	for i := range keys {
		keys[i] = make([]byte, 32)
		_, _ = rand.Read(keys[i])
	}
	mac := make([]byte, 32)
	_, _ = rand.Read(mac)
	return &Executor{keys: keys, mac: mac}
}

func NewExecutorWithKeys(keys [][]byte, mac []byte) *Executor {
	cp := make([][]byte, len(keys))
	for i := range keys {
		cp[i] = append([]byte(nil), keys[i]...)
	}
	return &Executor{keys: cp, mac: append([]byte(nil), mac...)}
}

func (e *Executor) Encrypt(scheme Scheme, plaintext []byte) (Ciphertext, error) {
	if scheme.ComposeMode == ComposeNone || (len(scheme.Algorithms) == 1 && scheme.Algorithms[0] == "PUBLIC") {
		return Ciphertext{SchemeID: scheme.ID(), Blob: append([]byte(nil), plaintext...)}, nil
	}
	switch scheme.ComposeMode {
	case ComposeSTE:
		signed := e.macThen(plaintext)
		blob, err := e.cascadeEncrypt(signed, max(1, len(scheme.Algorithms)))
		if err != nil {
			return Ciphertext{}, err
		}
		return Ciphertext{SchemeID: scheme.ID(), Blob: blob}, nil
	case ComposeCascade:
		n := len(scheme.Algorithms)
		if n < 2 {
			n = 2
		}
		blob, err := e.cascadeEncrypt(plaintext, n)
		if err != nil {
			return Ciphertext{}, err
		}
		return Ciphertext{SchemeID: scheme.ID(), Blob: blob}, nil
	default:
		blob, err := gcmSeal(e.key(0), plaintext)
		if err != nil {
			return Ciphertext{}, err
		}
		return Ciphertext{SchemeID: scheme.ID(), Blob: blob}, nil
	}
}

func (e *Executor) Decrypt(scheme Scheme, ct Ciphertext) ([]byte, error) {
	if scheme.ComposeMode == ComposeNone || (len(scheme.Algorithms) == 1 && scheme.Algorithms[0] == "PUBLIC") {
		return append([]byte(nil), ct.Blob...), nil
	}
	switch scheme.ComposeMode {
	case ComposeSTE:
		n := max(1, len(scheme.Algorithms))
		inner, err := e.cascadeDecrypt(ct.Blob, n)
		if err != nil {
			return nil, err
		}
		return e.macVerify(inner)
	case ComposeCascade:
		n := len(scheme.Algorithms)
		if n < 2 {
			n = 2
		}
		return e.cascadeDecrypt(ct.Blob, n)
	default:
		return gcmOpen(e.key(0), ct.Blob)
	}
}

func (e *Executor) cascadeEncrypt(pt []byte, layers int) ([]byte, error) {
	cur := pt
	var err error
	for i := 0; i < layers; i++ {
		cur, err = gcmSeal(e.key(i), cur)
		if err != nil {
			return nil, err
		}
	}
	return cur, nil
}

func (e *Executor) cascadeDecrypt(ct []byte, layers int) ([]byte, error) {
	cur := ct
	var err error
	for i := layers - 1; i >= 0; i-- {
		cur, err = gcmOpen(e.key(i), cur)
		if err != nil {
			return nil, err
		}
	}
	return cur, nil
}

func (e *Executor) macThen(pt []byte) []byte {
	mac := hmac.New(sha256.New, e.mac)
	mac.Write(pt)
	tag := mac.Sum(nil)
	out := make([]byte, 2+len(pt)+len(tag))
	binary.BigEndian.PutUint16(out[:2], uint16(len(pt)))
	copy(out[2:], pt)
	copy(out[2+len(pt):], tag)
	return out
}

func (e *Executor) macVerify(blob []byte) ([]byte, error) {
	if len(blob) < 2+32 {
		return nil, fmt.Errorf("ste blob too short")
	}
	n := int(binary.BigEndian.Uint16(blob[:2]))
	if 2+n+32 > len(blob) {
		return nil, fmt.Errorf("ste length mismatch")
	}
	pt := blob[2 : 2+n]
	tag := blob[2+n : 2+n+32]
	mac := hmac.New(sha256.New, e.mac)
	mac.Write(pt)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, fmt.Errorf("ste mac verify failed")
	}
	return pt, nil
}

func (e *Executor) key(i int) []byte {
	if i < len(e.keys) {
		return e.keys[i]
	}
	h := sha256.Sum256(append(e.keys[0], byte(i)))
	return h[:]
}

func gcmSeal(key, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, pt, nil), nil
}

func gcmOpen(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(ct) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return aead.Open(nil, ct[:ns], ct[ns:], nil)
}

// RandomCiphertext is used by simulator S (encrypt dummy / random bits of same length).
func RandomCiphertext(scheme Scheme, length int) (Ciphertext, error) {
	dummy := make([]byte, length)
	_, _ = rand.Read(dummy)
	ex := NewExecutor()
	return ex.Encrypt(scheme, dummy)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
