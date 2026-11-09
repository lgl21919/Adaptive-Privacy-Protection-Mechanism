package uc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"privacy-protection/adaptive/pkg/crypto"
)

// PrimitiveTag names the data-layer primitive that a candidate realises.
// ρ_app never calls these tags directly; it calls F_SC.
const (
	PrimitiveKE  = "F_KE"  // ECDH
	PrimitiveDKG = "F_DKG" // SSS (threshold / distributed share)
	PrimitivePRE = "F_PRE" // proxy re-encryption
	PrimitiveMPC = "F_SC"  // MPC treated as a secure-channel candidate
)

// SCService is the hybrid-world data port used by ρ_app.
type SCService interface {
	Name() string
	Primitive() string
	Seal(scheme crypto.Scheme, plaintext []byte) (crypto.Ciphertext, error)
	Open(scheme crypto.Scheme, ct crypto.Ciphertext) ([]byte, error)
}

// FSC is the data-layer core ideal functionality (secure message transmission):
// input (m, recipient/scheme), output a ciphertext that hides m except its length.
type FSC struct {
	mu    sync.Mutex
	store map[string][]byte
}

func NewFSC() *FSC {
	return &FSC{store: make(map[string][]byte)}
}

func (f *FSC) Name() string      { return "F_SC" }
func (f *FSC) Primitive() string { return PrimitiveMPC }

func (f *FSC) Seal(scheme crypto.Scheme, plaintext []byte) (crypto.Ciphertext, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return crypto.Ciphertext{}, err
	}
	key := hex.EncodeToString(id)
	dummy := make([]byte, len(plaintext)+16)
	if _, err := rand.Read(dummy); err != nil {
		return crypto.Ciphertext{}, err
	}
	copy(dummy[:16], id)
	f.mu.Lock()
	f.store[key] = append([]byte(nil), plaintext...)
	f.mu.Unlock()
	return crypto.Ciphertext{SchemeID: scheme.ID(), Blob: dummy}, nil
}

func (f *FSC) Open(scheme crypto.Scheme, ct crypto.Ciphertext) ([]byte, error) {
	if len(ct.Blob) < 16 {
		return nil, fmt.Errorf("F_SC: ciphertext too short")
	}
	key := hex.EncodeToString(ct.Blob[:16])
	f.mu.Lock()
	pt, ok := f.store[key]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("F_SC: unknown ciphertext")
	}
	return append([]byte(nil), pt...), nil
}
