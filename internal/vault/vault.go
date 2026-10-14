// Package vault encrypts per-user upstream credentials with AES-256-GCM.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// ponytail: one master key, no rotation; add a key-id prefix to sealed data when rotation is needed.
type Vault struct{ aead cipher.AEAD }

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("vault: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// Seal encrypts plain. aad binds the result to its owner (user + system), so
// sealed data copied to another owner fails to open.
func (v *Vault) Seal(plain, aad []byte) []byte {
	nonce := make([]byte, v.aead.NonceSize())
	rand.Read(nonce) // never fails since Go 1.24
	return v.aead.Seal(nonce, nonce, plain, aad)
}

func (v *Vault) Open(sealed, aad []byte) ([]byte, error) {
	n := v.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("vault: sealed data too short")
	}
	return v.aead.Open(nil, sealed[:n], sealed[n:], aad)
}
