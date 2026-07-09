package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD is the pluggable layer cipher — the "crypto algorithm" knob. It is a
// factory for keyed cipher.AEAD values; nonce handling lives in the session
// package. Every node and client on a network must agree on one AEAD.
type AEAD interface {
	// KeySize is the required key length in bytes.
	KeySize() int
	// New returns a keyed AEAD.
	New(key []byte) (cipher.AEAD, error)
	// Name identifies the algorithm.
	Name() string
}

// AESGCM is AES-256-GCM (standard library only).
func AESGCM() AEAD { return aesgcm{} }

// ChaCha20Poly1305 is IETF ChaCha20-Poly1305 (golang.org/x/crypto).
func ChaCha20Poly1305() AEAD { return chacha{} }

type aesgcm struct{}

func (aesgcm) KeySize() int { return 32 }
func (aesgcm) Name() string { return "aes-256-gcm" }
func (aesgcm) New(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	return cipher.NewGCM(block)
}

type chacha struct{}

func (chacha) KeySize() int                        { return chacha20poly1305.KeySize }
func (chacha) Name() string                        { return "chacha20-poly1305" }
func (chacha) New(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }
