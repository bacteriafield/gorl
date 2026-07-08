// Package crypto holds the pluggable cryptographic primitives used across the
// library: X25519 key agreement, an AEAD interface (the swappable layer
// cipher), and HKDF/HMAC helpers. It intentionally groups cohesive operations
// rather than exposing one primitive per package.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// KeyPair is an X25519 keypair with raw 32-byte encodings.
type KeyPair struct {
	Private []byte
	Public  []byte
}

// GenerateX25519 returns a fresh X25519 keypair (used for ntor ephemerals and
// relay static onion keys).
func GenerateX25519() (KeyPair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("x25519 generate: %w", err)
	}
	return KeyPair{Private: k.Bytes(), Public: k.PublicKey().Bytes()}, nil
}

// PublicFromPrivate recomputes the public key for a raw private scalar.
func PublicFromPrivate(private []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("x25519 private: %w", err)
	}
	return k.PublicKey().Bytes(), nil
}

// X25519 computes the ECDH shared secret EXP(peerPublic, private). The stdlib
// rejects low-order points, so a nil error implies a contributory secret.
func X25519(private, peerPublic []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("x25519 private: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("x25519 public: %w", err)
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}
	return secret, nil
}
