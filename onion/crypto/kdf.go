package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// MAC is HMAC-SHA256. It also serves as ntor's H(x, t) = HMAC(key=t, msg=x).
func MAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Extract is HKDF-Extract-SHA256 (equivalently HMAC(salt, secret)); this is
// ntor's KEY_SEED step.
func Extract(secret, salt []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		panic(fmt.Sprintf("hkdf extract: %v", err)) // only fails on a broken hash
	}
	return prk
}

// Expand is HKDF-Expand-SHA256.
func Expand(prk, info []byte, n int) ([]byte, error) {
	out, err := hkdf.Expand(sha256.New, prk, string(info), n)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return out, nil
}
