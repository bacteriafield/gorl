// Package session holds the directional symmetric keys derived from an ntor
// KEY_SEED and seals/opens onion layers. The same KEY_SEED yields the same
// Session on the client and on the matching relay, so it is the shared type
// between circuit and relay.
package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/bacteriafield/gorl/onion/crypto"
)

var sessionInfo = []byte("gorl session key expansion v1")

const nonceSize = 12

// Session carries the forward/backward AEADs plus the send-side nonce counters.
// A client seals forward / opens backward; a relay opens forward / seals
// backward. Nonces are transmitted with each layer, so only the sealing side of
// each direction advances a counter.
type Session struct {
	fwd, bwd cipher.AEAD
	fwdCtr   uint64
	bwdCtr   uint64
}

// Derive builds a Session from an ntor KEY_SEED and the network's AEAD.
func Derive(keySeed []byte, aead crypto.AEAD) (*Session, error) {
	ks := aead.KeySize()
	material, err := crypto.Expand(keySeed, sessionInfo, 2*ks)
	if err != nil {
		return nil, err
	}
	fwd, err := aead.New(material[:ks])
	if err != nil {
		return nil, err
	}
	bwd, err := aead.New(material[ks : 2*ks])
	if err != nil {
		return nil, err
	}
	if fwd.NonceSize() != nonceSize || bwd.NonceSize() != nonceSize {
		return nil, errors.New("session: AEAD nonce size must be 12")
	}
	return &Session{fwd: fwd, bwd: bwd}, nil
}

func nonceFor(ctr uint64) []byte {
	n := make([]byte, nonceSize)
	binary.BigEndian.PutUint64(n[4:], ctr) // 4 zero bytes || big-endian counter
	return n
}

func seal(a cipher.AEAD, ctr *uint64, plaintext []byte) []byte {
	n := nonceFor(*ctr)
	*ctr++
	return append(n, a.Seal(nil, n, plaintext, nil)...)
}

func open(a cipher.AEAD, wire []byte) ([]byte, error) {
	if len(wire) < nonceSize {
		return nil, errors.New("session: short layer")
	}
	return a.Open(nil, wire[:nonceSize], wire[nonceSize:], nil)
}

// Overhead is the bytes a single layer adds (nonce + AEAD tag). Assumes a
// 16-byte tag, true for AES-GCM and ChaCha20-Poly1305.
const Overhead = nonceSize + 16

// EncryptForward seals a layer toward the exit (client side).
func (s *Session) EncryptForward(plaintext []byte) []byte { return seal(s.fwd, &s.fwdCtr, plaintext) }

// DecryptForward opens a forward layer (relay side).
func (s *Session) DecryptForward(wire []byte) ([]byte, error) { return open(s.fwd, wire) }

// EncryptBackward seals a layer toward the client (relay side).
func (s *Session) EncryptBackward(plaintext []byte) []byte { return seal(s.bwd, &s.bwdCtr, plaintext) }

// DecryptBackward opens a backward layer (client side).
func (s *Session) DecryptBackward(wire []byte) ([]byte, error) { return open(s.bwd, wire) }
