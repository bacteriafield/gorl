// Package handshake implements the ntor one-way-authenticated key agreement
// (Tor proposal 216 / tor-spec §5.1.4). The client authenticates the relay via
// the relay's static onion key; forward secrecy comes from per-handshake
// ephemerals. Both the client (circuit) and the relay use this package.
package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/bacteriafield/gorl/onion/crypto"
)

const (
	protoID = "ntor-curve25519-sha256-1"
	tMac    = protoID + ":mac"
	tKey    = protoID + ":key_extract"
	tVerify = protoID + ":verify"
	server  = "Server"

	pubSize  = 32
	authSize = 32
	// IDSize is the length of a node id (SHA-256 of the static onion key).
	IDSize = 32
	// CreateSize / CreatedSize are the fixed handshake payload lengths.
	CreateSize  = IDSize + pubSize   // nodeID || X
	CreatedSize = pubSize + authSize // Y || AUTH
)

// NodeID derives a node's stable identifier from its static onion public key.
func NodeID(staticPub []byte) []byte {
	h := sha256.Sum256(staticPub)
	return h[:]
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ntorKDF computes KEY_SEED and AUTH from the two DH outputs and the transcript.
// Server uses dh1=EXP(X,y), dh2=EXP(X,b); client uses dh1=EXP(Y,x), dh2=EXP(B,x)
// — the pairs are equal, so both derive the same values.
func ntorKDF(dh1, dh2, nodeID, staticB, x, y []byte) (keySeed, auth []byte) {
	secretInput := concat(dh1, dh2, nodeID, staticB, x, y, []byte(protoID))
	keySeed = crypto.Extract(secretInput, []byte(tKey)) // H(secret_input, t_key)
	verify := crypto.MAC([]byte(tVerify), secretInput)  // H(secret_input, t_verify)
	authInput := concat(verify, nodeID, staticB, y, x, []byte(protoID), []byte(server))
	auth = crypto.MAC([]byte(tMac), authInput) // H(auth_input, t_mac)
	return keySeed, auth
}

// ClientState is the client's per-handshake secret, held between Create and
// Finish.
type ClientState struct {
	eph     crypto.KeyPair
	nodeID  []byte
	staticB []byte
}

// ClientCreate begins a handshake with the relay identified by (nodeID, staticB)
// and returns the CreateSize CREATE payload to send.
func ClientCreate(nodeID, staticB []byte) (*ClientState, []byte, error) {
	if len(nodeID) != IDSize || len(staticB) != pubSize {
		return nil, nil, errors.New("ntor: bad node id or static key")
	}
	eph, err := crypto.GenerateX25519()
	if err != nil {
		return nil, nil, err
	}
	st := &ClientState{eph: eph, nodeID: nodeID, staticB: staticB}
	return st, concat(nodeID, eph.Public), nil
}

// ServerAnswer runs the relay side. Given the relay's static keypair and the
// client's CREATE payload it returns the CREATED payload and KEY_SEED.
func ServerAnswer(staticPriv, staticPub, create []byte) (created, keySeed []byte, err error) {
	if len(create) < CreateSize {
		return nil, nil, errors.New("ntor: short create")
	}
	nodeID := create[:IDSize]
	x := create[IDSize:CreateSize]
	if !hmac.Equal(nodeID, NodeID(staticPub)) {
		return nil, nil, errors.New("ntor: create addressed to a different node")
	}
	eph, err := crypto.GenerateX25519() // y, Y
	if err != nil {
		return nil, nil, err
	}
	xy, err := crypto.X25519(eph.Private, x) // EXP(X, y)
	if err != nil {
		return nil, nil, err
	}
	xb, err := crypto.X25519(staticPriv, x) // EXP(X, b)
	if err != nil {
		return nil, nil, err
	}
	keySeed, auth := ntorKDF(xy, xb, nodeID, staticPub, x, eph.Public)
	return concat(eph.Public, auth), keySeed, nil
}

// Finish completes the client side against the relay's CREATED payload and
// returns KEY_SEED. It fails if the relay's AUTH does not verify.
func (st *ClientState) Finish(created []byte) ([]byte, error) {
	if len(created) < CreatedSize {
		return nil, errors.New("ntor: short created")
	}
	y := created[:pubSize]
	auth := created[pubSize:CreatedSize]
	yx, err := crypto.X25519(st.eph.Private, y) // EXP(Y, x)
	if err != nil {
		return nil, err
	}
	bx, err := crypto.X25519(st.eph.Private, st.staticB) // EXP(B, x)
	if err != nil {
		return nil, err
	}
	keySeed, expect := ntorKDF(yx, bx, st.nodeID, st.staticB, st.eph.Public, y)
	if !hmac.Equal(auth, expect) {
		return nil, errors.New("ntor: relay authentication failed")
	}
	return keySeed, nil
}
