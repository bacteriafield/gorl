// Package gorl is a convenience facade over the onion-routing library. It
// re-exports the pieces most callers need, so you can
//
//	import "github.com/bacteriafield/gorl"
//
// and build a client or a relay without reaching into the subpackages. The full
// API — every plug point — lives under github.com/bacteriafield/gorl/onion/...
package gorl

import (
	"github.com/bacteriafield/gorl/onion/client"
	"github.com/bacteriafield/gorl/onion/crypto"
	"github.com/bacteriafield/gorl/onion/directory"
	"github.com/bacteriafield/gorl/onion/relay"
	"github.com/bacteriafield/gorl/onion/transport"
)

// Core types, aliased from the subpackages (zero-cost).
type (
	AEAD      = crypto.AEAD
	KeyPair   = crypto.KeyPair
	Node      = directory.Node
	Resolver  = directory.Resolver
	Transport = transport.Transport
	Client    = client.Client
	Relay     = relay.Relay
)

// AESGCM is AES-256-GCM (standard library only).
func AESGCM() AEAD { return crypto.AESGCM() }

// ChaCha20Poly1305 is IETF ChaCha20-Poly1305.
func ChaCha20Poly1305() AEAD { return crypto.ChaCha20Poly1305() }

// GenerateKey returns a fresh X25519 static onion keypair for a relay.
func GenerateKey() (KeyPair, error) { return crypto.GenerateX25519() }

// TCP is the reference transport backend.
func TCP() Transport { return transport.TCP{} }

// StaticDirectory is a fixed node list (tests, small deployments).
func StaticDirectory(nodes ...Node) Resolver { return directory.Static(nodes) }

// HTTPDirectory reads the node list from a registry URL.
func HTTPDirectory(url string) Resolver { return directory.HTTPResolver{URL: url} }

// NewClient builds a client (random 3-hop paths by default; override its fields
// to change the strategy).
func NewClient(dir Resolver, tr Transport, aead AEAD) *Client {
	return client.New(dir, tr, aead)
}

// NewRelay builds a relay from its static keypair, the network AEAD, and the
// transport used to reach downstream hops.
func NewRelay(kp KeyPair, aead AEAD, tr Transport) *Relay {
	return relay.New(kp, aead, tr)
}
