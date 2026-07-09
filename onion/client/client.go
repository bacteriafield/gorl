// Package client is the high-level entry point: discover nodes, select a path,
// build a circuit, and send a message anonymously.
package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/bacteriafield/gorl/onion/circuit"
	"github.com/bacteriafield/gorl/onion/crypto"
	"github.com/bacteriafield/gorl/onion/directory"
	"github.com/bacteriafield/gorl/onion/transport"
)

// PathSelector chooses an ordered path from the available nodes. It is the
// pluggable path-selection strategy.
type PathSelector interface {
	Select(nodes []directory.Node, hops int) ([]directory.Node, error)
}

// Client wires the pluggable pieces together.
type Client struct {
	Resolver  directory.Resolver
	Transport transport.Transport
	AEAD      crypto.AEAD
	Selector  PathSelector
	Hops      int
}

// New returns a Client with sensible defaults (random 3-hop paths). Override any
// field before use.
func New(resolver directory.Resolver, tr transport.Transport, aead crypto.AEAD) *Client {
	return &Client{
		Resolver:  resolver,
		Transport: tr,
		AEAD:      aead,
		Selector:  RandomSelector{},
		Hops:      3,
	}
}

// Dial discovers nodes, selects a path, and builds a circuit ready for Send.
func (c *Client) Dial(ctx context.Context) (*circuit.Circuit, error) {
	nodes, err := c.Resolver.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	path, err := c.Selector.Select(nodes, c.Hops)
	if err != nil {
		return nil, err
	}
	return circuit.Build(ctx, c.Transport, c.AEAD, path)
}

// Send builds a fresh circuit, sends one message, and tears it down.
func (c *Client) Send(ctx context.Context, message []byte) error {
	circ, err := c.Dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = circ.Close() }()
	return circ.Send(message)
}

// RandomSelector picks distinct nodes uniformly at random (crypto/rand). It is
// the default path-selection strategy.
type RandomSelector struct{}

func (RandomSelector) Select(nodes []directory.Node, hops int) ([]directory.Node, error) {
	if hops < 1 {
		return nil, errors.New("client: hops must be >= 1")
	}
	if len(nodes) < hops {
		return nil, fmt.Errorf("client: need %d nodes, directory has %d", hops, len(nodes))
	}
	pool := append([]directory.Node(nil), nodes...)
	for i := len(pool) - 1; i > 0; i-- { // Fisher–Yates
		j := randInt(i + 1)
		pool[i], pool[j] = pool[j], pool[i]
	}
	return pool[:hops], nil
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return int(v.Int64())
}
