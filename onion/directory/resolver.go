// Package directory discovers relays. A Resolver fetches node descriptors; a
// Registry (see registry.go) is the server relays announce themselves to. The
// default backends use HTTP+JSON over an in-memory store — swap in a DHT,
// database, or signed consensus by implementing Resolver.
package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Node is a relay descriptor: where to reach it and its static onion key
// (the ntor "B"). The node id is derived from OnionKey by the handshake package,
// so it is never trusted from the wire.
type Node struct {
	Addr     string `json:"addr"`
	OnionKey []byte `json:"onion_key"`
}

// Resolver is the pluggable node-discovery backend.
type Resolver interface {
	Nodes(ctx context.Context) ([]Node, error)
}

// Static is a fixed node list (tests, small deployments, bootstrap sets).
type Static []Node

func (s Static) Nodes(context.Context) ([]Node, error) { return s, nil }

// HTTPResolver reads the node list from a Registry over HTTP.
type HTTPResolver struct {
	URL    string // base URL of the registry, e.g. http://dir:9000
	Client *http.Client
}

func (r HTTPResolver) Nodes(ctx context.Context) ([]Node, error) {
	c := r.Client
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL+"/nodes", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory: list status %s", resp.Status)
	}
	var nodes []Node
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// Announce publishes a node descriptor to a registry (used by relays at start).
func Announce(ctx context.Context, registryURL string, n Node) error {
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registryURL+"/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("directory: register status %s", resp.Status)
	}
	return nil
}
