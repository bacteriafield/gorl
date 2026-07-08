// Package transport abstracts the byte pipe between nodes. It is the single
// home of transport concerns, with pluggable backends. TCP is the reference
// implementation; QUIC and WebSocket are stubs left as plug points.
package transport

import (
	"context"
	"net"
)

// Transport is the pluggable connection backend. The signatures mirror the net
// package so any stream transport — TCP, QUIC streams, WebSocket, libp2p — can
// satisfy it by returning net.Conn-shaped pipes.
type Transport interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Listen(ctx context.Context, addr string) (net.Listener, error)
}
