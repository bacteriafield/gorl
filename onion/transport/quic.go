package transport

import (
	"context"
	"errors"
	"net"
)

// QUIC is a plug-point stub. Back it with e.g. quic-go, exposing each stream as
// a net.Conn, to enable a QUIC transport.
type QUIC struct{}

var errQUIC = errors.New("transport: QUIC backend not built in; plug your own")

func (QUIC) Dial(context.Context, string) (net.Conn, error)       { return nil, errQUIC }
func (QUIC) Listen(context.Context, string) (net.Listener, error) { return nil, errQUIC }
