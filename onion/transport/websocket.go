package transport

import (
	"context"
	"errors"
	"net"
)

// WebSocket is a plug-point stub. Back it with a WebSocket library, wrapping the
// connection as a net.Conn, to enable a WebSocket transport (useful for
// browser-reachable or firewall-friendly relays).
type WebSocket struct{}

var errWS = errors.New("transport: WebSocket backend not built in; plug your own")

func (WebSocket) Dial(context.Context, string) (net.Conn, error)       { return nil, errWS }
func (WebSocket) Listen(context.Context, string) (net.Listener, error) { return nil, errWS }
