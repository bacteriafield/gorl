package transport

import (
	"context"
	"net"
)

// TCP is the reference transport backend. In production, wrap it (or plug a
// backend) that provides TLS between hops — the onion length prefix is
// otherwise visible to on-path observers.
type TCP struct{}

func (TCP) Dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func (TCP) Listen(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", addr)
}
