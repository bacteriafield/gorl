// Package e2e is an integration test that stands up a directory-free set of
// relays over real TCP and pushes a message through a telescopic circuit,
// exercising every package end to end for each pluggable AEAD.
package e2e

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/bacteriafield/gorl/onion/circuit"
	"github.com/bacteriafield/gorl/onion/crypto"
	"github.com/bacteriafield/gorl/onion/directory"
	"github.com/bacteriafield/gorl/onion/relay"
	"github.com/bacteriafield/gorl/onion/transport"
)

func startRelay(t *testing.T, ctx context.Context, aead crypto.AEAD, handler func([]byte)) directory.Node {
	t.Helper()
	kp, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	tr := transport.TCP{}
	ln, err := tr.Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := relay.New(kp, aead, tr)
	r.Handler = handler
	go r.Serve(ctx, ln)
	return directory.Node{Addr: ln.Addr().String(), OnionKey: kp.Public}
}

func TestEndToEnd(t *testing.T) {
	for _, aead := range []crypto.AEAD{crypto.AESGCM(), crypto.ChaCha20Poly1305()} {
		t.Run(aead.Name(), func(t *testing.T) {
			ctx := t.Context()

			delivered := make(chan []byte, 1)
			path := []directory.Node{
				startRelay(t, ctx, aead, nil),                          // entry
				startRelay(t, ctx, aead, nil),                          // middle
				startRelay(t, ctx, aead, func(m []byte) { delivered <- m }), // exit
			}

			circ, err := circuit.Build(ctx, transport.TCP{}, aead, path)
			if err != nil {
				t.Fatalf("build circuit: %v", err)
			}
			defer circ.Close()

			msg := []byte("hello through the onion")
			if err := circ.Send(msg); err != nil {
				t.Fatalf("send: %v", err)
			}

			select {
			case got := <-delivered:
				if !bytes.Equal(got, msg) {
					t.Fatalf("exit got %q, want %q", got, msg)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for exit delivery")
			}
		})
	}
}

func TestMessageTooLarge(t *testing.T) {
	ctx := t.Context()

	aead := crypto.AESGCM()
	path := []directory.Node{
		startRelay(t, ctx, aead, nil),
		startRelay(t, ctx, aead, nil),
		startRelay(t, ctx, aead, func([]byte) {}),
	}
	circ, err := circuit.Build(ctx, transport.TCP{}, aead, path)
	if err != nil {
		t.Fatalf("build circuit: %v", err)
	}
	defer circ.Close()

	oversized := make([]byte, circuit.MaxMessage(3)+1)
	if err := circ.Send(oversized); err == nil {
		t.Fatal("expected oversized message to be rejected")
	}
}
