// Package relay is the server side of a circuit: it terminates ntor handshakes,
// peels one onion layer per forward cell, and forwards to the next hop. When it
// is the exit (a DATA cell terminates here) it hands the payload to a Handler.
package relay

import (
	"context"
	"net"
	"sync"

	"github.com/bacteriafield/gorl/onion/cell"
	"github.com/bacteriafield/gorl/onion/crypto"
	"github.com/bacteriafield/gorl/onion/handshake"
	"github.com/bacteriafield/gorl/onion/session"
	"github.com/bacteriafield/gorl/onion/transport"
)

// Relay is an onion router. Construct with New, then run Serve on a listener.
type Relay struct {
	priv, pub []byte
	aead      crypto.AEAD
	tr        transport.Transport
	// Handler receives the plaintext of every DATA cell that terminates here
	// (i.e. when this relay is the exit of a circuit). Optional.
	Handler func(msg []byte)
}

// New builds a relay from its static onion keypair, the network AEAD, and the
// transport used to reach downstream hops.
func New(kp crypto.KeyPair, aead crypto.AEAD, tr transport.Transport) *Relay {
	return &Relay{priv: kp.Private, pub: kp.Public, aead: aead, tr: tr}
}

// PublicKey returns the relay's static onion public key (its ntor "B").
func (r *Relay) PublicKey() []byte { return r.pub }

// Serve accepts connections until ln is closed or ctx is done.
func (r *Relay) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handleConn(ctx, conn)
	}
}

// circ is per-circuit state on one inbound connection.
type circ struct {
	inID    uint32
	sess    *session.Session
	outConn net.Conn // downstream hop, set once this circuit is extended
	outID   uint32
}

const outID uint32 = 1 // one dedicated downstream conn per circuit ⇒ constant id

func (r *Relay) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	circs := map[uint32]*circ{}
	var writeMu sync.Mutex // serializes writes to this inbound conn
	for {
		c, err := cell.Read(conn)
		if err != nil {
			return
		}
		switch c.Cmd {
		case cell.CmdCreate:
			r.onCreate(conn, &writeMu, circs, c)
		case cell.CmdRelay:
			r.onRelay(ctx, conn, &writeMu, circs, c)
		case cell.CmdDestroy:
			if cc := circs[c.CircID]; cc != nil && cc.outConn != nil {
				_ = cell.Write(cc.outConn, &cell.Cell{CircID: cc.outID, Cmd: cell.CmdDestroy})
				_ = cc.outConn.Close()
			}
			delete(circs, c.CircID)
		}
	}
}

func (r *Relay) onCreate(conn net.Conn, writeMu *sync.Mutex, circs map[uint32]*circ, c *cell.Cell) {
	created, keySeed, err := handshake.ServerAnswer(r.priv, r.pub, c.Payload[:handshake.CreateSize])
	if err != nil {
		return
	}
	sess, err := session.Derive(keySeed, r.aead)
	if err != nil {
		return
	}
	circs[c.CircID] = &circ{inID: c.CircID, sess: sess}
	reply := &cell.Cell{CircID: c.CircID, Cmd: cell.CmdCreated}
	copy(reply.Payload[:], created)
	writeMu.Lock()
	_ = cell.Write(conn, reply)
	writeMu.Unlock()
}

func (r *Relay) onRelay(ctx context.Context, conn net.Conn, writeMu *sync.Mutex, circs map[uint32]*circ, c *cell.Cell) {
	cc := circs[c.CircID]
	if cc == nil {
		return
	}
	onion, err := cell.UnpackRelay(&c.Payload)
	if err != nil {
		return
	}
	plain, err := cc.sess.DecryptForward(onion)
	if err != nil || len(plain) < 1 {
		return
	}
	switch plain[0] {
	case cell.LayerForward:
		if cc.outConn == nil {
			return // nowhere to forward; drop
		}
		fwd := &cell.Cell{CircID: cc.outID, Cmd: cell.CmdRelay}
		if err := cell.PackRelay(&fwd.Payload, plain[1:]); err != nil {
			return
		}
		_ = cell.Write(cc.outConn, fwd) // sole forward writer for outConn
	case cell.LayerTerminal:
		body, err := cell.ParseRelayBody(plain[1:])
		if err != nil {
			return
		}
		r.onTerminal(ctx, conn, writeMu, cc, body)
	}
}

func (r *Relay) onTerminal(ctx context.Context, conn net.Conn, writeMu *sync.Mutex, cc *circ, body cell.RelayBody) {
	switch body.Cmd {
	case cell.RelayData:
		if r.Handler != nil {
			r.Handler(body.Data)
		}
	case cell.RelayExtend:
		if cc.outConn != nil {
			return // already extended
		}
		addr, create, err := cell.DecodeExtend(body.Data)
		if err != nil {
			return
		}
		out, err := r.tr.Dial(ctx, addr)
		if err != nil {
			return
		}
		createCell := &cell.Cell{CircID: outID, Cmd: cell.CmdCreate}
		copy(createCell.Payload[:], create)
		if err := cell.Write(out, createCell); err != nil {
			_ = out.Close()
			return
		}
		resp, err := cell.Read(out) // synchronous CREATED, before the pump starts
		if err != nil || resp.Cmd != cell.CmdCreated {
			_ = out.Close()
			return
		}
		extended := cell.RelayBody{
			Cmd:      cell.RelayExtended,
			StreamID: body.StreamID,
			Data:     append([]byte(nil), resp.Payload[:handshake.CreatedSize]...),
		}.Marshal()
		onion := cc.sess.EncryptBackward(append([]byte{cell.LayerTerminal}, extended...))
		r.sendBackward(conn, writeMu, cc.inID, onion)

		cc.outConn = out
		cc.outID = outID
		go r.backwardPump(conn, writeMu, cc)
	}
}

// backwardPump carries downstream cells back toward the client, adding this
// relay's backward layer to each.
func (r *Relay) backwardPump(inConn net.Conn, writeMu *sync.Mutex, cc *circ) {
	for {
		c, err := cell.Read(cc.outConn)
		if err != nil {
			return
		}
		if c.Cmd != cell.CmdRelay {
			continue
		}
		inner, err := cell.UnpackRelay(&c.Payload)
		if err != nil {
			continue
		}
		onion := cc.sess.EncryptBackward(append([]byte{cell.LayerForward}, inner...))
		r.sendBackward(inConn, writeMu, cc.inID, onion)
	}
}

func (r *Relay) sendBackward(conn net.Conn, writeMu *sync.Mutex, circID uint32, onion []byte) {
	c := &cell.Cell{CircID: circID, Cmd: cell.CmdRelay}
	if err := cell.PackRelay(&c.Payload, onion); err != nil {
		return
	}
	writeMu.Lock()
	_ = cell.Write(conn, c)
	writeMu.Unlock()
}
