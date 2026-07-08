// Package circuit builds circuits from the client side: it runs the telescopic
// ntor handshakes hop by hop, then onion-wraps application data for the whole
// path. The relay package is the server-side counterpart.
package circuit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/bacteriafield/gorl/onion/cell"
	"github.com/bacteriafield/gorl/onion/crypto"
	"github.com/bacteriafield/gorl/onion/directory"
	"github.com/bacteriafield/gorl/onion/handshake"
	"github.com/bacteriafield/gorl/onion/session"
	"github.com/bacteriafield/gorl/onion/transport"
)

// Circuit is an established telescopic circuit. Send is not safe for concurrent
// use — this version carries one logical stream per circuit.
type Circuit struct {
	conn     net.Conn
	circID   uint32
	sessions []*session.Session
}

// Build dials the entry hop and telescopically extends the circuit across the
// whole path, running an ntor handshake with each hop in turn.
func Build(ctx context.Context, tr transport.Transport, aead crypto.AEAD, path []directory.Node) (*Circuit, error) {
	if len(path) == 0 {
		return nil, errors.New("circuit: empty path")
	}
	conn, err := tr.Dial(ctx, path[0].Addr)
	if err != nil {
		return nil, fmt.Errorf("circuit: dial entry: %w", err)
	}
	c := &Circuit{conn: conn, circID: randID()}

	s0, err := c.createFirst(aead, path[0]) // hop 0: direct CREATE/CREATED
	if err != nil {
		conn.Close()
		return nil, err
	}
	c.sessions = append(c.sessions, s0)

	for i := 1; i < len(path); i++ { // hops 1..n-1: RELAY EXTEND
		si, err := c.extend(aead, i, path[i])
		if err != nil {
			conn.Close()
			return nil, err
		}
		c.sessions = append(c.sessions, si)
	}
	return c, nil
}

func randID() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	id := binary.BigEndian.Uint32(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

func (c *Circuit) createFirst(aead crypto.AEAD, node directory.Node) (*session.Session, error) {
	st, create, err := handshake.ClientCreate(handshake.NodeID(node.OnionKey), node.OnionKey)
	if err != nil {
		return nil, err
	}
	cl := &cell.Cell{CircID: c.circID, Cmd: cell.CmdCreate}
	copy(cl.Payload[:], create)
	if err := cell.Write(c.conn, cl); err != nil {
		return nil, err
	}
	resp, err := cell.Read(c.conn)
	if err != nil {
		return nil, err
	}
	if resp.Cmd != cell.CmdCreated {
		return nil, fmt.Errorf("circuit: want CREATED, got cmd %d", resp.Cmd)
	}
	keySeed, err := st.Finish(resp.Payload[:handshake.CreatedSize])
	if err != nil {
		return nil, err
	}
	return session.Derive(keySeed, aead)
}

func (c *Circuit) extend(aead crypto.AEAD, i int, node directory.Node) (*session.Session, error) {
	st, create, err := handshake.ClientCreate(handshake.NodeID(node.OnionKey), node.OnionKey)
	if err != nil {
		return nil, err
	}
	body := cell.RelayBody{
		Cmd:      cell.RelayExtend,
		StreamID: 1,
		Data:     cell.EncodeExtend(node.Addr, create),
	}.Marshal()

	if err := c.sendRelay(buildOnion(c.sessions, i-1, body)); err != nil {
		return nil, err
	}

	resp, err := cell.Read(c.conn)
	if err != nil {
		return nil, err
	}
	if resp.Cmd != cell.CmdRelay {
		return nil, fmt.Errorf("circuit: want RELAY, got cmd %d", resp.Cmd)
	}
	back, err := cell.UnpackRelay(&resp.Payload)
	if err != nil {
		return nil, err
	}
	replyBytes, err := peelBackward(c.sessions, i-1, back)
	if err != nil {
		return nil, err
	}
	reply, err := cell.ParseRelayBody(replyBytes)
	if err != nil {
		return nil, err
	}
	if reply.Cmd != cell.RelayExtended {
		return nil, fmt.Errorf("circuit: want EXTENDED, got relay cmd %d", reply.Cmd)
	}
	keySeed, err := st.Finish(reply.Data)
	if err != nil {
		return nil, err
	}
	return session.Derive(keySeed, aead)
}

// Send onion-wraps message as a RELAY DATA cell delivered to the exit hop.
func (c *Circuit) Send(message []byte) error {
	if max := MaxMessage(len(c.sessions)); len(message) > max {
		return fmt.Errorf("circuit: message %d bytes exceeds max %d for %d hops", len(message), max, len(c.sessions))
	}
	body := cell.RelayBody{Cmd: cell.RelayData, StreamID: 1, Data: message}.Marshal()
	return c.sendRelay(buildOnion(c.sessions, len(c.sessions)-1, body))
}

// Close destroys the circuit and closes the entry connection.
func (c *Circuit) Close() error {
	_ = cell.Write(c.conn, &cell.Cell{CircID: c.circID, Cmd: cell.CmdDestroy})
	return c.conn.Close()
}

func (c *Circuit) sendRelay(onion []byte) error {
	cl := &cell.Cell{CircID: c.circID, Cmd: cell.CmdRelay}
	if err := cell.PackRelay(&cl.Payload, onion); err != nil {
		return err
	}
	return cell.Write(c.conn, cl)
}

// buildOnion seals body (a marshaled RelayBody) for the hop at terminalIdx as
// LayerTerminal, then wraps it LayerForward through every hop closer to the
// client (terminalIdx-1 .. 0).
func buildOnion(sessions []*session.Session, terminalIdx int, body []byte) []byte {
	onion := sessions[terminalIdx].EncryptForward(append([]byte{cell.LayerTerminal}, body...))
	for j := terminalIdx - 1; j >= 0; j-- {
		onion = sessions[j].EncryptForward(append([]byte{cell.LayerForward}, onion...))
	}
	return onion
}

// peelBackward removes backward layers 0..upto until the terminal layer,
// returning the terminal RelayBody bytes.
func peelBackward(sessions []*session.Session, upto int, onion []byte) ([]byte, error) {
	for j := 0; j <= upto; j++ {
		plain, err := sessions[j].DecryptBackward(onion)
		if err != nil {
			return nil, err
		}
		if len(plain) < 1 {
			return nil, errors.New("circuit: empty backward layer")
		}
		switch plain[0] {
		case cell.LayerForward:
			onion = plain[1:]
		case cell.LayerTerminal:
			return plain[1:], nil
		default:
			return nil, errors.New("circuit: bad backward layer type")
		}
	}
	return nil, errors.New("circuit: no terminal in backward onion")
}

// MaxMessage is the largest single-cell message for a circuit of the given hop
// count. Multi-cell fragmentation is not implemented.
func MaxMessage(hops int) int {
	if hops < 1 {
		return 0
	}
	// innermost: 1 type byte + 5-byte relay-body header, sealed once (Overhead),
	// then hops-1 forward wraps each add 1 type byte + Overhead.
	return cell.MaxOnion - (1 + 5) - session.Overhead - (hops-1)*(1+session.Overhead)
}
