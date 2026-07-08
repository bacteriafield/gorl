// Package cell defines the fixed-size wire frame and the (pure, crypto-free)
// framing of the relay payload. Every cell on the wire is exactly Size bytes so
// that a passive observer sees a uniform stream regardless of command or hop.
// No onion peeling happens here — that lives in circuit (build) and relay (peel).
package cell

import (
	"encoding/binary"
	"errors"
)

const (
	PayloadSize = 509
	Size        = 4 + 1 + PayloadSize // CircID + Cmd + Payload = 514
)

// Outer (per-link) cell commands.
const (
	CmdCreate  byte = 1 // begin an ntor handshake with the next hop
	CmdCreated byte = 2 // ntor response
	CmdRelay   byte = 3 // a layered onion payload
	CmdDestroy byte = 4 // tear a circuit down
)

// Cell is a fixed-size link frame identified by a per-link circuit id.
type Cell struct {
	CircID  uint32
	Cmd     byte
	Payload [PayloadSize]byte
}

// Marshal encodes the cell into exactly Size bytes.
func (c *Cell) Marshal() []byte {
	b := make([]byte, Size)
	binary.BigEndian.PutUint32(b[0:4], c.CircID)
	b[4] = c.Cmd
	copy(b[5:], c.Payload[:])
	return b
}

// Unmarshal decodes exactly Size bytes into c.
func (c *Cell) Unmarshal(b []byte) error {
	if len(b) != Size {
		return errors.New("cell: wrong frame length")
	}
	c.CircID = binary.BigEndian.Uint32(b[0:4])
	c.Cmd = b[4]
	copy(c.Payload[:], b[5:])
	return nil
}

// Inner (relay) commands, carried inside a decrypted onion layer.
const (
	RelayExtend   byte = 1 // to the current terminal hop: extend to a new hop
	RelayExtended byte = 2 // the new hop's ntor response, heading back to client
	RelayData     byte = 3 // to the exit: deliver payload
)

// Layer envelope type — the first plaintext byte of a decrypted layer.
const (
	LayerForward  byte = 0 // rest is the inner onion for the next hop
	LayerTerminal byte = 1 // rest is a RelayBody addressed to this hop
)

// MaxOnion is the largest onion (nonce+ciphertext) that fits one relay cell
// after the 2-byte length prefix.
const MaxOnion = PayloadSize - 2

// PackRelay writes Len(2) || onion || zero-pad into a relay cell payload.
func PackRelay(dst *[PayloadSize]byte, onion []byte) error {
	if len(onion) > MaxOnion {
		return errors.New("cell: onion too large for one relay cell")
	}
	*dst = [PayloadSize]byte{}
	binary.BigEndian.PutUint16(dst[0:2], uint16(len(onion)))
	copy(dst[2:], onion)
	return nil
}

// UnpackRelay returns the onion bytes carried by a relay cell payload.
func UnpackRelay(p *[PayloadSize]byte) ([]byte, error) {
	n := int(binary.BigEndian.Uint16(p[0:2]))
	if n > MaxOnion {
		return nil, errors.New("cell: bad onion length")
	}
	out := make([]byte, n)
	copy(out, p[2:2+n])
	return out, nil
}

// RelayBody is the plaintext addressed to a terminal hop (inside LayerTerminal).
type RelayBody struct {
	Cmd      byte
	StreamID uint16
	Data     []byte
}

// Marshal encodes: Cmd(1) || StreamID(2) || Len(2) || Data.
func (b RelayBody) Marshal() []byte {
	out := make([]byte, 5+len(b.Data))
	out[0] = b.Cmd
	binary.BigEndian.PutUint16(out[1:3], b.StreamID)
	binary.BigEndian.PutUint16(out[3:5], uint16(len(b.Data)))
	copy(out[5:], b.Data)
	return out
}

// ParseRelayBody decodes a RelayBody.
func ParseRelayBody(p []byte) (RelayBody, error) {
	if len(p) < 5 {
		return RelayBody{}, errors.New("cell: short relay body")
	}
	n := int(binary.BigEndian.Uint16(p[3:5]))
	if 5+n > len(p) {
		return RelayBody{}, errors.New("cell: relay body length overflow")
	}
	return RelayBody{
		Cmd:      p[0],
		StreamID: binary.BigEndian.Uint16(p[1:3]),
		Data:     append([]byte(nil), p[5:5+n]...),
	}, nil
}

// EncodeExtend packs the RelayExtend payload: addr length-prefixed, then the
// ntor CREATE bytes the terminal hop should relay to the new hop.
func EncodeExtend(addr string, create []byte) []byte {
	out := make([]byte, 2+len(addr)+len(create))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(addr)))
	copy(out[2:], addr)
	copy(out[2+len(addr):], create)
	return out
}

// DecodeExtend reverses EncodeExtend.
func DecodeExtend(data []byte) (addr string, create []byte, err error) {
	if len(data) < 2 {
		return "", nil, errors.New("cell: short extend")
	}
	n := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+n > len(data) {
		return "", nil, errors.New("cell: extend addr overflow")
	}
	return string(data[2 : 2+n]), data[2+n:], nil
}
