# gorl — a pluggable onion-routing library for Go

`gorl` is a reusable base for building anonymity networks, the way `grpc-go` is a
base for RPC. It implements real Tor-style onion routing — **ntor** handshakes,
**telescopic** circuit construction, and fixed-size **cells** — while leaving the
parts that vary between deployments behind interfaces you plug your own code
into.

Messages are wrapped in layers of encryption; each relay peels exactly one layer
and learns only its immediate predecessor and successor. The sender stays
anonymous because no single relay sees both ends.

## Plug points

| Concern | Interface | Ships with |
|---|---|---|
| Transport | `transport.Transport` | `TCP` (reference); `QUIC`, `WebSocket` stubs |
| Layer cipher (AEAD) | `crypto.AEAD` | `AESGCM` (stdlib), `ChaCha20Poly1305` (x/crypto) |
| Node discovery | `directory.Resolver` | `Static`, `HTTPResolver` + a `Registry` server |
| Path selection | `client.PathSelector` | `RandomSelector` |
| Key agreement | `handshake` (ntor) | X25519 via `crypto/ecdh` |

Anything not shipped (a DHT resolver, a QUIC transport, a weighted path
selector) is an interface away — implement the interface and pass it in.

## Packages

```
cmd/           relayd (relay daemon), dird (directory), onionctl (client CLI)
onion/
  cell/        fixed 514-byte frames + framing (pure wire format, no crypto)
  crypto/      X25519, the AEAD interface, HKDF/HMAC
  handshake/   ntor create/created — used by client and relay
  session/     KEY_SEED → directional keys, seal/open with counter nonces
  circuit/     client side: telescopic build + onion layering
  relay/        server side: peel one layer, forward, backward-pump replies
  directory/   resolver (fetch nodes) + registry (nodes announce themselves)
  transport/   the single home of transport, pluggable backends
  client/       high-level: discover → select path → build → send
  e2e/          integration test over real TCP
```

## Quickstart (the daemons)

```bash
# 1. directory
go run ./onion/cmd/dird -addr 127.0.0.1:9000 &

# 2. three relays (–exit lets a relay log what it delivers when it's the exit)
go run ./onion/cmd/relayd -dir http://127.0.0.1:9000 -exit &
go run ./onion/cmd/relayd -dir http://127.0.0.1:9000 -exit &
go run ./onion/cmd/relayd -dir http://127.0.0.1:9000 -exit &

# 3. send a message through a random 3-hop circuit
go run ./onion/cmd/onionctl -dir http://127.0.0.1:9000 -hops 3 -msg "hello"
# → an exit relay logs: exit delivered 5 bytes: "hello"
```

## Library usage

```go
aead := crypto.AESGCM() // every node on the network must agree on this

// A relay: give it a static onion key, the AEAD, and a transport.
kp, _ := crypto.GenerateX25519()
r := relay.New(kp, aead, transport.TCP{})
r.Handler = func(msg []byte) { /* this relay is the exit */ }
ln, _ := transport.TCP{}.Listen(ctx, "127.0.0.1:0")
go r.Serve(ctx, ln)

// A client: discover nodes, then send.
c := client.New(directory.HTTPResolver{URL: "http://dir:9000"}, transport.TCP{}, aead)
c.Hops = 3
c.Send(ctx, []byte("hello through the onion"))
```

## How it works

1. The client dials the entry relay and runs an **ntor** handshake directly
   (`CREATE`/`CREATED`), deriving a shared session.
2. It then **extends** the circuit one hop at a time: each `EXTEND` travels
   onion-wrapped to the current last hop, which runs ntor with the next relay on
   the client's behalf and returns `EXTENDED`. Every intermediate relay adds a
   layer to replies on the way back (the backward pump).
3. To send data, the client wraps a `DATA` cell in one AEAD layer per hop. Each
   relay peels its layer and forwards; the exit peels the last and delivers.

Every cell is a fixed 514 bytes, so a passive observer sees a uniform stream.

## Deliberate limitations (and how to lift them)

These are v1 ceilings, marked in-code and honest about the trade-off:

- **Onion-length leak.** AEAD layers shrink by a tag per hop, so the cleartext
  length prefix reveals *remaining depth* to each relay. Tor avoids this with a
  length-preserving stream cipher (AES-CTR) + an end-to-end digest. Upgrade =
  swap the AEAD for a stream cipher.
- **One-way data.** Fire-and-forget delivery; no reply stream yet. Construction
  itself is bidirectional, so the plumbing for replies exists.
- **One stream per circuit**, single-cell messages (~415 bytes for 3 hops); no
  fragmentation or stream multiplexing.
- **Unauthenticated directory.** The registry is plain HTTP/JSON — a real
  deployment must serve a *signed consensus* so clients can't be fed poisoned
  nodes.
- **Use TLS between hops in production.** The reference `TCP` transport is
  cleartext; wrap it (or plug a TLS/QUIC backend) so on-path observers can't read
  the length prefix.

## Requirements

Go 1.24+ (uses `crypto/hkdf`, `crypto/ecdh`). One external dependency:
`golang.org/x/crypto` (ChaCha20-Poly1305 only; the AES-GCM path is stdlib-only).
```
