package handshake

import (
	"bytes"
	"testing"

	"github.com/bacteriafield/gorl/onion/crypto"
)

func TestNtorAgree(t *testing.T) {
	static, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	id := NodeID(static.Public)

	cs, create, err := ClientCreate(id, static.Public)
	if err != nil {
		t.Fatal(err)
	}
	created, serverSeed, err := ServerAnswer(static.Private, static.Public, create)
	if err != nil {
		t.Fatal(err)
	}
	clientSeed, err := cs.Finish(created)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientSeed, serverSeed) {
		t.Fatal("client and server derived different KEY_SEED")
	}
}

func TestNtorRejectsTamperedAuth(t *testing.T) {
	static, _ := crypto.GenerateX25519()
	id := NodeID(static.Public)
	cs, create, _ := ClientCreate(id, static.Public)
	created, _, _ := ServerAnswer(static.Private, static.Public, create)

	created[len(created)-1] ^= 0xff // flip a byte of AUTH
	if _, err := cs.Finish(created); err == nil {
		t.Fatal("expected authentication failure on tampered CREATED")
	}
}

func TestNtorRejectsWrongNode(t *testing.T) {
	a, _ := crypto.GenerateX25519()
	b, _ := crypto.GenerateX25519()
	// Client aims at node a, but node b answers.
	_, create, _ := ClientCreate(NodeID(a.Public), a.Public)
	if _, _, err := ServerAnswer(b.Private, b.Public, create); err == nil {
		t.Fatal("expected node-id mismatch to be rejected")
	}
}
