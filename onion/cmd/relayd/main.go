// Command relayd runs an onion relay: it generates a static onion key, registers
// with a directory, and serves circuits over TCP.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/bacteriafield/gorl/onion/crypto"
	"github.com/bacteriafield/gorl/onion/directory"
	"github.com/bacteriafield/gorl/onion/relay"
	"github.com/bacteriafield/gorl/onion/transport"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "relay listen address")
	advertise := flag.String("advertise", "", "address to advertise (defaults to the listen address)")
	dir := flag.String("dir", "http://127.0.0.1:9000", "directory registry URL")
	exit := flag.Bool("exit", false, "log messages delivered when acting as the exit")
	flag.Parse()

	kp, err := crypto.GenerateX25519()
	if err != nil {
		log.Fatal(err)
	}
	tr := transport.TCP{}
	r := relay.New(kp, crypto.AESGCM(), tr)
	if *exit {
		r.Handler = func(msg []byte) { log.Printf("exit delivered %d bytes: %q", len(msg), msg) }
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ln, err := tr.Listen(ctx, *listen)
	if err != nil {
		log.Fatal(err)
	}
	adv := *advertise
	if adv == "" {
		adv = ln.Addr().String()
	}
	log.Printf("relayd on %s (advertising %s), onion key %s", ln.Addr(), adv, hex.EncodeToString(kp.Public))

	if err := directory.Announce(ctx, *dir, directory.Node{Addr: adv, OnionKey: kp.Public}); err != nil {
		log.Printf("warning: directory registration failed: %v", err)
	}
	if err := r.Serve(ctx, ln); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
