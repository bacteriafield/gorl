// Command onionctl is the client CLI: it builds a circuit through relays listed
// by a directory and sends a message to the exit.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"github.com/bacteriafield/gorl/onion/client"
	"github.com/bacteriafield/gorl/onion/crypto"
	"github.com/bacteriafield/gorl/onion/directory"
	"github.com/bacteriafield/gorl/onion/transport"
)

func main() {
	dir := flag.String("dir", "http://127.0.0.1:9000", "directory registry URL")
	hops := flag.Int("hops", 3, "number of relays in the circuit")
	msg := flag.String("msg", "", "message to send (default: read stdin)")
	flag.Parse()

	message := []byte(*msg)
	if *msg == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		message = b
	}

	c := client.New(directory.HTTPResolver{URL: *dir}, transport.TCP{}, crypto.AESGCM())
	c.Hops = *hops

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Send(ctx, message); err != nil {
		log.Fatalf("send: %v", err)
	}
	log.Printf("sent %d bytes through %d hops", len(message), *hops)
}
