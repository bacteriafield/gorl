// Command dird runs the directory registry: relays POST /register, clients GET
// /nodes.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/bacteriafield/gorl/onion/directory"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	flag.Parse()

	reg := directory.NewRegistry()
	log.Printf("dird listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, reg.Handler()))
}
