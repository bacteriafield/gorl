# gorl — build, test, and run the reference onion-routing daemons.
# Library packages live under ./onion; the runnable daemons under ./cmd.
SHELL := bash

BIN       := bin
DIR       ?= http://127.0.0.1:9000
DIRD_ADDR ?= 127.0.0.1:9000
HOPS      ?= 3
MSG       ?= hello through the onion

.DEFAULT_GOAL := build
.PHONY: build test check fmt vet tidy dird relay exit send demo clean

## build: compile all daemons into ./bin
build:
	@mkdir -p $(BIN)
	go build -o $(BIN)/ ./cmd/...

## test: race-test the whole module
test:
	go test -race -count=1 ./...

## check: format, vet, and test
check: fmt vet test

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

## dird: run a directory server (foreground)
dird:
	go run ./cmd/dird -addr $(DIRD_ADDR)

## relay: run a middle relay (foreground)
relay:
	go run ./cmd/relayd -dir $(DIR)

## exit: run an exit relay that logs delivered messages (foreground)
exit:
	go run ./cmd/relayd -dir $(DIR) -exit

## send: build a circuit and send a message — make send MSG="hi" HOPS=3
send:
	go run ./cmd/onionctl -dir $(DIR) -hops $(HOPS) -msg "$(MSG)"

## demo: one-shot — directory + 3 relays, send a message, show delivery
demo: build
	@bash scripts/demo.sh "$(MSG)" $(HOPS)

## clean: remove built binaries
clean:
	rm -rf $(BIN)
