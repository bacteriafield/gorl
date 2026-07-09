# gorl — build, test, and run the reference onion-routing daemons.
# The library lives under ./onion; the runnable daemons are ./onion/cmd/*.
SHELL := bash

BIN       := bin
DIR       ?= http://127.0.0.1:9000
DIRD_ADDR ?= 127.0.0.1:9000
HOPS      ?= 3
MSG       ?= hello through the onion

.DEFAULT_GOAL := build
.PHONY: build test check fmt vet tidy dird relay exit send demo clean

## build: compile the three daemons into ./bin
build:
	@mkdir -p $(BIN)
	go build -o $(BIN)/dird     ./onion/cmd/dird
	go build -o $(BIN)/relayd   ./onion/cmd/relayd
	go build -o $(BIN)/onionctl ./onion/cmd/onionctl

## test: race-test the library
test:
	go test -race -count=1 ./onion/...

## check: format, vet, and test
check: fmt vet test

fmt:
	gofmt -w onion

vet:
	go vet ./...

tidy:
	go mod tidy

## dird: run a directory server (foreground)
dird:
	go run ./onion/cmd/dird -addr $(DIRD_ADDR)

## relay: run a middle relay (foreground)
relay:
	go run ./onion/cmd/relayd -dir $(DIR)

## exit: run an exit relay that logs delivered messages (foreground)
exit:
	go run ./onion/cmd/relayd -dir $(DIR) -exit

## send: build a circuit and send a message — make send MSG="hi" HOPS=3
send:
	go run ./onion/cmd/onionctl -dir $(DIR) -hops $(HOPS) -msg "$(MSG)"

## demo: one-shot — start a directory + 3 relays, send a message, show delivery
demo: build
	@bash scripts/demo.sh "$(MSG)" $(HOPS)

## clean: remove built binaries
clean:
	rm -rf $(BIN)
