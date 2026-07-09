#!/usr/bin/env bash
# Bring up a directory + 3 relays, push one message through a 3-hop circuit,
# confirm it arrives at the exit, then tear everything down. Expects the
# binaries in ./bin (run `make build` first, or use `make demo`).
# Requires: curl, plus the usual coreutils.
set -uo pipefail

MSG="${1:-hello through the onion}"
HOPS="${2:-3}"
DIR_ADDR="127.0.0.1:9000"
DIR_URL="http://$DIR_ADDR"
BIN="./bin"

tmp="$(mktemp -d)"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT

"$BIN/dird" -addr "$DIR_ADDR" >"$tmp/dird.log" 2>&1 &
pids+=($!)
# wait until the directory accepts requests
for _ in $(seq 1 300); do curl -sf "$DIR_URL/nodes" >/dev/null 2>&1 && break; done

for i in 1 2 3; do
	"$BIN/relayd" -listen 127.0.0.1:0 -dir "$DIR_URL" -exit >"$tmp/r$i.log" 2>&1 &
	pids+=($!)
done

echo "== sending \"$MSG\" through $HOPS hops =="
# retry until the relays have registered and the circuit builds
for _ in $(seq 1 300); do
	"$BIN/onionctl" -dir "$DIR_URL" -hops "$HOPS" -msg "$MSG" >"$tmp/ctl.log" 2>&1 && break
done
cat "$tmp/ctl.log"

# the exit logs delivery asynchronously; wait briefly for its line
for _ in $(seq 1 300); do grep -qh "exit delivered" "$tmp"/r*.log 2>/dev/null && break; done
if grep -qh "exit delivered" "$tmp"/r*.log 2>/dev/null; then
	echo "== delivered at exit =="
	grep -h "exit delivered" "$tmp"/r*.log
else
	echo "== NO DELIVERY (something is wrong) =="
	exit 1
fi
