#!/bin/sh
# run-tests.sh - end-to-end CLI and two-node tests against a scratch HOME.
set -eu
cd "$(dirname "$0")/.."

BIN=${BIN:-build/ingot}
T=$(mktemp -d)
trap 'pkill -x ingot 2>/dev/null || true; rm -rf "$T"' EXIT
PASS=0
ok() { PASS=$((PASS + 1)); echo "ok $PASS - $1"; }
die() { echo "not ok - $1" >&2; exit 1; }

make -s "$BIN" >/dev/null 2>&1 || make -s >/dev/null

# --- single-node CLI ---
HOME=$T/a $BIN wallet new >/dev/null
A_ADDR=$(HOME=$T/a $BIN address)
case $A_ADDR in i*) ok "address starts with i";; *) die "address shape: $A_ADDR";; esac

HOME=$T/a $BIN mine 3 >/dev/null
OUT=$(HOME=$T/a $BIN balance)
[ "$OUT" = "150.0 INGOT (height 3)" ] || die "balance after mining: $OUT"
ok "mine 3, balance 150"

OUT=$(HOME=$T/a $BIN show 1)
echo "$OUT" | grep -q "reward:  50.0" || die "show 1: $OUT"
ok "show prints the block"

# --- two-node sync + send ---
HOME=$T/b $BIN wallet new >/dev/null
B_ADDR=$(HOME=$T/b $BIN address)

HOME=$T/a $BIN node --port 9511 --mine >$T/nodeA.log 2>&1 &
sleep 1
HOME=$T/b $BIN node --port 9512 --peer 127.0.0.1:9511 >$T/nodeB.log 2>&1 &
sleep 3

OUT=$(HOME=$T/b $BIN balance "$A_ADDR")
case $OUT in "0.0"*) die "B did not sync A's chain: $OUT";; esac
ok "second node syncs the chain"

HOME=$T/a INGOT_PORT=9511 $BIN send "$B_ADDR" 5 >/dev/null
sleep 4
OUT=$(HOME=$T/b $BIN balance)
case $OUT in "5.0 INGOT"*) ;; *) die "B balance after send: $OUT";; esac
ok "signed send relays, mines and lands on the other node"

pkill -x ingot 2>/dev/null || true
sleep 0.2

# --- persistence: a fresh process replays the store ---
OUT=$(HOME=$T/a $BIN balance)
case $OUT in *INGOT*) ok "store replays after restart ($OUT)";; *) die "replay: $OUT";; esac

# --- fork resolution: divergent chains reorg over TCP ---
HOME=$T/fa $BIN wallet new >/dev/null
HOME=$T/fb $BIN wallet new >/dev/null
HOME=$T/fa $BIN mine 3 >/dev/null
HOME=$T/fb $BIN mine 5 >/dev/null

HOME=$T/fa $BIN node --port 9521 >$T/forkA.log 2>&1 &
sleep 1
HOME=$T/fb $BIN node --port 9522 --peer 127.0.0.1:9521 >$T/forkB.log 2>&1 &
sleep 3

OUT=$(HOME=$T/fa $BIN balance)
case $OUT in *"(height 5)"*) ;; *) die "heavier fork did not resolve over TCP: $OUT";; esac
ok "a heavier fork resolves over TCP (A reorgs to height 5)"

pkill -x ingot 2>/dev/null || true
sleep 0.2

echo "all $PASS integration checks passed"
