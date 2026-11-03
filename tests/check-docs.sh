#!/bin/sh
# check-docs.sh - the README's claims must match the code. When a pinned
# number changes on purpose, change it here and in README.md together.
set -eu
cd "$(dirname "$0")/.."
fail() { echo "check-docs: $1" >&2; exit 1; }

UNIT=$(./build/test-unit | tail -1 | grep -o '^[0-9]*')
[ "$UNIT" = "85" ] || fail "unit checks: README says 83, binary says $UNIT"
grep -q "85 unit checks" README.md || fail "README no longer says 85 unit checks"

grep -q "7 integration checks" README.md || fail "README no longer says 6 integration checks"
N=$(grep -c '^    ok(' tests/wasm-smoke.js)
[ "$N" = "11" ] || fail "wasm smoke has $N checks, expected 11"

for pin in "INGOT_MAX_BLOCKS    2048" "INGOT_UTXO_SLOTS    16384" \
           "INGOT_MAX_MEMPOOL   256" "INGOT_MAX_BLOCK_TXS 32" \
           "INGOT_MAX_TX_IN 8" "INGOT_MAX_TX_OUT 8" \
           "INGOT_HALVING       1000" "INGOT_RETARGET      100" \
           "INGOT_BLOCK_SPACING 10" "INGOT_BITS_START    0x2000ffffu"; do
  grep -q "$pin" src/*.h || fail "consensus pin missing: $pin"
done
for claim in "2048 blocks" "16384 entries" "256" "(32)" "8 inputs, 8 outputs" \
             "every 1000 blocks" "every 100 blocks" "0x2000ffff" "50 coins"; do
  grep -q "$claim" README.md || fail "README claim missing: $claim"
done
grep -q "https://aditya2375.github.io/ingot/" README.md || fail "README lost the live URL"
grep -q "not constant-time" README.md || fail "README lost the crypto caveat"
grep -q "version byte" README.md || fail "README lost the address-format note"

# no stray AI/tooling mentions anywhere public-facing
! grep -ri --exclude=check-docs.sh "claude\|anthropic\|openai\|chatgpt\|copilot" README.md docs/ src/ wasm/ tests/ \
  || fail "tooling mention found"
echo "check-docs ok"
