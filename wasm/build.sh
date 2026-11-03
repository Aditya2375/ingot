#!/bin/sh
# Rebuild the browser demo strictly from source. Requires emsdk on PATH.
set -eu
cd "$(dirname "$0")/.."
emcc -O2 -Isrc \
  src/sha256.c src/sha512.c src/ed25519.c src/base58.c src/keys.c \
  src/tx.c src/block.c src/chain.c src/miner.c wasm/ingot_wasm.c \
  -o docs/3-ingot-v2.js \
  -sEXPORTED_FUNCTIONS='["_w_init","_w_address","_w_mine","_w_send","_w_sync","_w_state","_w_tamper"]' \
  -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
  -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=33554432 \
  -sMODULARIZE=1 -sEXPORT_NAME=createIngot --no-entry

# Keep the stable loader URL; version the corrected binary without removing the old asset.
mv docs/3-ingot-v2.js docs/ingot.js
