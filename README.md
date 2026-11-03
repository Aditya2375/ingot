# ingot

A small blockchain from scratch in C: proof of work, a UTXO ledger, Ed25519
wallets, compact-target difficulty adjustments, work-based reorganizations,
and TCP peer sync - plus an interactive two-node demo that runs the same
consensus code in your browser.

**[Live demo](https://aditya2375.github.io/ingot/)** - two nodes side by side:
mine, send, cut the link to fork, sync and watch the heavier fork win.

No dependencies beyond libc and an emscripten SDK for the web build.

## Try it

```sh
make build/ingot            # the CLI
build/ingot wallet new      # creates ~/.ingot/wallet, prints your i... address
build/ingot mine 5          # mine five blocks offline
build/ingot balance         # 250.0 INGOT
```

Two nodes on one machine:

```sh
build/ingot node --port 9333 --mine            # terminal 1
build/ingot node --port 9334 --peer 127.0.0.1:9333   # terminal 2
build/ingot send iFriendAddress... 5           # terminal 3: 5 coins to a friend
```

The browser demo is `docs/index.html` (also rebuilt from source with
`sh wasm/build.sh`, then serve `docs/`).

## How it works

**Transactions.** An input spends a previous output: it carries the spender's
full Ed25519 public key and a signature over the whole transaction with every
signature zeroed (`src/tx.c`). The txid commits to the signatures, so a signed
transaction is immutable. An output is an amount plus a 20-byte address hash
(`base58check(0x66 || sha256(pubkey)[:20])` - the `0x66` version byte is why
addresses start with `i`).

**Blocks.** A header is `version || prev || merkle || time || bits || nonce`;
the block hash is double-SHA-256 of those 80 bytes (`src/block.c`). The merkle
root pairs txids with sha256d, duplicating a lone leaf per level. Proof of
work compares the hash, as a big-endian 256-bit number, against a target
encoded in Bitcoin's compact `bits` form.

**Consensus** (`src/chain.c`):

- subsidy 50 coins, halving every 1000 blocks
- difficulty retargets every 100 blocks from the actual timespan, clamped to
  4x per step, never easier than the start bits `0x2000ffff` (~2^16 hashes)
- the valid chain is the one with the most cumulative work, computed with
  128-bit integer division - not the longest
- a heavier fork triggers a reorganization that rebuilds the UTXO set by
  replaying from genesis; if any block on the new branch fails validation the
  old chain is restored untouched
- the coinbase input carries the block height (BIP34-style), so no two
  coinbases can ever share a txid and overwrite each other in the UTXO map
- block timestamps must be monotonic and within two hours of wall clock;
  the miner paces itself to real time so a fast machine cannot walk header
  times past that window
- the mempool is fee-ordered with cheapest-first eviction at capacity, and
  every entry is rechecked against the UTXO set after each connected block

**Networking** (`src/net.c`). Length-prefixed messages over TCP
(`HELLO / GETBLOCKS / BLOCK / TX`), an epoll event loop, push gossip: every
new valid block or transaction is relayed to every peer but the sender.
A peer that announces a taller tip gets a `GETBLOCKS` from our height;
orphans trigger the same request. Writes are queued per peer and `EPOLLOUT`
is armed at queue time - a peer that never speaks still gets its bytes.

**Persistence** (`src/store.c`). Blocks are appended to
`~/.ingot/blocks.dat` as length-prefixed records; startup replays the file
through the same validation as network input, so a torn tail or a flipped
byte is caught the same way. Out-of-order records (orphans) are skipped and
connect when their parents arrive later in the file.

**Web demo** (`wasm/`, `docs/`). The same `chain.c`, compiled with
emscripten, runs two independent nodes in the page. "Gossip" is JavaScript
delivering each node's main chain to the other; with the link switch off the
chains fork, and the next sync reorganizes the shorter branch. The forgery
button rewrites an old coinbase and offers it back to the node, which
rejects it at the proof-of-work check.

## Deliberate simplifications

This is a teaching blockchain, not money:

- **Ed25519 is a reference-style implementation and is not constant-time.**
  Fine for a demo, wrong for real keys.
- Addresses hash with SHA-256 only (no RIPEMD-160).
- The block index (2048 blocks), UTXO map (16384 entries), mempool (256
  transactions), per-block transaction count (32) and transaction shape
  (8 inputs, 8 outputs) are fixed compile-time caps.
- No coinbase maturity, no script system, no P2P discovery, no peer scoring;
  gossip is push-only.
- The difficulty retarget keeps 64 bits of target precision.
- The node is single-threaded; Linux only (epoll).

## Development

```sh
make test            # 83 unit checks (hashes, signatures, PoW, reorgs, mempool)
make sanitize        # the same under ASan/UBSan, plus a fuzz pass
sh tests/run-tests.sh   # CLI + two-node integration
python3 tests/fuzz.py   # parser fuzzing
sh wasm/build.sh && node tests/wasm-smoke.js   # browser build + smoke
```

Layout: `src/` the C core (crypto, transactions, blocks, chain, miner,
store, net, CLI), `wasm/` the emscripten wrapper, `docs/` the demo page,
`tests/` unit, integration, fuzz and smoke suites.

83 unit checks, 6 integration checks, all green; CI runs every suite on
every push.
