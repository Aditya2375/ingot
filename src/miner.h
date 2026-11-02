/* miner.h - candidate assembly and nonce grinding. */
#ifndef INGOT_MINER_H
#define INGOT_MINER_H

#include "chain.h"

/* Build a candidate block on the current tip: a coinbase paying
 * subsidy plus fees to cb_addr, then as many mempool transactions as
 * fit, highest fee first. */
void ingot_miner_template(IngotChain *c, const unsigned char cb_addr[INGOT_ADDR_HASH_LEN],
                          IngotBlock *out);

/* Grind the nonce until the block meets its target or tries run out.
 * Returns 1 on success. time_fn supplies wall-clock seconds so the
 * wasm build can pass a JavaScript clock; the header time is bumped
 * whenever it moves, which restarts no work because the nonce covers
 * the whole 32-bit range per second at these difficulties. */
int ingot_miner_grind(IngotBlock *b, uint32_t max_tries, uint32_t (*time_fn)(void));

/* One full mining step: template, grind, and connect on success.
 * Returns INGOT_OK with the new block in out, or an error. */
IngotErr ingot_mine_once(IngotChain *c, const unsigned char cb_addr[INGOT_ADDR_HASH_LEN],
                         uint32_t max_tries, uint32_t (*time_fn)(void), IngotBlock *out);

#endif
