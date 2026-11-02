#include "miner.h"
#include <string.h>
#include <stdlib.h>

static int fee_cmp(const void *a, const void *b) {
    const IngotMempoolEntry *ea = a, *eb = b;
    if (ea->fee < eb->fee) return 1;
    if (ea->fee > eb->fee) return -1;
    return 0;
}

void ingot_miner_template(IngotChain *c, const unsigned char cb_addr[INGOT_ADDR_HASH_LEN],
                          IngotBlock *out) {
    memset(out, 0, sizeof *out);
    uint32_t height = (uint32_t)ingot_chain_height(c) + 1;
    out->h.version = 1;
    memcpy(out->h.prev, ingot_chain_tip(c)->hash, 32);
    out->h.bits = ingot_chain_next_bits(c);
    out->h.time = ingot_chain_tip(c)->b.h.time + 1;   /* monotonic; grind bumps it */

    /* mempool, highest fee first */
    IngotMempoolEntry pool[INGOT_MAX_MEMPOOL];
    int n = c->n_mempool;
    memcpy(pool, c->mempool, sizeof(IngotMempoolEntry) * (size_t)n);
    qsort(pool, (size_t)n, sizeof *pool, fee_cmp);

    uint64_t fees = 0;
    int k = 1;
    for (int i = 0; i < n && k < INGOT_MAX_BLOCK_TXS; i++) {
        out->tx[k++] = pool[i].tx;
        fees += pool[i].fee;
    }
    out->n_tx = k;
    IngotTx *cb = &out->tx[0];
    cb->coinbase = 1;
    cb->n_in = 1;
    cb->in[0].index = height;
    cb->n_out = 1;
    cb->out[0].amount = ingot_subsidy(height) + fees;
    memcpy(cb->out[0].addr, cb_addr, INGOT_ADDR_HASH_LEN);
}

int ingot_miner_grind(IngotBlock *b, uint32_t max_tries, uint32_t (*time_fn)(void)) {
    unsigned char hash[32], target[32];
    ingot_bits_to_target(b->h.bits, target);
    ingot_merkle(b, b->h.merkle);   /* the txs never change while grinding */
    for (uint32_t i = 0; i < max_tries; i++) {
        if (time_fn) {
            uint32_t now = time_fn();
            if (now > b->h.time)
                b->h.time = now;
        }
        b->h.nonce = i;
        ingot_block_hash(b, hash);
        if (ingot_hash_meets(hash, target))
            return 1;
    }
    return 0;
}

IngotErr ingot_mine_once(IngotChain *c, const unsigned char cb_addr[INGOT_ADDR_HASH_LEN],
                         uint32_t max_tries, uint32_t (*time_fn)(void), IngotBlock *out) {
    ingot_miner_template(c, cb_addr, out);
    if (!ingot_miner_grind(out, max_tries, time_fn))
        return INGOT_ERR_POW;
    return ingot_chain_add(c, out);
}
