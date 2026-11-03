/* ingot_wasm.c - two in-browser nodes for the demo page.
 *
 * The page drives two full chains (A and B) through the same consensus
 * code as the native node. "Gossip" is the page calling w_sync(), which
 * delivers each node's main chain to the other - with the link switch
 * off, the chains fork and the next sync reorganizes the shorter one. */
#include <emscripten.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../src/chain.h"
#include "../src/miner.h"
#include "../src/keys.h"
#include "../src/ed25519.h"

static IngotChain *nodes[2];
static unsigned char seeds[2][32];
static char buf[65536];

static void hexn(const unsigned char *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", b[i]);
    out[n * 2] = 0;
}

EMSCRIPTEN_KEEPALIVE
int w_init(unsigned s0, unsigned s1) {
    for (int i = 0; i < 2; i++) {
        nodes[i] = malloc(sizeof *nodes[i]);
        if (!nodes[i])
            return -1;
        ingot_chain_init(nodes[i]);
        /* demo wallets from the page's random seeds */
        for (int k = 0; k < 32; k++)
            seeds[i][k] = (unsigned char)((i ? s1 : s0) >> ((k % 4) * 8) ^ (k * 31 + i * 77));
    }
    return 0;
}

EMSCRIPTEN_KEEPALIVE
const char *w_address(int node) {
    static char addr[2][64];
    unsigned char pk[32];
    ed25519_publickey(seeds[node], pk);
    ingot_address(pk, addr[node], 64);
    return addr[node];
}

static void addr_of(int node, unsigned char out[INGOT_ADDR_HASH_LEN]) {
    unsigned char pk[32];
    ed25519_publickey(seeds[node], pk);
    ingot_addr_hash(pk, out);
}

EMSCRIPTEN_KEEPALIVE
const char *w_mine(int node) {
    IngotChain *c = nodes[node];
    unsigned char addr[INGOT_ADDR_HASH_LEN];
    addr_of(node, addr);
    IngotBlock *b = malloc(sizeof *b);
    if (!b)
        return "{\"ok\":false,\"err\":\"out of memory\"}";
    ingot_miner_template(c, addr, b);
    int found = ingot_miner_grind(b, 1u << 24, NULL);
    IngotErr e = INGOT_ERR_POW;
    if (found)
        e = ingot_chain_add(c, b);
    char hh[65];
    unsigned char h[32];
    ingot_block_hash(b, h);
    hexn(h, 32, hh);
    free(b);
    if (e != INGOT_OK) {
        snprintf(buf, sizeof buf, "{\"ok\":false,\"err\":\"%s\"}", ingot_err_str(e));
        return buf;
    }
    snprintf(buf, sizeof buf,
             "{\"ok\":true,\"height\":%d,\"hash\":\"%s\",\"time\":%u}",
             ingot_chain_height(c), hh, ingot_chain_tip(c)->b.h.time);
    return buf;
}

EMSCRIPTEN_KEEPALIVE
const char *w_send(int from, int to, double amount_coins) {
    IngotChain *c = nodes[from];
    uint64_t amount = (uint64_t)(amount_coins * (double)INGOT_COIN + 0.5);
    if (amount == 0 || amount_coins <= 0)
        return "{\"ok\":false,\"err\":\"bad amount\"}";
    unsigned char my[INGOT_ADDR_HASH_LEN], toaddr[INGOT_ADDR_HASH_LEN];
    addr_of(from, my);
    addr_of(to, toaddr);

    IngotUtxo mine[64];
    int n = 0;
    for (int i = 0; i < INGOT_UTXO_SLOTS && n < 64; i++)
        if (c->utxo[i].used == 1 && memcmp(c->utxo[i].u.addr, my, INGOT_ADDR_HASH_LEN) == 0)
            mine[n++] = c->utxo[i].u;
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (mine[j].amount > mine[i].amount) {
                IngotUtxo t = mine[i];
                mine[i] = mine[j];
                mine[j] = t;
            }
    IngotTx tx;
    memset(&tx, 0, sizeof tx);
    uint64_t got = 0;
    while (got < amount && tx.n_in < INGOT_MAX_TX_IN && tx.n_in < n) {
        memcpy(tx.in[tx.n_in].prev_txid, mine[tx.n_in].txid, 32);
        tx.in[tx.n_in].index = mine[tx.n_in].idx;
        got += mine[tx.n_in].amount;
        tx.n_in++;
    }
    if (got < amount) {
        snprintf(buf, sizeof buf, "{\"ok\":false,\"err\":\"insufficient funds\"}");
        return buf;
    }
    tx.out[0].amount = amount;
    memcpy(tx.out[0].addr, toaddr, INGOT_ADDR_HASH_LEN);
    tx.n_out = 1;
    if (got > amount) {
        tx.out[1].amount = got - amount;
        memcpy(tx.out[1].addr, my, INGOT_ADDR_HASH_LEN);
        tx.n_out = 2;
    }
    for (int i = 0; i < tx.n_in; i++)
        ingot_tx_sign(&tx, i, seeds[from]);
    IngotErr e = ingot_mempool_add(c, &tx);
    if (e != INGOT_OK) {
        snprintf(buf, sizeof buf, "{\"ok\":false,\"err\":\"%s\"}", ingot_err_str(e));
        return buf;
    }
    unsigned char id[32];
    char idhex[65];
    ingot_txid(&tx, id);
    hexn(id, 32, idhex);
    snprintf(buf, sizeof buf, "{\"ok\":true,\"txid\":\"%s\",\"mempool\":%d}",
             idhex, ingot_mempool_size(c));
    return buf;
}

/* deliver every main-chain block of src that dst lacks; return blocks
 * moved and whether dst's tip changed */
static int sync_one(IngotChain *src, IngotChain *dst, int *reorged) {
    unsigned char old_tip[32];
    memcpy(old_tip, ingot_chain_tip(dst)->hash, 32);
    int moved = 0;
    uint32_t tip = (uint32_t)ingot_chain_height(src);
    for (uint32_t h = 0; h <= tip; h++) {
        const IngotNode *node = NULL;
        for (int i = 0; i < src->n_nodes; i++)
            if (src->nodes[i]->main && src->nodes[i]->height == h)
                node = src->nodes[i];
        if (!node)
            continue;
        if (ingot_chain_find(dst, node->hash))
            continue;
        IngotErr e = ingot_chain_add(dst, &node->b);
        if (e == INGOT_OK)
            moved++;
    }
    /* mempool follows the blocks */
    for (int i = 0; i < src->n_mempool; i++)
        ingot_mempool_add(dst, &src->mempool[i].tx);
    *reorged = memcmp(old_tip, ingot_chain_tip(dst)->hash, 32) != 0 && moved > 0;
    return moved;
}

EMSCRIPTEN_KEEPALIVE
const char *w_sync(void) {
    int r1 = 0, r2 = 0;
    int ab = sync_one(nodes[0], nodes[1], &r1);
    int ba = sync_one(nodes[1], nodes[0], &r2);
    snprintf(buf, sizeof buf,
             "{\"a\":%d,\"b\":%d,\"moved\":%d,\"reorg\":%s}",
             ingot_chain_height(nodes[0]), ingot_chain_height(nodes[1]),
             ab + ba, (r1 || r2) ? "true" : "false");
    return buf;
}

EMSCRIPTEN_KEEPALIVE
const char *w_state(int node) {
    IngotChain *c = nodes[node];
    unsigned char addr[INGOT_ADDR_HASH_LEN];
    addr_of(node, addr);
    char tip[65];
    hexn(ingot_chain_tip(c)->hash, 32, tip);
    size_t off = snprintf(buf, sizeof buf,
        "{\"height\":%d,\"balance\":%.8f,\"tip\":\"%s\",\"mempool\":%d,\"blocks\":[",
        ingot_chain_height(c),
        (double)ingot_chain_balance(c, addr) / (double)INGOT_COIN,
        tip, ingot_mempool_size(c));
    /* newest 12 main-chain blocks */
    int shown = 0;
    for (int h = ingot_chain_height(c); h >= 0 && shown < 12; h--, shown++) {
        const IngotNode *n = NULL;
        for (int i = 0; i < c->n_nodes; i++)
            if (c->nodes[i]->main && c->nodes[i]->height == (uint32_t)h)
                n = c->nodes[i];
        if (!n)
            continue;
        char hh[17];
        hexn(n->hash, 8, hh);
        off += snprintf(buf + off, sizeof buf - off, "%s{\"height\":%u,\"hash\":\"%s\",\"txs\":%d,\"time\":%u}",
                        shown ? "," : "", n->height, hh, n->b.n_tx, n->b.h.time);
        if (off > sizeof buf - 256)
            break;
    }
    snprintf(buf + off, sizeof buf - off, "]}");
    return buf;
}

/* tamper with a copy of a main-chain block and offer it back: the
 * chain must reject it */
EMSCRIPTEN_KEEPALIVE
const char *w_tamper(int node, int height) {
    IngotChain *c = nodes[node];
    const IngotNode *n = NULL;
    for (int i = 0; i < c->n_nodes; i++)
        if (c->nodes[i]->main && c->nodes[i]->height == (uint32_t)height)
            n = c->nodes[i];
    if (!n)
        return "{\"ok\":false,\"err\":\"no such main-chain block\"}";
    IngotBlock *evil = malloc(sizeof *evil);
    if (!evil)
        return "{\"ok\":false,\"err\":\"out of memory\"}";
    *evil = n->b;
    evil->tx[0].out[0].amount += 10 * INGOT_COIN;   /* pay yourself extra */
    ingot_merkle(evil, evil->h.merkle);             /* "fix" the merkle root */
    evil->h.nonce = 0;                              /* ...but not the work */
    IngotErr e = ingot_chain_add(c, evil);
    free(evil);
    snprintf(buf, sizeof buf, "{\"ok\":false,\"err\":\"%s\"}", ingot_err_str(e));
    return buf;
}
