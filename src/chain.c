#include "chain.h"
#include "sha256.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

/* ---------- UTXO map: open addressing, linear probe ---------- */

static uint32_t utxo_hash(const unsigned char key[36]) {
    unsigned char d[32];
    sha256(key, 36, d);
    uint32_t h;
    memcpy(&h, d, 4);
    return h % INGOT_UTXO_SLOTS;
}

static IngotUtxoSlot *utxo_find_slot(IngotChain *c, const unsigned char key[36], int for_insert) {
    uint32_t h = utxo_hash(key);
    IngotUtxoSlot *tomb = NULL;
    for (uint32_t i = 0; i < INGOT_UTXO_SLOTS; i++) {
        IngotUtxoSlot *s = &c->utxo[(h + i) % INGOT_UTXO_SLOTS];
        if (s->used == 0)
            return for_insert && tomb ? tomb : s;
        if (s->used == 2) {
            if (!tomb) tomb = s;
            continue;
        }
        if (memcmp(s->key, key, 36) == 0)
            return s;
    }
    return tomb;
}

static void utxo_make_key(unsigned char key[36], const unsigned char txid[32], uint32_t idx) {
    memcpy(key, txid, 32);
    key[32] = (unsigned char)(idx >> 24);
    key[33] = (unsigned char)(idx >> 16);
    key[34] = (unsigned char)(idx >> 8);
    key[35] = (unsigned char)idx;
}

static int utxo_put(IngotChain *c, const IngotUtxo *u) {
    unsigned char key[36];
    utxo_make_key(key, u->txid, u->idx);
    IngotUtxoSlot *s = utxo_find_slot(c, key, 1);
    if (!s) return -1;
    if (s->used != 1) c->utxo_count++;
    s->used = 1;
    memcpy(s->key, key, 36);
    s->u = *u;
    return 0;
}

static void utxo_del(IngotChain *c, const unsigned char txid[32], uint32_t idx) {
    unsigned char key[36];
    utxo_make_key(key, txid, idx);
    IngotUtxoSlot *s = utxo_find_slot(c, key, 0);
    if (s && s->used == 1) {
        s->used = 2;
        c->utxo_count--;
    }
}

const IngotUtxo *ingot_chain_utxo(const IngotChain *c,
                                  const unsigned char txid[32], uint32_t idx) {
    unsigned char key[36];
    utxo_make_key(key, txid, idx);
    uint32_t h = utxo_hash(key);
    for (uint32_t i = 0; i < INGOT_UTXO_SLOTS; i++) {
        const IngotUtxoSlot *s = &c->utxo[(h + i) % INGOT_UTXO_SLOTS];
        if (s->used == 0) return NULL;
        if (s->used == 1 && memcmp(s->key, key, 36) == 0) return &s->u;
    }
    return NULL;
}

uint64_t ingot_chain_balance(const IngotChain *c, const unsigned char addr[INGOT_ADDR_HASH_LEN]) {
    uint64_t total = 0;
    for (int i = 0; i < INGOT_UTXO_SLOTS; i++)
        if (c->utxo[i].used == 1 && memcmp(c->utxo[i].u.addr, addr, INGOT_ADDR_HASH_LEN) == 0)
            total += c->utxo[i].u.amount;
    return total;
}

/* ---------- consensus parameters ---------- */

#define INGOT_GENESIS_TIME 1767225600u   /* 2026-01-01T00:00:00Z */

uint64_t ingot_subsidy(uint32_t height) {
    uint32_t halvings = height / INGOT_HALVING;
    if (halvings >= 64) return 0;
    return INGOT_SUBSIDY >> halvings;
}

/* Scale a 256-bit target by num/den keeping the top 64 significant
 * bits. k is the byte offset (from the most significant end) of the
 * window; sliding the window keeps the arithmetic exact at the edges. */
static void target_scale(const unsigned char t[32], uint64_t num, uint64_t den,
                         unsigned char out[32]) {
    int k = 0;
    while (k < 32 && t[k] == 0) k++;
    uint64_t m = 0;
    for (int i = 0; i < 8 && k + i < 32; i++)
        m = m << 8 | t[k + i];
    unsigned __int128 r = (unsigned __int128)m * num;
    if (den)
        r = r / den;
    while (r >= ((unsigned __int128)1 << 64)) {   /* slide the window left */
        r >>= 8;
        k--;
    }
    while (r && r < ((unsigned __int128)1 << 56) && k + 8 < 32) { /* slide right */
        r <<= 8;
        k++;
    }
    memset(out, 0, 32);
    for (int i = 7; i >= 0; i--) {
        if (k + i >= 0 && k + i < 32)
            out[k + i] = (unsigned char)((uint64_t)r >> ((7 - i) * 8));
    }
}

static void target_floor(unsigned char t[32]) {
    unsigned char start[32];
    ingot_bits_to_target(INGOT_BITS_START, start);
    if (memcmp(t, start, 32) > 0)   /* never easier than the start */
        memcpy(t, start, 32);
}

/* The bits a child of node pi must carry. */
static uint32_t bits_after(const IngotChain *c, int pi) {
    const IngotNode *p = c->nodes[pi];
    uint32_t h = p->height + 1;
    if (h % INGOT_RETARGET != 0)
        return p->b.h.bits;
    /* retarget: timespan of the last INGOT_RETARGET blocks on this branch */
    int first = pi;
    for (int i = 0; i < INGOT_RETARGET - 1 && c->nodes[first]->parent >= 0; i++)
        first = c->nodes[first]->parent;
    uint32_t span = p->b.h.time - c->nodes[first]->b.h.time;
    uint32_t expect = INGOT_BLOCK_SPACING * INGOT_RETARGET;
    if (span < expect / 4) span = expect / 4;
    if (span > expect * 4) span = expect * 4;
    unsigned char t[32], nt[32];
    ingot_bits_to_target(p->b.h.bits, t);
    target_scale(t, span, expect, nt);
    target_floor(nt);
    return ingot_target_to_bits(nt);
}

uint32_t ingot_chain_next_bits(const IngotChain *c) {
    return bits_after(c, c->tip);
}

/* ---------- block index ---------- */

static int find_node(const IngotChain *c, const unsigned char hash[32]) {
    for (int i = 0; i < c->n_nodes; i++)
        if (memcmp(c->nodes[i]->hash, hash, 32) == 0)
            return i;
    return -1;
}

const IngotNode *ingot_chain_find(const IngotChain *c, const unsigned char hash[32]) {
    int i = find_node(c, hash);
    return i < 0 ? NULL : c->nodes[i];
}

int ingot_chain_height(const IngotChain *c) {
    return (int)c->nodes[c->tip]->height;
}

const IngotNode *ingot_chain_tip(const IngotChain *c) {
    return c->nodes[c->tip];
}

uint32_t ingot_chain_height_of(const IngotChain *c, const unsigned char hash[32]) {
    int i = find_node(c, hash);
    return i < 0 ? UINT32_MAX : c->nodes[i]->height;
}

/* ---------- transaction validation against the UTXO set ---------- */

static IngotErr validate_txs(IngotChain *c, const IngotBlock *b, uint32_t height,
                             uint64_t *fees_out) {
    if (b->n_tx < 1 || !b->tx[0].coinbase)
        return INGOT_ERR_COINBASE;
    for (int i = 1; i < b->n_tx; i++)
        if (b->tx[i].coinbase)
            return INGOT_ERR_COINBASE;
    uint64_t fees = 0;
    /* an outpoint may be spent once per block, across the whole block:
     * checking each transaction against the pre-block UTXO set alone
     * would let two transactions in the same block spend it twice */
    unsigned char spent[INGOT_MAX_BLOCK_TXS * INGOT_MAX_TX_IN][36];
    int n_spent = 0;
    for (int i = 1; i < b->n_tx; i++) {
        const IngotTx *tx = &b->tx[i];
        if (tx->n_in < 1 || tx->n_out < 1)
            return INGOT_ERR_TX;
        uint64_t in_sum = 0, out_sum = 0;
        for (int j = 0; j < tx->n_in; j++) {
            const IngotTxIn *in = &tx->in[j];
            unsigned char key[36];
            utxo_make_key(key, in->prev_txid, in->index);
            for (int k = 0; k < n_spent; k++)
                if (memcmp(spent[k], key, 36) == 0)
                    return INGOT_ERR_DBLSPEND;   /* spent twice in one block */
            memcpy(spent[n_spent++], key, 36);
            const IngotUtxo *u = ingot_chain_utxo(c, in->prev_txid, in->index);
            if (!u)
                return INGOT_ERR_DBLSPEND;       /* unknown or already spent */
            unsigned char addr[INGOT_ADDR_HASH_LEN];
            ingot_addr_hash(in->pubkey, addr);
            if (memcmp(addr, u->addr, INGOT_ADDR_HASH_LEN) != 0)
                return INGOT_ERR_SIG;            /* pubkey does not own the output */
            if (!ingot_tx_input_valid(tx, j))
                return INGOT_ERR_SIG;
            in_sum += u->amount;
            if (in_sum < u->amount)
                return INGOT_ERR_VALUE;          /* uint64 wrap */
        }
        for (int j = 0; j < tx->n_out; j++) {
            if (tx->out[j].amount == 0)
                return INGOT_ERR_VALUE;
            out_sum += tx->out[j].amount;
            if (out_sum < tx->out[j].amount)
                return INGOT_ERR_VALUE;          /* uint64 wrap */
        }
        if (out_sum > in_sum)
            return INGOT_ERR_VALUE;
        fees += in_sum - out_sum;
    }
    const IngotTx *cb = &b->tx[0];
    /* BIP34-style uniqueness: the coinbase input carries the height in
     * its index field, so no two coinbases can ever share a txid and
     * overwrite each other in the UTXO map. */
    if (cb->n_in != 1 || cb->in[0].index != height)
        return INGOT_ERR_COINBASE;
    uint64_t cb_out = 0;
    for (int j = 0; j < cb->n_out; j++) {
        cb_out += cb->out[j].amount;
        if (cb_out < cb->out[j].amount)
            return INGOT_ERR_COINBASE;           /* uint64 wrap */
    }
    if (cb_out > ingot_subsidy(height) + fees)
        return INGOT_ERR_COINBASE;
    *fees_out = fees;
    return INGOT_OK;
}

static void apply_txs(IngotChain *c, const IngotBlock *b) {
    for (int i = 0; i < b->n_tx; i++) {
        const IngotTx *tx = &b->tx[i];
        if (!tx->coinbase)
            for (int j = 0; j < tx->n_in; j++)
                utxo_del(c, tx->in[j].prev_txid, tx->in[j].index);
        unsigned char txid[32];
        ingot_txid(tx, txid);
        for (int j = 0; j < tx->n_out; j++) {
            IngotUtxo u;
            memcpy(u.txid, txid, 32);
            u.idx = (uint32_t)j;
            u.amount = tx->out[j].amount;
            memcpy(u.addr, tx->out[j].addr, INGOT_ADDR_HASH_LEN);
            u.coinbase = tx->coinbase;
            utxo_put(c, &u);
        }
    }
}

/* Rebuild the UTXO set by replaying the chain that ends at node `to`,
 * validating every block. On failure the map is left half-built; the
 * caller restores a saved copy. */
static IngotErr rebuild_utxo(IngotChain *c, int to) {
    static int path[INGOT_MAX_BLOCKS];
    int depth = 0;
    for (int i = to; i >= 0; i = c->nodes[i]->parent)
        path[depth++] = i;
    memset(c->utxo, 0, sizeof c->utxo);
    c->utxo_count = 0;
    for (int i = depth - 1; i >= 0; i--) {
        IngotNode *n = c->nodes[path[i]];
        uint64_t fees;
        IngotErr e = validate_txs(c, &n->b, n->height, &fees);
        if (e != INGOT_OK)
            return e;
        apply_txs(c, &n->b);
    }
    return INGOT_OK;
}

/* ---------- mempool ---------- */

int ingot_mempool_size(const IngotChain *c) {
    return c->n_mempool;
}

static IngotErr mempool_check(const IngotChain *c, const IngotTx *tx, uint64_t *fee_out) {
    if (tx->coinbase || tx->n_in < 1 || tx->n_out < 1)
        return INGOT_ERR_TX;
    uint64_t in_sum = 0, out_sum = 0;
    for (int j = 0; j < tx->n_in; j++) {
        const IngotTxIn *in = &tx->in[j];
        const IngotUtxo *u = ingot_chain_utxo(c, in->prev_txid, in->index);
        if (!u)
            return INGOT_ERR_DBLSPEND;
        for (int m = 0; m < c->n_mempool; m++)
            for (int k = 0; k < c->mempool[m].tx.n_in; k++)
                if (memcmp(c->mempool[m].tx.in[k].prev_txid, in->prev_txid, 32) == 0 &&
                    c->mempool[m].tx.in[k].index == in->index)
                    return INGOT_ERR_CONFLICT;
        unsigned char addr[INGOT_ADDR_HASH_LEN];
        ingot_addr_hash(in->pubkey, addr);
        if (memcmp(addr, u->addr, INGOT_ADDR_HASH_LEN) != 0)
            return INGOT_ERR_SIG;
        if (!ingot_tx_input_valid(tx, j))
            return INGOT_ERR_SIG;
        in_sum += u->amount;
        if (in_sum < u->amount)
            return INGOT_ERR_VALUE;
    }
    for (int j = 0; j < tx->n_out; j++) {
        if (tx->out[j].amount == 0)
            return INGOT_ERR_VALUE;
        out_sum += tx->out[j].amount;
        if (out_sum < tx->out[j].amount)
            return INGOT_ERR_VALUE;
    }
    if (out_sum > in_sum)
        return INGOT_ERR_VALUE;
    *fee_out = in_sum - out_sum;
    return INGOT_OK;
}

IngotErr ingot_mempool_add(IngotChain *c, const IngotTx *tx) {
    uint64_t fee;
    IngotErr e = mempool_check(c, tx, &fee);
    if (e != INGOT_OK)
        return e;
    if (c->n_mempool == INGOT_MAX_MEMPOOL) {
        /* evict the cheapest entry, but only for something better */
        int worst = 0;
        for (int i = 1; i < c->n_mempool; i++)
            if (c->mempool[i].fee < c->mempool[worst].fee)
                worst = i;
        if (fee <= c->mempool[worst].fee)
            return INGOT_ERR_FULL;
        c->mempool[worst] = c->mempool[c->n_mempool - 1];
        c->n_mempool--;
    }
    c->mempool[c->n_mempool].tx = *tx;
    c->mempool[c->n_mempool].fee = fee;
    c->n_mempool++;
    return INGOT_OK;
}

/* Drop every mempool tx the new UTXO set no longer supports: mined
 * transactions, and conflicts whose inputs were spent by the block. */
static void mempool_rescan(IngotChain *c) {
    int w = 0;
    for (int i = 0; i < c->n_mempool; i++) {
        const IngotTx *tx = &c->mempool[i].tx;
        int ok = 1;
        for (int j = 0; j < tx->n_in && ok; j++)
            if (!ingot_chain_utxo(c, tx->in[j].prev_txid, tx->in[j].index))
                ok = 0;
        if (ok)
            c->mempool[w++] = c->mempool[i];
    }
    c->n_mempool = w;
}

/* ---------- validation and connection ---------- */

static IngotErr validate_header(const IngotChain *c, int ni) {
    const IngotNode *n = c->nodes[ni];
    if (!ingot_block_pow_valid(&n->b))
        return INGOT_ERR_POW;
    int pi = n->parent;
    if (pi >= 0) {
        if (n->b.h.bits != bits_after(c, pi))
            return INGOT_ERR_BITS;
        if (n->b.h.time <= c->nodes[pi]->b.h.time)
            return INGOT_ERR_TIME;
    }
    if (n->b.h.time > (uint32_t)time(NULL) + INGOT_MAX_FUTURE)
        return INGOT_ERR_TIME;
    return INGOT_OK;
}

static IngotErr connect_node(IngotChain *c, int ni);

static void rescan_orphans(IngotChain *c, const unsigned char hash[32]) {
    for (int i = 0; i < c->n_nodes; i++) {
        if (c->nodes[i]->orphan && memcmp(c->nodes[i]->b.h.prev, hash, 32) == 0) {
            c->nodes[i]->orphan = 0;
            c->nodes[i]->parent = find_node(c, hash);   /* now known */
            if (connect_node(c, i) == INGOT_OK)
                rescan_orphans(c, c->nodes[i]->hash);
        }
    }
}

static IngotErr connect_node(IngotChain *c, int ni) {
    IngotNode *n = c->nodes[ni];
    IngotErr e = validate_header(c, ni);
    if (e != INGOT_OK) {
        n->invalid = 1;
        return e;
    }
    int pi = n->parent;
    n->height = c->nodes[pi]->height + 1;
    unsigned __int128 bw;
    ingot_bits_work(n->b.h.bits, &bw);
    n->work = c->nodes[pi]->work + bw;

    if (pi == c->tip) {
        /* extends the active tip: validate against the live UTXO set */
        uint64_t fees;
        e = validate_txs(c, &n->b, n->height, &fees);
        if (e != INGOT_OK) {
            n->invalid = 1;
            return e;
        }
        apply_txs(c, &n->b);
        n->main = 1;
        c->tip = ni;
        mempool_rescan(c);
        return INGOT_OK;
    }
    if (n->work > c->nodes[c->tip]->work) {
        /* Heavier branch: save the UTXO map, rebuild it along the new
         * fork, and roll back if any block fails. The map copy is in
         * static storage - chains are driven single-threaded - so a
         * deep reorg cannot exhaust the stack. */
        static IngotUtxoSlot saved[INGOT_UTXO_SLOTS];
        size_t saved_count = c->utxo_count;
        memcpy(saved, c->utxo, sizeof saved);
        e = rebuild_utxo(c, ni);
        if (e != INGOT_OK) {
            memcpy(c->utxo, saved, sizeof saved);
            c->utxo_count = saved_count;
            n->invalid = 1;
            return e;
        }
        for (int i = 0; i < c->n_nodes; i++)
            c->nodes[i]->main = 0;
        for (int i = ni; i >= 0; i = c->nodes[i]->parent)
            c->nodes[i]->main = 1;
        c->tip = ni;
        mempool_rescan(c);
    }
    return INGOT_OK;
}

IngotErr ingot_chain_add(IngotChain *c, const IngotBlock *b) {
    unsigned char hash[32];
    ingot_block_hash(b, hash);
    if (find_node(c, hash) >= 0)
        return INGOT_ERR_DUP;
    if (c->n_nodes == INGOT_MAX_BLOCKS)
        return INGOT_ERR_FULL;
    int pi = find_node(c, b->h.prev);
    IngotNode *n = calloc(1, sizeof *n);
    if (!n)
        return INGOT_ERR_FULL;
    n->b = *b;
    memcpy(n->hash, hash, 32);
    n->parent = pi;
    c->nodes[c->n_nodes++] = n;
    if (pi < 0 || c->nodes[pi]->orphan) {
        /* a child of an orphan is an orphan too: never let connect_node
         * compute heights and work from an orphan's zeroed fields */
        n->orphan = 1;
        return INGOT_ERR_ORPHAN;
    }
    if (c->nodes[pi]->invalid) {
        n->invalid = 1;
        return INGOT_ERR_PARENT;
    }
    IngotErr e = connect_node(c, c->n_nodes - 1);
    if (!n->invalid)
        rescan_orphans(c, hash);
    return e;
}

static int node_height_cmp(const void *a, const void *b) {
    const IngotNode *na = *(const IngotNode *const *)a;
    const IngotNode *nb = *(const IngotNode *const *)b;
    return na->height < nb->height ? -1 : na->height > nb->height;
}

int ingot_chain_pending_store(IngotChain *c, IngotNode **out, int max) {
    int k = 0;
    for (int i = 0; i < c->n_nodes && k < max; i++)
        if (!c->nodes[i]->orphan && !c->nodes[i]->invalid && !c->nodes[i]->stored)
            out[k++] = c->nodes[i];
    qsort(out, (size_t)k, sizeof *out, node_height_cmp);
    return k;
}

/* ---------- genesis ---------- */

void ingot_chain_init(IngotChain *c) {
    memset(c, 0, sizeof *c);
    IngotNode *n = calloc(1, sizeof *n);
    IngotBlock *g = &n->b;
    g->h.version = 1;
    g->h.time = INGOT_GENESIS_TIME;
    g->h.bits = INGOT_BITS_START;
    g->n_tx = 1;
    g->tx[0].coinbase = 1;
    g->tx[0].n_in = 1;
    g->tx[0].in[0].index = 0;   /* height 0 */
    g->tx[0].n_out = 1;
    g->tx[0].out[0].amount = INGOT_SUBSIDY;
    /* all-zero address: the genesis subsidy is unspendable by design */
    ingot_merkle(g, g->h.merkle);
    unsigned char target[32];
    ingot_bits_to_target(g->h.bits, target);
    for (uint32_t nonce = 0;; nonce++) {
        g->h.nonce = nonce;
        ingot_block_hash(g, n->hash);
        if (ingot_hash_meets(n->hash, target))
            break;
    }
    n->height = 0;
    ingot_bits_work(g->h.bits, &n->work);
    n->parent = -1;
    n->main = 1;
    n->stored = 1;   /* synthesized at load, never read from the file */
    c->nodes[0] = n;
    c->n_nodes = 1;
    c->tip = 0;
    apply_txs(c, g);
}

void ingot_chain_free(IngotChain *c) {
    for (int i = 0; i < c->n_nodes; i++)
        free(c->nodes[i]);
    c->n_nodes = 0;
}

const char *ingot_err_str(IngotErr e) {
    switch (e) {
    case INGOT_OK: return "ok";
    case INGOT_ERR_DUP: return "duplicate block";
    case INGOT_ERR_ORPHAN: return "orphan: parent unknown";
    case INGOT_ERR_FULL: return "a capacity limit was reached";
    case INGOT_ERR_POW: return "bad proof of work or merkle root";
    case INGOT_ERR_PARENT: return "an ancestor is invalid";
    case INGOT_ERR_BITS: return "bits do not match the retarget rule";
    case INGOT_ERR_TIME: return "timestamp out of range";
    case INGOT_ERR_COINBASE: return "coinbase rule violation";
    case INGOT_ERR_TX: return "malformed transaction";
    case INGOT_ERR_DBLSPEND: return "input unknown or already spent";
    case INGOT_ERR_SIG: return "signature check failed";
    case INGOT_ERR_VALUE: return "outputs exceed inputs";
    case INGOT_ERR_CONFLICT: return "conflicts with a mempool transaction";
    }
    return "unknown error";
}
