/* chain.h - block index, UTXO set, validation, reorganization, mempool.
 *
 * Consensus parameters (toy scale, chosen so a browser can play):
 *   subsidy 50 coins, halving every 1000 blocks
 *   retarget every 100 blocks, factor-4 clamp, 10 second target spacing
 *   initial bits 0x2000ffff (~2^16 expected hashes)
 *   most cumulative work wins; the UTXO set is rebuilt from genesis on
 *   every reorg (O(chain), simple and obviously correct)
 *
 * Everything is fixed-capacity and in memory; persistence lives in
 * store.c, networking in net.c. No I/O happens here. */
#ifndef INGOT_CHAIN_H
#define INGOT_CHAIN_H

#include "block.h"

#define INGOT_SUBSIDY       (50ULL * INGOT_COIN)
#define INGOT_HALVING       1000
#define INGOT_RETARGET      100
#define INGOT_BLOCK_SPACING 10          /* seconds */
#define INGOT_BITS_START    0x2000ffffu
#define INGOT_MAX_FUTURE    (2 * 3600)  /* block time tolerance */

#define INGOT_MAX_BLOCKS    2048        /* block index capacity */
/* Nodes are heap-allocated one by one: the index is a pointer array so
 * an empty chain costs kilobytes, not megabytes. */
#define INGOT_UTXO_SLOTS    16384       /* open-addressing UTXO map */
#define INGOT_MAX_MEMPOOL   256


typedef struct {
    unsigned char txid[32];
    uint32_t idx;
    uint64_t amount;
    unsigned char addr[INGOT_ADDR_HASH_LEN];
    int coinbase;
} IngotUtxo;

typedef struct {
    unsigned char key[36];      /* txid || idx (big-endian u32) */
    IngotUtxo u;
    int used;                   /* 0 empty, 1 live, 2 tombstone */
} IngotUtxoSlot;

typedef struct {
    IngotBlock b;
    unsigned char hash[32];
    uint32_t height;
    unsigned __int128 work;     /* cumulative chain work */
    int parent;                 /* index or -1 */
    int main;                   /* on the active chain */
    int orphan;                 /* parent unknown */
    int invalid;                /* failed validation once */
} IngotNode;

typedef struct {
    IngotTx tx;
    uint64_t fee;
} IngotMempoolEntry;

typedef struct {
    IngotNode *nodes[INGOT_MAX_BLOCKS];
    int n_nodes;
    int tip;                    /* index of active tip */
    IngotUtxoSlot utxo[INGOT_UTXO_SLOTS];
    size_t utxo_count;
    IngotMempoolEntry mempool[INGOT_MAX_MEMPOOL];
    int n_mempool;
} IngotChain;

typedef enum {
    INGOT_OK = 0,
    INGOT_ERR_DUP,              /* block already known */
    INGOT_ERR_ORPHAN,           /* parent unknown - kept for later */
    INGOT_ERR_FULL,             /* an index capacity was reached */
    INGOT_ERR_POW,              /* bad merkle or hash above target */
    INGOT_ERR_PARENT,           /* an ancestor is already invalid */
    INGOT_ERR_BITS,             /* bits do not match the retarget rule */
    INGOT_ERR_TIME,             /* non-monotonic or too far in the future */
    INGOT_ERR_COINBASE,         /* missing/extra/overspending coinbase */
    INGOT_ERR_TX,               /* a transaction failed validation */
    INGOT_ERR_DBLSPEND,         /* input already spent */
    INGOT_ERR_SIG,              /* signature check failed */
    INGOT_ERR_VALUE,            /* outputs exceed inputs */
    INGOT_ERR_CONFLICT,         /* mempool double-spend */
} IngotErr;

const char *ingot_err_str(IngotErr e);

void ingot_chain_init(IngotChain *c);
void ingot_chain_free(IngotChain *c);   /* the struct itself is the caller's */
uint64_t ingot_subsidy(uint32_t height);
uint32_t ingot_chain_next_bits(const IngotChain *c);

/* Validate, index and maybe connect a block. INGOT_OK when it extends
 * the active chain, INGOT_ERR_ORPHAN when kept for later,
 * INGOT_ERR_DUP when already known; other codes are rejections. */
IngotErr ingot_chain_add(IngotChain *c, const IngotBlock *b);

int ingot_chain_height(const IngotChain *c);            /* -1 impossible */
const IngotNode *ingot_chain_tip(const IngotChain *c);
const IngotNode *ingot_chain_find(const IngotChain *c, const unsigned char hash[32]);

const IngotUtxo *ingot_chain_utxo(const IngotChain *c,
                                  const unsigned char txid[32], uint32_t idx);
uint64_t ingot_chain_balance(const IngotChain *c, const unsigned char addr[INGOT_ADDR_HASH_LEN]);
uint32_t ingot_chain_height_of(const IngotChain *c, const unsigned char hash[32]);

/* Mempool: validate against the active UTXO set plus pending spends. */
IngotErr ingot_mempool_add(IngotChain *c, const IngotTx *tx);
int ingot_mempool_size(const IngotChain *c);

#endif
