/* fuzz-driver: feed stdin bytes at the wire parsers and the chain. Never
 * crashes, never hangs; run under ASan/UBSan in CI. */
#include "../src/tx.h"
#include "../src/block.h"
#include "../src/chain.h"
#include "../src/keys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    static unsigned char buf[16384];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    if (n == 0)
        return 0;

    /* transactions: parse, and round-trip whatever parses */
    IngotTx *tx = malloc(sizeof *tx);
    if (!tx) return 1;
    size_t used = ingot_tx_parse(buf, n, tx);
    if (used) {
        static unsigned char out[8 + INGOT_MAX_TX_IN * 132 + INGOT_MAX_TX_OUT * 28];
        size_t m = ingot_tx_serialize(tx, 1, out, sizeof out);
        IngotTx *back = malloc(sizeof *back);
        if (!back) return 1;
        if (m != used || ingot_tx_parse(out, m, back) != m) {
            fprintf(stderr, "tx round-trip mismatch\n");
            return 1;
        }
        unsigned char id[32];
        ingot_txid(tx, id);
        free(back);
    }
    free(tx);

    /* blocks: parse, and offer whatever parses to a fresh chain */
    IngotBlock *b = malloc(sizeof *b);
    if (!b) return 1;
    if (ingot_block_parse(buf, n, b)) {
        IngotChain *c = malloc(sizeof *c);
        if (!c) return 1;
        ingot_chain_init(c);
        ingot_chain_add(c, b);   /* any rejection is fine; a crash is not */
        ingot_chain_free(c);
        free(c);
    }
    free(b);

    /* addresses: the bytes as text, must never crash the decoder */
    char addr[65];
    if (n < sizeof addr) {
        memcpy(addr, buf, n);
        addr[n] = 0;
        unsigned char h[INGOT_ADDR_HASH_LEN];
        ingot_address_parse(addr, h);
    }
    return 0;
}
