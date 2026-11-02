#include "tx.h"
#include "ed25519.h"
#include "sha256.h"
#include <string.h>

static void put32(unsigned char **p, uint32_t v) {
    (*p)[0] = (unsigned char)v;
    (*p)[1] = (unsigned char)(v >> 8);
    (*p)[2] = (unsigned char)(v >> 16);
    (*p)[3] = (unsigned char)(v >> 24);
    *p += 4;
}

static void put64(unsigned char **p, uint64_t v) {
    for (int i = 0; i < 8; i++)
        (*p)[i] = (unsigned char)(v >> (i * 8));
    *p += 8;
}

size_t ingot_tx_serialize(const IngotTx *tx, int with_sigs,
                          unsigned char *out, size_t cap) {
    size_t need = 6 + (size_t)tx->n_in * (with_sigs ? 132 : 36) +
                  (size_t)tx->n_out * (8 + INGOT_ADDR_HASH_LEN);
    if (need > cap)
        return 0;
    unsigned char *p = out;
    *p++ = (unsigned char)tx->coinbase;
    *p++ = (unsigned char)tx->n_in;
    for (int i = 0; i < tx->n_in; i++) {
        memcpy(p, tx->in[i].prev_txid, 32); p += 32;
        put32(&p, tx->in[i].index);
        if (with_sigs) {
            memcpy(p, tx->in[i].pubkey, 32); p += 32;
            memcpy(p, tx->in[i].sig, 64); p += 64;
        }
    }
    *p++ = (unsigned char)tx->n_out;
    for (int i = 0; i < tx->n_out; i++) {
        put64(&p, tx->out[i].amount);
        memcpy(p, tx->out[i].addr, INGOT_ADDR_HASH_LEN);
        p += INGOT_ADDR_HASH_LEN;
    }
    return (size_t)(p - out);
}

static int get32(const unsigned char **p, const unsigned char *end, uint32_t *v) {
    if ((size_t)(end - *p) < 4) return -1;
    *v = (uint32_t)(*p)[0] | (uint32_t)(*p)[1] << 8 |
         (uint32_t)(*p)[2] << 16 | (uint32_t)(*p)[3] << 24;
    *p += 4;
    return 0;
}

static int get64(const unsigned char **p, const unsigned char *end, uint64_t *v) {
    if ((size_t)(end - *p) < 8) return -1;
    *v = 0;
    for (int i = 0; i < 8; i++)
        *v |= (uint64_t)(*p)[i] << (i * 8);
    *p += 8;
    return 0;
}

size_t ingot_tx_parse(const unsigned char *in, size_t len, IngotTx *tx) {
    const unsigned char *p = in, *end = in + len;
    if (len < 3) return 0;
    memset(tx, 0, sizeof *tx);
    tx->coinbase = *p++;
    if (tx->coinbase > 1) return 0;
    tx->n_in = *p++;
    if (tx->n_in > INGOT_MAX_TX_IN) return 0;
    for (int i = 0; i < tx->n_in; i++) {
        if ((size_t)(end - p) < 132) return 0;
        memcpy(tx->in[i].prev_txid, p, 32); p += 32;
        if (get32(&p, end, &tx->in[i].index) != 0) return 0;
        memcpy(tx->in[i].pubkey, p, 32); p += 32;
        memcpy(tx->in[i].sig, p, 64); p += 64;
    }
    tx->n_out = *p++;
    if (tx->n_out > INGOT_MAX_TX_OUT) return 0;
    for (int i = 0; i < tx->n_out; i++) {
        if (get64(&p, end, &tx->out[i].amount) != 0) return 0;
        if ((size_t)(end - p) < INGOT_ADDR_HASH_LEN) return 0;
        memcpy(tx->out[i].addr, p, INGOT_ADDR_HASH_LEN);
        p += INGOT_ADDR_HASH_LEN;
    }
    return (size_t)(p - in);
}

void ingot_tx_sighash(const IngotTx *tx, unsigned char out[32]) {
    unsigned char buf[32 + (size_t)INGOT_MAX_TX_IN * 36 +
                      (size_t)INGOT_MAX_TX_OUT * (8 + INGOT_ADDR_HASH_LEN) + 8];
    size_t n = ingot_tx_serialize(tx, 0, buf, sizeof buf);
    sha256d(buf, n, out);
}

void ingot_txid(const IngotTx *tx, unsigned char out[32]) {
    unsigned char buf[32 + (size_t)INGOT_MAX_TX_IN * 132 +
                      (size_t)INGOT_MAX_TX_OUT * (8 + INGOT_ADDR_HASH_LEN) + 8];
    size_t n = ingot_tx_serialize(tx, 1, buf, sizeof buf);
    sha256d(buf, n, out);
}

void ingot_tx_sign(IngotTx *tx, int i, const unsigned char seed[32]) {
    unsigned char pk[32], digest[32];
    ed25519_publickey(seed, pk);
    memcpy(tx->in[i].pubkey, pk, 32);
    ingot_tx_sighash(tx, digest);
    ed25519_sign(digest, 32, seed, pk, tx->in[i].sig);
}

int ingot_tx_input_valid(const IngotTx *tx, int i) {
    unsigned char digest[32];
    ingot_tx_sighash(tx, digest);
    return ed25519_verify(digest, 32, tx->in[i].pubkey, tx->in[i].sig);
}
