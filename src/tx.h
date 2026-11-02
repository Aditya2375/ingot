/* tx.h - transactions over a UTXO model.
 *
 * An input spends a previous output: it carries the spender's full
 * public key and a signature over the whole transaction with every
 * signature zeroed. The txid commits to the signatures too, so a signed
 * transaction is immutable. */
#ifndef INGOT_TX_H
#define INGOT_TX_H

#include <stddef.h>
#include <stdint.h>
#include "keys.h"

#define INGOT_MAX_TX_IN 8
#define INGOT_MAX_TX_OUT 8
#define INGOT_COIN 100000000ULL   /* base units per coin */

typedef struct {
    unsigned char prev_txid[32];   /* all zero for a coinbase */
    uint32_t index;
    unsigned char pubkey[32];      /* empty for a coinbase */
    unsigned char sig[64];         /* empty for a coinbase */
} IngotTxIn;

typedef struct {
    uint64_t amount;
    unsigned char addr[INGOT_ADDR_HASH_LEN];
} IngotTxOut;

typedef struct {
    IngotTxIn in[INGOT_MAX_TX_IN];
    IngotTxOut out[INGOT_MAX_TX_OUT];
    int n_in, n_out;
    int coinbase;
} IngotTx;

/* Canonical serialization (with or without signatures). Returns the
 * length, 0 on overflow. */
size_t ingot_tx_serialize(const IngotTx *tx, int with_sigs,
                          unsigned char *out, size_t cap);
/* Parse; returns the length consumed, 0 on malformed. */
size_t ingot_tx_parse(const unsigned char *in, size_t len, IngotTx *tx);

void ingot_txid(const IngotTx *tx, unsigned char out[32]);
/* The digest every input signs: the serialization with empty sigs. */
void ingot_tx_sighash(const IngotTx *tx, unsigned char out[32]);
/* Sign the sighash with seed's key into input i. */
void ingot_tx_sign(IngotTx *tx, int i, const unsigned char seed[32]);
/* 1 when input i's signature matches its pubkey and the sighash. */
int ingot_tx_input_valid(const IngotTx *tx, int i);

#endif
