/* block.h - block headers, merkle roots, compact-target proof of work.
 *
 * The target is Bitcoin's compact "bits": 0x1d00ffff style, mantissa
 * over 23 bits with an exponent. Work per block is 2^256/(target+1),
 * accumulated over the chain as a 128-bit integer - the most-work chain
 * wins, never the longest. */
#ifndef INGOT_BLOCK_H
#define INGOT_BLOCK_H

#include <stddef.h>
#include <stdint.h>
#include "tx.h"

#define INGOT_MAX_BLOCK_TXS 32
#define INGOT_HEADER_SIZE (4 + 32 + 32 + 4 + 4 + 4)

typedef struct {
    uint32_t version;
    unsigned char prev[32];
    unsigned char merkle[32];
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
} IngotHeader;

typedef struct {
    IngotHeader h;
    IngotTx tx[INGOT_MAX_BLOCK_TXS];
    int n_tx;
} IngotBlock;

void ingot_merkle(const IngotBlock *b, unsigned char out[32]);

/* Compact bits <-> 32-byte big target. */
void ingot_bits_to_target(uint32_t bits, unsigned char out[32]);
uint32_t ingot_target_to_bits(const unsigned char target[32]);
/* 1 when hash (32 raw bytes) is at or below target. */
int ingot_hash_meets(const unsigned char hash[32], const unsigned char target[32]);
/* Estimated hashes needed: 2^256/(target+1), clamped to 2^128-1. */
void ingot_bits_work(uint32_t bits, unsigned __int128 *out);

void ingot_block_hash(const IngotBlock *b, unsigned char out[32]);
int ingot_block_pow_valid(const IngotBlock *b);

/* Whole-block serialization for the wire and for disk. Returns length,
 * 0 on overflow/parse error. */
size_t ingot_block_serialize(const IngotBlock *b, unsigned char *out, size_t cap);
size_t ingot_block_parse(const unsigned char *in, size_t len, IngotBlock *b);

#define INGOT_MAX_BLOCK_SIZE (INGOT_HEADER_SIZE + 4 + \
    (size_t)INGOT_MAX_BLOCK_TXS * (8 + (size_t)INGOT_MAX_TX_IN * 132 + \
    (size_t)INGOT_MAX_TX_OUT * (8 + INGOT_ADDR_HASH_LEN)))

#endif
