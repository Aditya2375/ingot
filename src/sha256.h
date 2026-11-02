/* sha256.h - SHA-256 (FIPS 180-4), streaming interface. */
#ifndef INGOT_SHA256_H
#define INGOT_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t len;            /* total bytes fed */
    unsigned char buf[64];   /* partial block */
    size_t buflen;
} Sha256;

void sha256_init(Sha256 *c);
void sha256_update(Sha256 *c, const void *data, size_t len);
void sha256_final(Sha256 *c, unsigned char out[32]);

/* One-shot. */
void sha256(const void *data, size_t len, unsigned char out[32]);

/* Hash of the hash - the double-SHA-256 blockchains use for tx and block
 * ids, so a length-extension on the first pass buys nothing. */
void sha256d(const void *data, size_t len, unsigned char out[32]);

#endif
