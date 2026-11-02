/* sha512.h - SHA-512 (FIPS 180-4), streaming interface. Ed25519 needs it. */
#ifndef INGOT_SHA512_H
#define INGOT_SHA512_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t h[8];
    uint64_t len_lo, len_hi;   /* total bits is tracked as bytes: lo/hi */
    unsigned char buf[128];
    size_t buflen;
} Sha512;

void sha512_init(Sha512 *c);
void sha512_update(Sha512 *c, const void *data, size_t len);
void sha512_final(Sha512 *c, unsigned char out[64]);
void sha512(const void *data, size_t len, unsigned char out[64]);

#endif
