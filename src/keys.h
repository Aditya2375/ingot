/* keys.h - wallet keys and addresses.
 *
 * An address is base58check(version || sha256(pubkey)[:20]) - one hash,
 * not Bitcoin's RIPEMD-160(SHA-256) pair, since we already carry
 * SHA-256. The version byte makes ingot addresses start with 'i'. */
#ifndef INGOT_KEYS_H
#define INGOT_KEYS_H

#include <stddef.h>

#define INGOT_ADDR_VERSION 0x66   /* addresses render as i... */
#define INGOT_ADDR_HASH_LEN 20

/* seed -> public key -> hash -> address string (out cap >= 40). */
void ingot_pubkey(const unsigned char seed[32], unsigned char pk[32]);
void ingot_addr_hash(const unsigned char pk[32], unsigned char out[INGOT_ADDR_HASH_LEN]);
size_t ingot_address(const unsigned char pk[32], char *out, size_t cap);
/* 1 when addr decodes to a versioned hash; fills hash. */
int ingot_address_parse(const char *addr, unsigned char hash[INGOT_ADDR_HASH_LEN]);

#endif
