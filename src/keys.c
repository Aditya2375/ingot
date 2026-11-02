#include "keys.h"
#include "ed25519.h"
#include "sha256.h"
#include "base58.h"

void ingot_pubkey(const unsigned char seed[32], unsigned char pk[32]) {
    ed25519_publickey(seed, pk);
}

void ingot_addr_hash(const unsigned char pk[32], unsigned char out[INGOT_ADDR_HASH_LEN]) {
    unsigned char d[32];
    sha256(pk, 32, d);
    for (int i = 0; i < INGOT_ADDR_HASH_LEN; i++)
        out[i] = d[i];
}

size_t ingot_address(const unsigned char pk[32], char *out, size_t cap) {
    unsigned char payload[1 + INGOT_ADDR_HASH_LEN];
    payload[0] = INGOT_ADDR_VERSION;
    ingot_addr_hash(pk, payload + 1);
    return base58check_encode(payload, sizeof payload, out, cap);
}

int ingot_address_parse(const char *addr, unsigned char hash[INGOT_ADDR_HASH_LEN]) {
    unsigned char payload[1 + INGOT_ADDR_HASH_LEN];
    if (base58check_decode(addr, payload, sizeof payload) != sizeof payload)
        return 0;
    if (payload[0] != INGOT_ADDR_VERSION)
        return 0;
    for (int i = 0; i < INGOT_ADDR_HASH_LEN; i++)
        hash[i] = payload[1 + i];
    return 1;
}
