#include "block.h"
#include "sha256.h"
#include <string.h>

void ingot_merkle(const IngotBlock *b, unsigned char out[32]) {
    /* pairwise sha256d of txids, duplicating a lone leaf per level */
    unsigned char level[INGOT_MAX_BLOCK_TXS][32];
    int n = b->n_tx;
    for (int i = 0; i < n; i++)
        ingot_txid(&b->tx[i], level[i]);
    if (n == 0) {
        memset(out, 0, 32);
        return;
    }
    while (n > 1) {
        int m = 0;
        for (int i = 0; i < n; i += 2) {
            unsigned char pair[64];
            memcpy(pair, level[i], 32);
            memcpy(pair + 32, level[i + 1 < n ? i + 1 : i], 32);
            sha256d(pair, 64, level[m++]);
        }
        n = m;
    }
    memcpy(out, level[0], 32);
}

void ingot_bits_to_target(uint32_t bits, unsigned char out[32]) {
    memset(out, 0, 32);
    uint32_t mant = bits & 0x007fffff;
    int exp = (int)(bits >> 24);
    /* the target is mant * 256^(exp-3); lay the 3 mantissa bytes down
     * big-endian at the right offset */
    for (int i = 0; i < 3; i++) {
        int byte_pos = 32 - exp + i;  /* 0 = most significant */
        if (byte_pos >= 0 && byte_pos < 32)
            out[byte_pos] = (unsigned char)(mant >> (16 - i * 8));
    }
}

uint32_t ingot_target_to_bits(const unsigned char target[32]) {
    int i = 0;
    while (i < 32 && target[i] == 0)
        i++;
    if (i > 29)
        return 0;
    int exp = 32 - i;
    uint32_t mant = 0;
    for (int k = 0; k < 3 && i + k < 32; k++)
        mant = mant << 8 | target[i + k];
    if (mant & 0x00800000) {   /* keep the sign bit clear */
        mant >>= 8;
        exp++;
    }
    return (uint32_t)exp << 24 | mant;
}

int ingot_hash_meets(const unsigned char hash[32], const unsigned char target[32]) {
    for (int i = 0; i < 32; i++) {
        if (hash[i] < target[i]) return 1;
        if (hash[i] > target[i]) return 0;
    }
    return 1;
}

void ingot_bits_work(uint32_t bits, unsigned __int128 *out) {
    unsigned char target[32];
    ingot_bits_to_target(bits, target);
    /* work = floor(2^256 / (target+1)); compute with 256-bit long
     * division of (2^256-1) by (target+1), close enough for ordering */
    unsigned __int128 hi = 0, lo = 0;
    /* represent target+1 as 5 limbs of 64 bits (little-endian) */
    uint64_t t[5] = {0};
    for (int i = 0; i < 32; i++)
        t[i / 8] |= (uint64_t)target[31 - i] << ((i % 8) * 8);
    /* t+1 */
    int i = 0;
    while (i < 5 && ++t[i] == 0)
        i++;
    /* dividend: 2^256 - 1 (all ones); bitwise long division */
    unsigned __int128 q = 0;
    uint64_t rem[6] = {0};
    for (int bit = 255; bit >= 0; bit--) {
        /* rem = rem*2 + 1 (dividend is all ones) */
        uint64_t c = 1;
        for (int j = 0; j < 6; j++) {
            uint64_t nc = rem[j] >> 63;
            rem[j] = (rem[j] << 1) | c;
            c = nc;
        }
        /* if rem >= t, rem -= t, quotient bit set */
        int ge = 1;
        for (int j = 5; j >= 0; j--) {
            uint64_t tv = j < 5 ? t[j] : 0;
            if (rem[j] > tv) break;
            if (rem[j] < tv) { ge = 0; break; }
        }
        if (ge) {
            uint64_t bor = 0;
            for (int j = 0; j < 5; j++) {
                unsigned __int128 u = (unsigned __int128)rem[j] - t[j] - bor;
                rem[j] = (uint64_t)u;
                bor = (uint64_t)(u >> 64) & 1;
            }
            rem[5] -= (uint64_t)bor;
            if (bit < 128)
                q |= (unsigned __int128)1 << bit;
            else
                q = ~(unsigned __int128)0;   /* saturated: tiny targets */
        }
    }
    (void)hi; (void)lo;
    *out = q;
}

void ingot_block_hash(const IngotBlock *b, unsigned char out[32]) {
    unsigned char hdr[INGOT_HEADER_SIZE], *p = hdr;
    p[0] = (unsigned char)b->h.version;
    p[1] = (unsigned char)(b->h.version >> 8);
    p[2] = (unsigned char)(b->h.version >> 16);
    p[3] = (unsigned char)(b->h.version >> 24);
    p += 4;
    memcpy(p, b->h.prev, 32); p += 32;
    memcpy(p, b->h.merkle, 32); p += 32;
    for (int i = 0; i < 4; i++) p[i] = (unsigned char)(b->h.time >> (i * 8));
    p += 4;
    for (int i = 0; i < 4; i++) p[i] = (unsigned char)(b->h.bits >> (i * 8));
    p += 4;
    for (int i = 0; i < 4; i++) p[i] = (unsigned char)(b->h.nonce >> (i * 8));
    sha256d(hdr, INGOT_HEADER_SIZE, out);
}

int ingot_block_pow_valid(const IngotBlock *b) {
    unsigned char hash[32], target[32], merkle[32];
    ingot_block_hash(b, hash);
    ingot_bits_to_target(b->h.bits, target);
    ingot_merkle(b, merkle);
    if (memcmp(merkle, b->h.merkle, 32) != 0)
        return 0;
    return ingot_hash_meets(hash, target);
}

static void put32(unsigned char **p, uint32_t v) {
    for (int i = 0; i < 4; i++) (*p)[i] = (unsigned char)(v >> (i * 8));
    *p += 4;
}

size_t ingot_block_serialize(const IngotBlock *b, unsigned char *out, size_t cap) {
    unsigned char *p = out, *end = out + cap;
    if ((size_t)(end - p) < INGOT_HEADER_SIZE + 4) return 0;
    put32(&p, b->h.version);
    memcpy(p, b->h.prev, 32); p += 32;
    memcpy(p, b->h.merkle, 32); p += 32;
    put32(&p, b->h.time);
    put32(&p, b->h.bits);
    put32(&p, b->h.nonce);
    put32(&p, (uint32_t)b->n_tx);
    for (int i = 0; i < b->n_tx; i++) {
        size_t n = ingot_tx_serialize(&b->tx[i], 1, p, (size_t)(end - p));
        if (!n) return 0;
        p += n;
    }
    return (size_t)(p - out);
}

static int get32(const unsigned char **p, const unsigned char *end, uint32_t *v) {
    if ((size_t)(end - *p) < 4) return -1;
    *v = 0;
    for (int i = 0; i < 4; i++)
        *v |= (uint32_t)(*p)[i] << (i * 8);
    *p += 4;
    return 0;
}

size_t ingot_block_parse(const unsigned char *in, size_t len, IngotBlock *b) {
    const unsigned char *p = in, *end = in + len;
    if (len < INGOT_HEADER_SIZE + 4) return 0;
    memset(b, 0, sizeof *b);
    if (get32(&p, end, &b->h.version) != 0) return 0;
    memcpy(b->h.prev, p, 32); p += 32;
    memcpy(b->h.merkle, p, 32); p += 32;
    if (get32(&p, end, &b->h.time) != 0) return 0;
    if (get32(&p, end, &b->h.bits) != 0) return 0;
    if (get32(&p, end, &b->h.nonce) != 0) return 0;
    uint32_t n;
    if (get32(&p, end, &n) != 0) return 0;
    if (n > INGOT_MAX_BLOCK_TXS) return 0;
    b->n_tx = (int)n;
    for (uint32_t i = 0; i < n; i++) {
        size_t used = ingot_tx_parse(p, (size_t)(end - p), &b->tx[i]);
        if (!used) return 0;
        p += used;
    }
    return (size_t)(p - in);
}
