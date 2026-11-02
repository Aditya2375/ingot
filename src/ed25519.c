#include "ed25519.h"
#include "sha512.h"
#include <stdint.h>
#include <string.h>

/* ---- field arithmetic mod p = 2^255 - 19, limbs little-endian ----
 *
 * Every value is kept fully reduced (< p). Reductions are exact folds
 * (2^256 = 38, 2^255 = 19 mod p) applied until the value fits, never
 * masked-away bits. */

typedef uint64_t fe[4];

static const fe FE_P = {
    0xffffffffffffffedULL, 0xffffffffffffffffULL,
    0xffffffffffffffffULL, 0x7fffffffffffffffULL
};
static const fe FE_D = {
    0x75eb4dca135978a3ULL, 0x00700a4d4141d8abULL,
    0x8cc740797779e898ULL, 0x52036cee2b6ffe73ULL
};
static const fe FE_D2 = {
    0xebd69b9426b2f159ULL, 0x00e0149a8283b156ULL,
    0x198e80f2eef3d130ULL, 0x2406d9dc56dffce7ULL
};
static const fe FE_SQRTM1 = {
    0xc4ee1b274a0ea0b0ULL, 0x2f431806ad2fe478ULL,
    0x2b4d00993dfbd7a7ULL, 0x2b8324804fc1df0bULL
};

/* if r >= p, r -= p. Requires r < 2p. */
static void fe_csub(fe r) {
    uint64_t tmp[4], b = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 t = (unsigned __int128)r[i] - FE_P[i] - b;
        tmp[i] = (uint64_t)t;
        b = (uint64_t)(t >> 64) & 1;
    }
    if (!b)
        memcpy(r, tmp, sizeof tmp);
}

/* fold the 2^255 bit (worth 19) until clear. Each pass strictly lowers
 * the value, and the carry chain cannot overflow 2^256 (r[3] < 2^63
 * after masking, carry-in <= 1), so this terminates with r < 2^255 + 19. */
static void fe_fold(fe r) {
    while (r[3] >> 63) {
        r[3] &= 0x7fffffffffffffffULL;
        unsigned __int128 t = (unsigned __int128)r[0] + 19;
        r[0] = (uint64_t)t;
        t = (t >> 64) + r[1]; r[1] = (uint64_t)t;
        t = (t >> 64) + r[2]; r[2] = (uint64_t)t;
        t = (t >> 64) + r[3]; r[3] = (uint64_t)t;
    }
}

static void fe_norm(fe r) {
    fe_fold(r);
    fe_csub(r);
    fe_csub(r);
}

/* a + b, both < p, so the sum is < 2p < 2^256: one csub finishes. */
static void fe_add(fe r, const fe a, const fe b) {
    unsigned __int128 t = (unsigned __int128)a[0] + b[0];
    r[0] = (uint64_t)t;
    t = (t >> 64) + a[1] + b[1]; r[1] = (uint64_t)t;
    t = (t >> 64) + a[2] + b[2]; r[2] = (uint64_t)t;
    t = (t >> 64) + a[3] + b[3]; r[3] = (uint64_t)t;
    fe_csub(r);
}

static int fe_iszero(const fe a) {
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

/* p - a, with 0 mapping to 0. */
static void fe_neg(fe r, const fe a) {
    if (fe_iszero(a)) {
        memset(r, 0, sizeof(fe));
        return;
    }
    uint64_t bor = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 t = (unsigned __int128)FE_P[i] - a[i] - bor;
        r[i] = (uint64_t)t;
        bor = (uint64_t)(t >> 64) & 1;
    }
    /* a in [1, p-1], so p - a in [1, p-1]: no borrow out, already < p */
    (void)bor;
}

static void fe_sub(fe r, const fe a, const fe b) {
    fe nb;
    fe_neg(nb, b);
    fe_add(r, a, nb);
}

static void fe_mul(fe r, const fe a, const fe b) {
    unsigned __int128 prod[8] = {0};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            unsigned __int128 m = (unsigned __int128)a[i] * b[j];
            unsigned __int128 t = prod[i + j] + (uint64_t)m;
            prod[i + j] = (uint64_t)t;
            prod[i + j + 1] += (t >> 64) + (m >> 64);
        }
    /* fold the high half: 2^256 = 38 mod p */
    fe v;
    unsigned __int128 t = prod[0] + 38 * prod[4];
    v[0] = (uint64_t)t;
    t = (t >> 64) + prod[1] + 38 * prod[5]; v[1] = (uint64_t)t;
    t = (t >> 64) + prod[2] + 38 * prod[6]; v[2] = (uint64_t)t;
    t = (t >> 64) + prod[3] + 38 * prod[7]; v[3] = (uint64_t)t;
    uint64_t c = (uint64_t)(t >> 64);
    while (c) {   /* each pass is exact and shrinks c: 40 -> 1 -> 1 -> 0 */
        t = (unsigned __int128)v[0] + 38 * c;
        v[0] = (uint64_t)t;
        t = (t >> 64) + v[1]; v[1] = (uint64_t)t;
        t = (t >> 64) + v[2]; v[2] = (uint64_t)t;
        t = (t >> 64) + v[3]; v[3] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    memcpy(r, v, sizeof v);
    fe_norm(r);
}

static void fe_sq(fe r, const fe a) { fe_mul(r, a, a); }

/* r = a^e mod p, e given as 4 little-endian limbs < 2^255 */
static void fe_pow(fe r, const fe a, const uint64_t e[4]) {
    fe acc = {1, 0, 0, 0};
    fe base;
    memcpy(base, a, sizeof base);
    for (int i = 254; i >= 0; i--) {
        fe_sq(acc, acc);
        if ((e[i / 64] >> (i % 64)) & 1)
            fe_mul(acc, acc, base);
    }
    memcpy(r, acc, sizeof acc);
}

static void fe_inv(fe r, const fe a) {
    static const uint64_t PM2[4] = {   /* p - 2 = 2^255 - 21 */
        0xffffffffffffffebULL, 0xffffffffffffffffULL,
        0xffffffffffffffffULL, 0x7fffffffffffffffULL
    };
    fe_pow(r, a, PM2);
}

static void fe_pow22523(fe r, const fe a) {
    static const uint64_t E[4] = {     /* (p - 5) / 8 = 2^252 - 3 */
        0xfffffffffffffffdULL, 0xffffffffffffffffULL,
        0xffffffffffffffffULL, 0x0fffffffffffffffULL
    };
    fe_pow(r, a, E);
}

static int fe_equal(const fe a, const fe b) {
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
}

static void fe_tobytes(unsigned char out[32], const fe a) {
    fe t;
    memcpy(t, a, sizeof t);
    fe_csub(t);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (unsigned char)(t[i] >> (j * 8));
}

static void fe_frombytes(fe r, const unsigned char in[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++)
            v |= (uint64_t)in[i * 8 + j] << (j * 8);
        r[i] = v;
    }
    r[3] &= 0x7fffffffffffffffULL;   /* top bit is the sign, not value */
    fe_csub(r);                      /* < 2^255, at most p + 18 */
}

/* ---- group: edwards25519, extended coordinates (X:Y:Z:T), a = -1 ---- */

typedef struct { fe X, Y, Z, T; } ge;

static const ge GE_B = {{   /* the base point, T = X*Y */
    0xc9562d608f25d51aULL, 0x692cc7609525a7b2ULL,
    0xc0a4e231fdd6dc5cULL, 0x216936d3cd6e53feULL
}, {
    0x6666666666666658ULL, 0x6666666666666666ULL,
    0x6666666666666666ULL, 0x6666666666666666ULL
}, {1, 0, 0, 0}, {
    0x6dde8ab3a5b7dda3ULL, 0x20f09f80775152f5ULL,
    0x66ea4e8e64abe37dULL, 0x67875f0fd78b7665ULL
}};

/* add-2008-hwcd-3: complete for edwards25519 (d is a non-square), so the
 * identity and equal inputs need no special cases */
static void ge_add(ge *r, const ge *p, const ge *q) {
    fe a, b, c, d, e, f, g, h, t1, t2;
    fe_sub(t1, p->Y, p->X);
    fe_sub(t2, q->Y, q->X);
    fe_mul(a, t1, t2);
    fe_add(t1, p->Y, p->X);
    fe_add(t2, q->Y, q->X);
    fe_mul(b, t1, t2);
    fe_mul(t1, p->T, q->T);
    fe_mul(c, t1, FE_D2);
    fe_mul(t1, p->Z, q->Z);
    fe_add(d, t1, t1);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

/* dbl-2008-hwcd */
static void ge_dbl(ge *r, const ge *p) {
    fe a, b, c, d, e, f, g, h, t;
    fe_sq(a, p->X);
    fe_sq(b, p->Y);
    fe_sq(t, p->Z);
    fe_add(c, t, t);
    fe_neg(d, a);
    fe_add(t, p->X, p->Y);
    fe_sq(e, t);
    fe_sub(e, e, a);
    fe_sub(e, e, b);
    fe_add(g, d, b);
    fe_sub(f, g, c);
    fe_sub(h, d, b);
    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

static void ge_scalarmult(ge *r, const ge *p, const unsigned char s[32]) {
    ge acc = {{0,0,0,0}, {1,0,0,0}, {1,0,0,0}, {0,0,0,0}};   /* identity */
    ge base = *p;
    for (int i = 0; i < 256; i++) {
        if ((s[i / 8] >> (i % 8)) & 1)
            ge_add(&acc, &acc, &base);
        ge_dbl(&base, &base);
    }
    *r = acc;
}

/* decode y + sign into a point. 0 on success, -1 when no x exists. */
static int ge_frombytes(ge *r, const unsigned char in[32]) {
    fe y, u, v, x, check;
    fe_frombytes(y, in);
    fe one = {1, 0, 0, 0};
    fe_sq(u, y);
    fe_sub(u, u, one);              /* y^2 - 1 */
    fe_sq(v, y);
    fe_mul(v, v, FE_D);
    fe_add(v, v, one);              /* d*y^2 + 1 */
    /* x = sqrt(u/v): the p = 5 (mod 8) candidate (u v^3)(u v^7)^((p-5)/8) */
    fe uv3, uv7, cand, v2, v4;
    fe_sq(v2, v);
    fe_mul(uv3, v2, v);
    fe_mul(uv3, uv3, u);            /* u v^3 */
    fe_sq(v4, v2);
    fe_mul(uv7, v4, v2);
    fe_mul(uv7, uv7, v);
    fe_mul(uv7, uv7, u);            /* u v^7 */
    fe_pow22523(cand, uv7);
    fe_mul(x, uv3, cand);
    fe_sq(check, x);
    fe_mul(check, check, v);        /* v x^2 = u (or -u) on success */
    if (!fe_equal(check, u)) {
        fe neg_u;
        fe_neg(neg_u, u);
        if (!fe_equal(check, neg_u))
            return -1;
        fe_mul(x, x, FE_SQRTM1);
    }
    if (fe_iszero(x) && (in[31] >> 7))
        return -1;
    if ((x[0] & 1) != (in[31] >> 7))
        fe_neg(x, x);
    memcpy(r->X, x, sizeof x);
    memcpy(r->Y, y, sizeof y);
    { fe z = {1, 0, 0, 0}; memcpy(r->Z, z, sizeof z); }
    fe_mul(r->T, x, y);
    return 0;
}

static void ge_tobytes(unsigned char out[32], const ge *p) {
    fe iz, x, y;
    fe_inv(iz, p->Z);
    fe_mul(x, p->X, iz);
    fe_mul(y, p->Y, iz);
    fe_tobytes(out, y);
    out[31] |= (unsigned char)(x[0] & 1) << 7;
}

/* ---- scalars mod the group order L ---- */

static const uint64_t SC_L[4] = {
    0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL,
    0x0000000000000000ULL, 0x1000000000000000ULL
};

/* reduce a 64-byte little-endian number mod L into 32 bytes, by plain
 * long division - slow, obvious, and exactly right */
static void sc_reduce(unsigned char out[32], const unsigned char in[64]) {
    uint64_t rem[5] = {0};
    for (int i = 511; i >= 0; i--) {
        int bit = (in[i / 8] >> (i % 8)) & 1;
        uint64_t carry = bit;
        for (int j = 0; j < 5; j++) {
            uint64_t nc = rem[j] >> 63;
            rem[j] = (rem[j] << 1) | carry;
            carry = nc;
        }
        uint64_t tmp[5], bor = 0;
        for (int j = 0; j < 5; j++) {
            uint64_t lv = j < 4 ? SC_L[j] : 0;
            unsigned __int128 t = (unsigned __int128)rem[j] - lv - bor;
            tmp[j] = (uint64_t)t;
            bor = (uint64_t)(t >> 64) & 1;
        }
        if (!bor)
            memcpy(rem, tmp, sizeof tmp);
    }
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (unsigned char)(rem[i] >> (j * 8));
}

/* 1 when s < L */
static int sc_is_canonical(const unsigned char s[32]) {
    uint64_t bor = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++)
            v |= (uint64_t)s[i * 8 + j] << (j * 8);
        unsigned __int128 t = (unsigned __int128)v - SC_L[i] - bor;
        bor = (uint64_t)(t >> 64) & 1;
    }
    return bor == 1;
}

static void le_to_limbs(uint64_t out[4], const unsigned char in[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++)
            v |= (uint64_t)in[i * 8 + j] << (j * 8);
        out[i] = v;
    }
}

static void limbs_to_le(unsigned char out[32], const uint64_t in[4]) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (unsigned char)(in[i] >> (j * 8));
}

/* S = (r + k * a) mod L, all 32-byte little-endian */
static void sc_muladd(unsigned char out[32], const unsigned char r[32],
                      const unsigned char k[32], const unsigned char a[32]) {
    uint64_t av[4], kv[4], rv[4];
    le_to_limbs(av, a);
    le_to_limbs(kv, k);
    le_to_limbs(rv, r);
    unsigned __int128 acc[8] = {0};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            unsigned __int128 m = (unsigned __int128)av[i] * kv[j];
            unsigned __int128 t = acc[i + j] + (uint64_t)m;
            acc[i + j] = (uint64_t)t;
            acc[i + j + 1] += (t >> 64) + (m >> 64);
        }
    /* add r and flatten the 128-bit accumulators into 64-bit limbs */
    unsigned char prod[64];
    {
        uint64_t pl[8];
        unsigned __int128 carry = 0;
        for (int i = 0; i < 8; i++) {
            unsigned __int128 t = acc[i] + carry + (i < 4 ? rv[i] : 0);
            pl[i] = (uint64_t)t;
            carry = t >> 64;
        }
        /* k*a + r < 2^507, so carry ends at 0 */
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 8; j++)
                prod[i * 8 + j] = (unsigned char)(pl[i] >> (j * 8));
    }
    sc_reduce(out, prod);
}

/* ---- RFC 8032 ---- */

void ed25519_publickey(const unsigned char seed[32], unsigned char pk[32]) {
    unsigned char h[64];
    sha512(seed, 32, h);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    ge A;
    ge_scalarmult(&A, &GE_B, h);
    ge_tobytes(pk, &A);
}

void ed25519_sign(const unsigned char *msg, size_t len,
                  const unsigned char seed[32], const unsigned char pk[32],
                  unsigned char sig[64]) {
    unsigned char h[64];
    sha512(seed, 32, h);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    Sha512 c;
    sha512_init(&c);
    sha512_update(&c, h + 32, 32);
    sha512_update(&c, msg, len);
    unsigned char r_hash[64], r[32];
    sha512_final(&c, r_hash);
    sc_reduce(r, r_hash);
    ge R;
    ge_scalarmult(&R, &GE_B, r);
    ge_tobytes(sig, &R);
    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, len);
    unsigned char k_hash[64], k[32];
    sha512_final(&c, k_hash);
    sc_reduce(k, k_hash);
    sc_muladd(sig + 32, r, k, h);
}

int ed25519_verify(const unsigned char *msg, size_t len,
                   const unsigned char pk[32], const unsigned char sig[64]) {
    if (!sc_is_canonical(sig + 32))
        return 0;
    ge A, R;
    if (ge_frombytes(&A, pk) != 0)
        return 0;
    if (ge_frombytes(&R, sig) != 0)
        return 0;
    Sha512 c;
    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, len);
    unsigned char k_hash[64], k[32];
    sha512_final(&c, k_hash);
    sc_reduce(k, k_hash);
    ge left, kA, right;
    ge_scalarmult(&left, &GE_B, sig + 32);
    ge_scalarmult(&kA, &A, k);
    ge_add(&right, &R, &kA);
    unsigned char lb[32], rb[32];
    ge_tobytes(lb, &left);
    ge_tobytes(rb, &right);
    return memcmp(lb, rb, 32) == 0;
}
