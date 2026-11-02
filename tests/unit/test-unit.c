/* test-unit.c - the unit suite: every check prints ok/NOK via CHECK. */
#include "../../src/sha256.h"
#include "../../src/sha512.h"
#include "../../src/ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, fails;
#define CHECK(cond, msg) do { \
    checks++; \
    if (!(cond)) { fails++; printf("NOK %d: %s\n", checks, msg); } \
} while (0)

static int hexv(int c) {
    return c <= '9' ? c - '0' : c <= 'f' ? c - 'a' + 10 : c - 'A' + 10;
}

static void hex(const unsigned char *b, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = h[b[i] >> 4];
        out[i * 2 + 1] = h[b[i] & 15];
    }
    out[n * 2] = '\0';
}

int main(void) {
    /* ---- SHA-256: FIPS 180-4 and project vectors ---- */
    unsigned char d[32];
    char h[65];
    sha256("", 0, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "sha256 of empty");
    sha256("abc", 3, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "sha256 of abc");
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
          "sha256 of the 56-byte vector");

    /* a million 'a' characters, fed in awkward dribbles to exercise the
     * buffering */
    Sha256 c;
    sha256_init(&c);
    char chunk[997];
    memset(chunk, 'a', sizeof chunk);
    size_t fed = 0;
    while (fed < 1000000) {
        size_t take = 1000000 - fed;
        if (take > sizeof chunk) take = sizeof chunk;
        sha256_update(&c, chunk, take);
        fed += take;
    }
    sha256_final(&c, d);
    hex(d, 32, h);
    CHECK(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
          "sha256 of a million a's in 997-byte dribbles");

    /* double-SHA-256 differs from a single pass */
    unsigned char d2[32];
    sha256d("abc", 3, d2);
    CHECK(memcmp(d, d2, 32) != 0, "sha256d is not a single pass");
    /* and matches sha256(sha256(x)) computed by hand */
    unsigned char t1[32];
    sha256("abc", 3, t1);
    sha256(t1, 32, t1);
    CHECK(memcmp(d2, t1, 32) == 0, "sha256d composes two passes");

    /* ---- SHA-512: FIPS 180-4 vectors ---- */
    {
        unsigned char d512[64];
        char h512[129];
        sha512("abc", 3, d512);
        static const char hexd[] = "0123456789abcdef";
        for (int i = 0; i < 64; i++) {
            h512[i * 2] = hexd[d512[i] >> 4];
            h512[i * 2 + 1] = hexd[d512[i] & 15];
        }
        h512[128] = '\0';
        CHECK(strcmp(h512,
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") == 0,
              "sha512 of abc");
        sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
               "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, d512);
        for (int i = 0; i < 64; i++) {
            h512[i * 2] = hexd[d512[i] >> 4];
            h512[i * 2 + 1] = hexd[d512[i] & 15];
        }
        CHECK(strcmp(h512,
              "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
              "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909") == 0,
              "sha512 of the 112-byte vector");
    }

    /* ---- Ed25519: RFC 8032 test vectors ---- */
    {
        unsigned char sk[32], pk[32], sig[64], want[128];
        const char *sk1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        const char *pk1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        const char *sig1 =
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        for (int i = 0; i < 32; i++)
            sk[i] = (unsigned char)(hexv(sk1[i*2]) * 16 + hexv(sk1[i*2+1]));
        ed25519_publickey(sk, pk);
        for (int i = 0; i < 32; i++)
            want[i] = (unsigned char)(hexv(pk1[i*2]) * 16 + hexv(pk1[i*2+1]));
        CHECK(memcmp(pk, want, 32) == 0, "ed25519 vector 1 public key");
        ed25519_sign((const unsigned char *)"", 0, sk, pk, sig);
        for (int i = 0; i < 64; i++)
            want[i] = (unsigned char)(hexv(sig1[i*2]) * 16 + hexv(sig1[i*2+1]));
        CHECK(memcmp(sig, want, 64) == 0, "ed25519 vector 1 signature");
        CHECK(ed25519_verify((const unsigned char *)"", 0, pk, sig) == 1,
              "ed25519 vector 1 verifies");

        const char *sk2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        const char *pk2 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        const char *sig2 =
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
        unsigned char msg2[1] = {0x72};
        for (int i = 0; i < 32; i++)
            sk[i] = (unsigned char)(hexv(sk2[i*2]) * 16 + hexv(sk2[i*2+1]));
        ed25519_publickey(sk, pk);
        for (int i = 0; i < 32; i++)
            want[i] = (unsigned char)(hexv(pk2[i*2]) * 16 + hexv(pk2[i*2+1]));
        CHECK(memcmp(pk, want, 32) == 0, "ed25519 vector 2 public key");
        ed25519_sign(msg2, 1, sk, pk, sig);
        for (int i = 0; i < 64; i++)
            want[i] = (unsigned char)(hexv(sig2[i*2]) * 16 + hexv(sig2[i*2+1]));
        CHECK(memcmp(sig, want, 64) == 0, "ed25519 vector 2 signature");
        CHECK(ed25519_verify(msg2, 1, pk, sig) == 1, "ed25519 vector 2 verifies");

        /* tampered message or signature must not verify */
        CHECK(ed25519_verify(msg2, 1, pk, sig) == 1, "vector 2 still verifies");
        sig[0] ^= 1;
        CHECK(ed25519_verify(msg2, 1, pk, sig) == 0, "a tampered R fails");
        sig[0] ^= 1;
        sig[40] ^= 1;
        CHECK(ed25519_verify(msg2, 1, pk, sig) == 0, "a tampered S fails");
        sig[40] ^= 1;
        msg2[0] ^= 1;
        CHECK(ed25519_verify(msg2, 1, pk, sig) == 0, "a tampered message fails");
        msg2[0] ^= 1;
        pk[0] ^= 1;
        CHECK(ed25519_verify(msg2, 1, pk, sig) == 0, "a wrong key fails");

        /* sign and verify a longer message through the streaming path */
        unsigned char big[1000];
        for (int i = 0; i < 1000; i++) big[i] = (unsigned char)i;
        for (int i = 0; i < 32; i++)
            sk[i] = (unsigned char)(hexv(sk1[i*2]) * 16 + hexv(sk1[i*2+1]));
        ed25519_publickey(sk, pk);
        ed25519_sign(big, 1000, sk, pk, sig);
        CHECK(ed25519_verify(big, 1000, pk, sig) == 1, "1 KB message round-trips");
        CHECK(ed25519_verify(big, 999, pk, sig) == 0, "a truncated message fails");
    }

    printf("%d checks passed\n", checks);
    return fails ? 1 : 0;
}
