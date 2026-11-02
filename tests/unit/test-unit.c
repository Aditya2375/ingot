/* test-unit.c - the unit suite: every check prints ok/NOK via CHECK. */
#include "../../src/sha256.h"
#include "../../src/sha512.h"
#include "../../src/ed25519.h"
#include "../../src/base58.h"
#include "../../src/keys.h"
#include "../../src/tx.h"
#include "../../src/block.h"
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

    /* ---- Base58Check ---- */
    {
        char b58[512];
        unsigned char back[260];
        /* known vector: 0x00 + 20 zero hash bytes -> the Bitcoin address
         * for the all-zero hash */
        unsigned char zero21[21] = {0};
        size_t n = base58check_encode(zero21, 21, b58, sizeof b58);
        CHECK(n > 0 && strcmp(b58, "1111111111111111111114oLvT2") == 0,
              "base58check of the all-zero payload");
        n = base58check_decode("1111111111111111111114oLvT2", back, sizeof back);
        CHECK(n == 21 && memcmp(back, zero21, 21) == 0, "base58check round-trips zeros");
        /* a random-ish payload round-trips */
        unsigned char pay[25];
        for (int i = 0; i < 25; i++) pay[i] = (unsigned char)(i * 7 + 3);
        n = base58check_encode(pay, 25, b58, sizeof b58);
        CHECK(n > 0, "base58check encodes 25 bytes");
        n = base58check_decode(b58, back, sizeof back);
        CHECK(n == 25 && memcmp(back, pay, 25) == 0, "base58check round-trips 25 bytes");
        /* a corrupted string fails the checksum */
        b58[5] = b58[5] == 'z' ? 'y' : 'z';
        CHECK(base58check_decode(b58, back, sizeof back) == 0,
              "a corrupted base58check string is rejected");
        CHECK(base58check_decode("0OIl", back, sizeof back) == 0,
              "non-base58 characters are rejected");
    }

    /* ---- keys and addresses ---- */
    {
        unsigned char seed[32], pk[32], hash[INGOT_ADDR_HASH_LEN];
        for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(i * 3 + 1);
        ingot_pubkey(seed, pk);
        char addr[64];
        size_t n = ingot_address(pk, addr, sizeof addr);
        CHECK(n > 0 && addr[0] == 'i', "addresses start with i");
        CHECK(ingot_address_parse(addr, hash) == 1, "an address parses back");
        unsigned char want[INGOT_ADDR_HASH_LEN];
        ingot_addr_hash(pk, want);
        CHECK(memcmp(hash, want, INGOT_ADDR_HASH_LEN) == 0, "the hash round-trips");
        CHECK(ingot_address_parse("1111111111111111111114oLvT2", hash) == 0,
              "a foreign version byte is rejected");
        addr[n - 2] = addr[n - 2] == 'x' ? 'y' : 'x';
        CHECK(ingot_address_parse(addr, hash) == 0, "a corrupted address is rejected");
    }

    /* ---- transactions ---- */
    {
        unsigned char seed_a[32], seed_b[32], pk_a[32];
        for (int i = 0; i < 32; i++) {
            seed_a[i] = (unsigned char)(i + 9);
            seed_b[i] = (unsigned char)(i * 5 + 2);
        }
        ingot_pubkey(seed_a, pk_a);
        IngotTx tx;
        memset(&tx, 0, sizeof tx);
        tx.n_in = 1;
        memset(tx.in[0].prev_txid, 7, 32);
        tx.in[0].index = 3;
        tx.n_out = 2;
        tx.out[0].amount = 5 * INGOT_COIN;
        ingot_addr_hash(pk_a, tx.out[0].addr);
        tx.out[1].amount = 2500000000ULL;
        memset(tx.out[1].addr, 9, INGOT_ADDR_HASH_LEN);
        ingot_tx_sign(&tx, 0, seed_a);
        CHECK(ingot_tx_input_valid(&tx, 0) == 1, "a signed input validates");
        /* the same signature under another key does not */
        unsigned char keep[64], keep_pk[32];
        memcpy(keep, tx.in[0].sig, 64);
        memcpy(keep_pk, tx.in[0].pubkey, 32);
        ingot_tx_sign(&tx, 0, seed_b);
        CHECK(memcmp(keep, tx.in[0].sig, 64) != 0, "different keys sign differently");
        memcpy(tx.in[0].sig, keep, 64);
        memcpy(tx.in[0].pubkey, keep_pk, 32);
        /* tampering with an output invalidates the input */
        tx.out[0].amount++;
        CHECK(ingot_tx_input_valid(&tx, 0) == 0, "a tampered output breaks the signature");
        tx.out[0].amount--;
        CHECK(ingot_tx_input_valid(&tx, 0) == 1, "restored output validates again");
        /* serialization round-trips */
        unsigned char buf[4096];
        size_t n = ingot_tx_serialize(&tx, 1, buf, sizeof buf);
        IngotTx back;
        CHECK(n > 0 && ingot_tx_parse(buf, n, &back) == n, "a transaction round-trips");
        CHECK(back.n_in == 1 && back.n_out == 2 &&
              back.out[1].amount == 2500000000ULL &&
              memcmp(back.in[0].sig, tx.in[0].sig, 64) == 0,
              "the parsed transaction matches");
        unsigned char id1[32], id2[32];
        ingot_txid(&tx, id1);
        ingot_txid(&back, id2);
        CHECK(memcmp(id1, id2, 32) == 0, "txid survives a round-trip");
        /* the txid commits to the signature: a different sig, different id */
        back.in[0].sig[0] ^= 1;
        ingot_txid(&back, id2);
        CHECK(memcmp(id1, id2, 32) != 0, "the txid commits to signatures");
        /* truncated parses fail */
        CHECK(ingot_tx_parse(buf, n - 1, &back) == 0, "a truncated transaction fails");
    }

    /* ---- blocks, targets, merkle ---- */
    {
        unsigned char target[32];
        ingot_bits_to_target(0x1d00ffff, target);
        CHECK(target[0] == 0 && target[3] == 0 && target[4] == 0xff &&
              target[5] == 0xff, "compact bits lay the mantissa out big-endian");
        uint32_t bits = ingot_target_to_bits(target);
        CHECK(bits == 0x1d00ffff, "compact bits round-trip");
        /* harder target, lower work estimate ordering */
        unsigned __int128 w_easy, w_hard;
        ingot_bits_work(0x1d00ffff, &w_easy);
        ingot_bits_to_target(0x1c00ffff, target);
        bits = ingot_target_to_bits(target);
        CHECK(bits == 0x1c00ffff, "a smaller exponent round-trips");
        ingot_bits_work(0x1c00ffff, &w_hard);
        CHECK(w_hard > w_easy, "a smaller target is more work");
        /* hash comparison is big-endian numeric */
        unsigned char h[32], t2[32];
        memset(h, 0x00, 32); h[31] = 5;
        memset(t2, 0x00, 32); t2[31] = 6;
        CHECK(ingot_hash_meets(h, t2) == 1, "a smaller hash meets the target");
        CHECK(ingot_hash_meets(t2, h) == 0, "a larger hash does not");

        /* a tiny mined block passes its own PoW and round-trips */
        IngotBlock b;
        memset(&b, 0, sizeof b);
        b.h.version = 1;
        b.h.time = 1700000000;
        b.h.bits = 0x207fffff;   /* comically easy: target with top byte 0x7f */
        b.n_tx = 1;
        b.tx[0].coinbase = 1;
        b.tx[0].n_in = 1;
        b.tx[0].n_out = 1;
        b.tx[0].out[0].amount = 50 * INGOT_COIN;
        memset(b.tx[0].out[0].addr, 3, INGOT_ADDR_HASH_LEN);
        ingot_merkle(&b, b.h.merkle);
        unsigned char hash[32];
        int mined = 0;
        for (uint64_t nonce = 0; nonce < 5000000 && !mined; nonce++) {
            b.h.nonce = (uint32_t)nonce;
            ingot_block_hash(&b, hash);
            ingot_bits_to_target(b.h.bits, t2);
            if (ingot_hash_meets(hash, t2))
                mined = 1;
        }
        CHECK(mined, "the easy block mines within the nonce budget");
        CHECK(ingot_block_pow_valid(&b) == 1, "the mined block passes PoW");
        b.h.merkle[0] ^= 1;
        CHECK(ingot_block_pow_valid(&b) == 0, "a wrong merkle root fails");
        ingot_merkle(&b, b.h.merkle);
        static unsigned char wbuf[INGOT_MAX_BLOCK_SIZE];
        size_t n = ingot_block_serialize(&b, wbuf, sizeof wbuf);
        IngotBlock back;
        CHECK(n > 0 && ingot_block_parse(wbuf, n, &back) == n, "a block round-trips");
        unsigned char id1[32], id2[32];
        ingot_block_hash(&b, id1);
        ingot_block_hash(&back, id2);
        CHECK(memcmp(id1, id2, 32) == 0, "the block hash survives parsing");
        /* merkle commits to every transaction */
        back.tx[0].out[0].amount++;
        ingot_merkle(&back, id2);
        CHECK(memcmp(id1, id2, 32) != 0, "a tampered tx changes the merkle root");
    }

    printf("%d checks passed\n", checks);
    return fails ? 1 : 0;
}
