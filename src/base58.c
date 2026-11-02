#include "base58.h"
#include "sha256.h"
#include <string.h>

static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int b58val(char c) {
    const char *p = strchr(B58, c);
    return p ? (int)(p - B58) : -1;
}

/* raw base58 of a byte string, leading zero bytes becoming '1's */
static size_t b58_encode(const unsigned char *in, size_t len, char *out, size_t cap) {
    /* count leading zeros */
    size_t zeros = 0;
    while (zeros < len && in[zeros] == 0)
        zeros++;
    /* convert: repeated division of the big number by 58 */
    unsigned char work[256];
    if (len > sizeof work)
        return 0;
    memcpy(work, in, len);
    char tmp[512];
    size_t n = 0, start = zeros;
    while (start < len) {
        int rem = 0;
        for (size_t i = start; i < len; i++) {
            int v = rem * 256 + work[i];
            work[i] = (unsigned char)(v / 58);
            rem = v % 58;
        }
        if (n >= sizeof tmp)
            return 0;
        tmp[n++] = B58[rem];
        while (start < len && work[start] == 0)
            start++;
    }
    if (zeros + n + 1 > cap)
        return 0;
    size_t o = 0;
    for (size_t i = 0; i < zeros; i++)
        out[o++] = '1';
    while (n)
        out[o++] = tmp[--n];
    out[o] = '\0';
    return o;
}

static size_t b58_decode(const char *s, unsigned char *out, size_t cap) {
    size_t len = strlen(s);
    if (len == 0)
        return 0;
    /* leading '1's are zero bytes */
    size_t zeros = 0;
    while (s[zeros] == '1')
        zeros++;
    unsigned char work[512];
    memset(work, 0, sizeof work);
    size_t wlen = 1;   /* big-endian accumulator length used */
    for (size_t i = zeros; i < len; i++) {
        int v = b58val(s[i]);
        if (v < 0)
            return 0;
        int carry = v;
        size_t j = sizeof work;
        for (size_t used = 0; used < wlen; used++) {
            j--;
            int cur = work[j] * 58 + carry;
            work[j] = (unsigned char)cur;
            carry = cur >> 8;
        }
        while (carry) {
            if (j == 0 || wlen >= sizeof work)
                return 0;
            work[--j] = (unsigned char)carry;
            carry >>= 8;
            wlen++;
        }
    }
    if (zeros + wlen > cap)
        return 0;
    memset(out, 0, zeros);
    memcpy(out + zeros, work + sizeof work - wlen, wlen);
    return zeros + wlen;
}

size_t base58check_encode(const void *payload, size_t len, char *out, size_t cap) {
    unsigned char buf[260];
    if (len > 256)
        return 0;
    memcpy(buf, payload, len);
    unsigned char d[32];
    sha256d(buf, len, d);
    memcpy(buf + len, d, 4);
    return b58_encode(buf, len + 4, out, cap);
}

size_t base58check_decode(const char *s, void *out, size_t cap) {
    unsigned char buf[512];
    size_t n = b58_decode(s, buf, sizeof buf);
    if (n < 4)
        return 0;
    unsigned char d[32];
    sha256d(buf, n - 4, d);
    if (memcmp(d, buf + n - 4, 4) != 0)
        return 0;
    if (n - 4 > cap)
        return 0;
    memcpy(out, buf, n - 4);
    return n - 4;
}
