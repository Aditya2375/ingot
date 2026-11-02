/* base58.h - Base58Check encoding (Bitcoin alphabet). */
#ifndef INGOT_BASE58_H
#define INGOT_BASE58_H

#include <stddef.h>

/* Encode payload||checksum4 as base58. out must hold 2*len + 8 bytes.
 * Returns the string length, or 0 on overflow. */
size_t base58check_encode(const void *payload, size_t len, char *out, size_t cap);

/* Decode a base58check string, verifying the checksum. Returns the
 * payload length, or 0 on malformed input or a bad checksum. */
size_t base58check_decode(const char *s, void *out, size_t cap);

#endif
