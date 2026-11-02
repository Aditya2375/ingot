/* ed25519.h - Ed25519 signatures (RFC 8032), self-contained.
 *
 * This is a REFERENCE-STYLE implementation: simple formulas, no side-
 * channel hardening. It is NOT constant-time - fine for a toy chain and
 * browser demo, wrong for guarding real money. See the README's honest
 * limits. */
#ifndef INGOT_ED25519_H
#define INGOT_ED25519_H

#include <stddef.h>

void ed25519_publickey(const unsigned char seed[32], unsigned char pk[32]);
void ed25519_sign(const unsigned char *msg, size_t len,
                  const unsigned char seed[32], const unsigned char pk[32],
                  unsigned char sig[64]);
/* 1 when the signature verifies, 0 otherwise. */
int ed25519_verify(const unsigned char *msg, size_t len,
                   const unsigned char pk[32], const unsigned char sig[64]);

#endif
