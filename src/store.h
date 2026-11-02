/* store.h - append-only block persistence.
 *
 * blocks.dat is a sequence of records: magic u32, length u32, then the
 * serialized block. Loading replays the file through ingot_chain_add,
 * so a torn tail record or a flipped byte is caught by the same
 * validation as anything arriving from the network. */
#ifndef INGOT_STORE_H
#define INGOT_STORE_H

#include "chain.h"

/* Replay every record into the chain. Returns the number of blocks
 * connected or kept as side branches, -1 when the file is unreadable
 * in a way that is not just "does not exist yet". */
int ingot_store_load(IngotChain *c, const char *path);

/* Append one block. Returns 0, -1 on I/O error. */
int ingot_store_append(const char *path, const IngotBlock *b);

#endif
