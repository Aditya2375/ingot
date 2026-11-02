/* net.h - TCP peer sync over epoll (Linux).
 *
 * Framing: magic u32 "INGT", type u8, length u32, payload.
 * Types: HELLO (tip height u32), GETBLOCKS (start height u32), BLOCK
 * (serialized block), TX (serialized transaction).
 *
 * Gossip is push-based: a node relays every new valid block or
 * transaction to every peer but the sender. A peer that announces a
 * taller tip gets a GETBLOCKS from our height; orphans trigger the
 * same request. There is no peer scoring or banning - a misbehaving
 * peer is simply disconnected at the message-size cap. */
#ifndef INGOT_NET_H
#define INGOT_NET_H

#include "chain.h"
#include "miner.h"
#include "store.h"

#define INGOT_MAX_PEERS   32
#define INGOT_MSG_MAX     (INGOT_MAX_BLOCK_SIZE + 64)
#define INGOT_PEER_WMAX   (4 * 1024 * 1024)
#define INGOT_SYNC_BATCH  100      /* blocks sent per GETBLOCKS */

typedef struct {
    int fd;
    unsigned char *rbuf;
    size_t rlen, rcap;
    unsigned char *wbuf;
    size_t wlen, wsent, wcap;
    int helloed;
} IngotPeer;

typedef struct {
    IngotChain *chain;
    const char *store_path;
    int listen_fd, epfd;
    IngotPeer peers[INGOT_MAX_PEERS];
    const unsigned char *mine_addr;   /* NULL = do not mine */
    uint32_t mine_tries;              /* nonces per loop turn */
    int running;
} IngotNet;

int ingot_net_init(IngotNet *n, IngotChain *c, const char *store_path,
                   uint16_t port);
int ingot_net_connect(IngotNet *n, const char *host, uint16_t port);
void ingot_net_broadcast_tx(IngotNet *n, const IngotTx *tx);
void ingot_net_mine(IngotNet *n, const unsigned char addr[INGOT_ADDR_HASH_LEN],
                    uint32_t tries_per_turn);
void ingot_net_run(IngotNet *n);

/* One-shot client: connect, push one transaction, close. For the CLI;
 * returns 0 when the bytes left the machine. */
int ingot_net_push_tx(const char *host, uint16_t port, const IngotTx *tx);

#endif
