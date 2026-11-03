#include "net.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#define NET_MAGIC 0x54474e49u
#define MSG_HELLO     1
#define MSG_GETBLOCKS 2
#define MSG_BLOCK     3
#define MSG_TX        4

enum { HDR = 9, RBUF_INIT = 1 << 16, WBUF_INIT = 1 << 16 };

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ? -1 : 0;
}

static int peer_send(IngotNet *n, IngotPeer *p, uint8_t type,
                     const void *payload, uint32_t len) {
    if (len + HDR > INGOT_MSG_MAX)
        return -1;
    size_t need = p->wlen + HDR + len;
    if (need > INGOT_PEER_WMAX)
        return -1;   /* slow peer: the caller drops it */
    if (need > p->wcap) {
        size_t cap = p->wcap ? p->wcap : WBUF_INIT;
        while (cap < need)
            cap *= 2;
        unsigned char *nb = realloc(p->wbuf, cap);
        if (!nb)
            return -1;
        p->wbuf = nb;
        p->wcap = cap;
    }
    unsigned char *w = p->wbuf + p->wlen;
    uint32_t magic = NET_MAGIC, l32 = len;
    memcpy(w, &magic, 4);
    w[4] = type;
    memcpy(w + 5, &l32, 4);
    if (len)
        memcpy(w + HDR, payload, len);
    p->wlen = need;
    /* Queueing is not sending: arm EPOLLOUT now. Broadcasts from the
     * mining path happen on turns where this peer has no event, so
     * waiting for its next event to arm would park the bytes forever. */
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.ptr = p;
    epoll_ctl(n->epfd, EPOLL_CTL_MOD, p->fd, &ev);
    return 0;
}

static void broadcast(IngotNet *n, int skip, uint8_t type, const void *pl, uint32_t len) {
    for (int i = 0; i < INGOT_MAX_PEERS; i++)
        if (n->peers[i].fd >= 0 && i != skip)
            peer_send(n, &n->peers[i], type, pl, len);
}

static void peer_drop(IngotNet *n, int i) {
    IngotPeer *p = &n->peers[i];
    if (p->fd >= 0) {
        fprintf(stderr, "[net] peer %d dropped\n", i);
        epoll_ctl(n->epfd, EPOLL_CTL_DEL, p->fd, NULL);
        close(p->fd);
    }
    free(p->rbuf);
    free(p->wbuf);
    memset(p, 0, sizeof *p);
    p->fd = -1;
}

static void peer_arm(IngotNet *n, IngotPeer *p) {
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | (p->wlen > p->wsent ? EPOLLOUT : 0);
    ev.data.ptr = p;
    epoll_ctl(n->epfd, EPOLL_CTL_MOD, p->fd, &ev);
}

static void request_sync(IngotNet *n, IngotPeer *p) {
    uint32_t from = (uint32_t)ingot_chain_height(n->chain) + 1;
    peer_send(n, p, MSG_GETBLOCKS, &from, 4);
}

static void send_hello(IngotNet *n, IngotPeer *p) {
    uint32_t h = (uint32_t)ingot_chain_height(n->chain);
    peer_send(n, p, MSG_HELLO, &h, 4);
}

/* main-chain block at height h, or NULL */
static const IngotNode *main_at(const IngotChain *c, uint32_t h) {
    for (int i = 0; i < c->n_nodes; i++)
        if (c->nodes[i]->main && c->nodes[i]->height == h)
            return c->nodes[i];
    return NULL;
}

static void handle_msg(IngotNet *n, int pi, uint8_t type,
                       const unsigned char *pl, uint32_t len) {
    IngotPeer *p = &n->peers[pi];
    switch (type) {
    case MSG_HELLO: {
        if (len != 4) break;
        uint32_t their_h;
        memcpy(&their_h, pl, 4);
        p->helloed = 1;
        if ((int)their_h > ingot_chain_height(n->chain))
            request_sync(n, p);
        break;
    }
    case MSG_GETBLOCKS: {
        if (len != 4) break;
        uint32_t from;
        memcpy(&from, pl, 4);
        uint32_t tip = (uint32_t)ingot_chain_height(n->chain);
        static unsigned char buf[INGOT_MAX_BLOCK_SIZE];
        for (uint32_t h = from, sent = 0; h <= tip && sent < INGOT_SYNC_BATCH; h++) {
            const IngotNode *node = main_at(n->chain, h);
            if (!node)
                continue;
            size_t blen = ingot_block_serialize(&node->b, buf, sizeof buf);
            if (blen && peer_send(n, p, MSG_BLOCK, buf, (uint32_t)blen) == 0)
                sent++;
        }
        break;
    }
    case MSG_BLOCK: {
        IngotBlock *b = malloc(sizeof *b);
        if (!b) break;
        if (ingot_block_parse(pl, len, b) != len) {
            free(b);
            break;
        }
        IngotErr e = ingot_chain_add(n->chain, b);
        if (e != INGOT_OK && e != INGOT_ERR_DUP)
            fprintf(stderr, "[net] block from peer %d: %s (tip %d)\n",
                    pi, ingot_err_str(e), ingot_chain_height(n->chain));
        if (e == INGOT_OK) {
            ingot_store_append(n->store_path, b);
            broadcast(n, pi, MSG_BLOCK, pl, len);
            /* still behind? ask for more */
            const IngotNode *tip = ingot_chain_tip(n->chain);
            unsigned char bh[32];
            ingot_block_hash(b, bh);
            if (memcmp(tip->hash, bh, 32) != 0)
                request_sync(n, p);
        } else if (e == INGOT_ERR_ORPHAN) {
            request_sync(n, p);
        }
        free(b);
        break;
    }
    case MSG_TX: {
        IngotTx *tx = malloc(sizeof *tx);
        if (!tx) break;
        if (ingot_tx_parse(pl, len, tx) == len) {
            IngotErr e = ingot_mempool_add(n->chain, tx);
            if (e == INGOT_OK) {
                fprintf(stderr, "[net] tx accepted from peer %d (mempool %d)\n",
                        pi, n->chain->n_mempool);
                broadcast(n, pi, MSG_TX, pl, len);
            } else {
                fprintf(stderr, "[net] tx from peer %d rejected: %s\n", pi, ingot_err_str(e));
            }
        }
        free(tx);
        break;
    }
    }
}

static void peer_read(IngotNet *n, int i) {
    IngotPeer *p = &n->peers[i];
    if (p->rlen == p->rcap) {
        size_t cap = p->rcap ? p->rcap * 2 : RBUF_INIT;
        if (cap > INGOT_MSG_MAX * 2) {
            peer_drop(n, i);
            return;
        }
        unsigned char *nb = realloc(p->rbuf, cap);
        if (!nb) {
            peer_drop(n, i);
            return;
        }
        p->rbuf = nb;
        p->rcap = cap;
    }
    ssize_t r = recv(p->fd, p->rbuf + p->rlen, p->rcap - p->rlen, 0);
    if (r <= 0) {
        if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
            peer_drop(n, i);
        return;
    }
    p->rlen += (size_t)r;
    size_t off = 0;
    while (p->rlen - off >= HDR) {
        uint32_t magic, len;
        memcpy(&magic, p->rbuf + off, 4);
        memcpy(&len, p->rbuf + off + 5, 4);
        if (magic != NET_MAGIC || len > INGOT_MSG_MAX) {
            peer_drop(n, i);
            return;
        }
        if (p->rlen - off < HDR + len)
            break;
        handle_msg(n, i, p->rbuf[off + 4], p->rbuf + off + HDR, len);
        off += HDR + len;
    }
    memmove(p->rbuf, p->rbuf + off, p->rlen - off);
    p->rlen -= off;
}

static void peer_write(IngotNet *n, int i) {
    IngotPeer *p = &n->peers[i];
    while (p->wsent < p->wlen) {
        ssize_t w = send(p->fd, p->wbuf + p->wsent, p->wlen - p->wsent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                peer_drop(n, i);
            return;
        }
        p->wsent += (size_t)w;
    }
    p->wlen = p->wsent = 0;
}

static void peer_add(IngotNet *n, int fd) {
    for (int i = 0; i < INGOT_MAX_PEERS; i++) {
        if (n->peers[i].fd < 0) {
            IngotPeer *p = &n->peers[i];
            memset(p, 0, sizeof *p);
            p->fd = fd;
            struct epoll_event ev = {0};
            ev.events = EPOLLIN;
            ev.data.ptr = p;
            epoll_ctl(n->epfd, EPOLL_CTL_ADD, fd, &ev);
            send_hello(n, p);
            peer_arm(n, p);
            return;
        }
    }
    close(fd);   /* peer table full */
}

int ingot_net_init(IngotNet *n, IngotChain *c, const char *store_path, uint16_t port) {
    memset(n, 0, sizeof *n);
    n->chain = c;
    n->store_path = store_path;
    for (int i = 0; i < INGOT_MAX_PEERS; i++)
        n->peers[i].fd = -1;
    n->epfd = epoll_create1(0);
    n->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (n->epfd < 0 || n->listen_fd < 0)
        return -1;
    int one = 1;
    setsockopt(n->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);
    if (bind(n->listen_fd, (struct sockaddr *)&sa, sizeof sa) < 0 ||
        listen(n->listen_fd, 16) < 0 || set_nonblock(n->listen_fd) < 0)
        return -1;
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;   /* the listen socket */
    epoll_ctl(n->epfd, EPOLL_CTL_ADD, n->listen_fd, &ev);
    return 0;
}

int ingot_net_connect(IngotNet *n, const char *host, uint16_t port) {
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
        return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    int ok = -1;
    if (fd >= 0) {
        if (connect(fd, res->ai_addr, res->ai_addrlen) == 0 && set_nonblock(fd) == 0) {
            peer_add(n, fd);
            ok = 0;
        } else {
            close(fd);
        }
    }
    freeaddrinfo(res);
    return ok;
}

void ingot_net_broadcast_tx(IngotNet *n, const IngotTx *tx) {
    static unsigned char buf[8 + INGOT_MAX_TX_IN * 132 + INGOT_MAX_TX_OUT * 28];
    size_t len = ingot_tx_serialize(tx, 1, buf, sizeof buf);
    if (len)
        broadcast(n, -1, MSG_TX, buf, (uint32_t)len);
}

void ingot_net_mine(IngotNet *n, const unsigned char addr[INGOT_ADDR_HASH_LEN],
                    uint32_t tries_per_turn) {
    n->mine_addr = addr;
    n->mine_tries = tries_per_turn;
}

int ingot_net_push_tx(const char *host, uint16_t port, const IngotTx *tx) {
    static unsigned char buf[8 + INGOT_MAX_TX_IN * 132 + INGOT_MAX_TX_OUT * 28];
    size_t len = ingot_tx_serialize(tx, 1, buf, sizeof buf);
    if (!len)
        return -1;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%u", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
        return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    int ok = -1;
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
        unsigned char hdr[HDR];
        uint32_t magic = NET_MAGIC, l32 = (uint32_t)len;
        memcpy(hdr, &magic, 4);
        hdr[4] = MSG_TX;
        memcpy(hdr + 5, &l32, 4);
        ok = send(fd, hdr, HDR, MSG_NOSIGNAL) == HDR &&
             send(fd, buf, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
    }
    if (fd >= 0)
        close(fd);
    freeaddrinfo(res);
    return ok;
}

static uint32_t wall_now(void) {
    return (uint32_t)time(NULL);
}

void ingot_net_run(IngotNet *n) {
    n->running = 1;
    IngotBlock *tmpl = malloc(sizeof *tmpl);
    int have_tmpl = 0;
    while (n->running) {
        struct epoll_event evs[16];
        int nev = epoll_wait(n->epfd, evs, 16, 20);
        for (int i = 0; i < nev; i++) {
            if (!evs[i].data.ptr) {
                int fd = accept(n->listen_fd, NULL, NULL);
                if (fd >= 0) {
                    if (set_nonblock(fd) == 0)
                        peer_add(n, fd);
                    else
                        close(fd);
                }
                continue;
            }
            IngotPeer *p = evs[i].data.ptr;
            int idx = (int)(p - n->peers);
            if (evs[i].events & EPOLLIN)
                peer_read(n, idx);
            if (n->peers[idx].fd >= 0 && (evs[i].events & EPOLLOUT))
                peer_write(n, idx);
            if (n->peers[idx].fd >= 0)
                peer_arm(n, &n->peers[idx]);
        }
        if (n->mine_addr) {
            if (!have_tmpl || tmpl->n_tx - 1 != n->chain->n_mempool) {
                /* fresh tip, or the mempool gained a transaction worth
                 * including */
                ingot_miner_template(n->chain, n->mine_addr, tmpl);
                have_tmpl = 1;
            }
            /* Pace to the wall clock: monotonic timestamps force each
             * block at least one second past its parent, and grinding
             * faster than real time would walk header times past the
             * future limit and stall the chain. Skip the turn instead. */
            if (tmpl->h.time <= wall_now() &&
                ingot_miner_grind(tmpl, n->mine_tries, wall_now)) {
                if (ingot_chain_add(n->chain, tmpl) == INGOT_OK) {
                    fprintf(stderr, "[mine] block %d (%d tx)\n",
                            ingot_chain_height(n->chain), tmpl->n_tx);
                    ingot_store_append(n->store_path, tmpl);
                    static unsigned char buf[INGOT_MAX_BLOCK_SIZE];
                    size_t len = ingot_block_serialize(tmpl, buf, sizeof buf);
                    if (len)
                        broadcast(n, -1, MSG_BLOCK, buf, (uint32_t)len);
                }
                have_tmpl = 0;
            }
            /* a new tip from the network invalidates the template */
            if (have_tmpl) {
                unsigned char th[32];
                memcpy(th, ingot_chain_tip(n->chain)->hash, 32);
                if (memcmp(tmpl->h.prev, th, 32) != 0)
                    have_tmpl = 0;
            }
        }
    }
    free(tmpl);
}
