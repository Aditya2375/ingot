/* main.c - the ingot command line: wallets, a node, mining, spending. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "chain.h"
#include "miner.h"
#include "store.h"
#include "net.h"
#include "keys.h"
#include "ed25519.h"

#define INGOT_PORT 9333

static char data_dir[512];
static char store_path[560];
static char wallet_path[560];

static void paths_init(void) {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(data_dir, sizeof data_dir, "%s/.ingot", home);
    snprintf(store_path, sizeof store_path, "%s/blocks.dat", data_dir);
    snprintf(wallet_path, sizeof wallet_path, "%s/wallet", data_dir);
    if (mkdir(data_dir, 0700) != 0) {
        /* maybe the parent is missing too */
        mkdir(home, 0700);
        mkdir(data_dir, 0700);
    }
}

static void hex(const unsigned char *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", b[i]);
    out[n * 2] = 0;
}

static int unhex(const char *s, unsigned char *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + i * 2, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

static int wallet_load(unsigned char seed[32]) {
    FILE *f = fopen(wallet_path, "r");
    if (!f) return -1;
    char buf[65] = {0};
    int ok = fgets(buf, sizeof buf, f) && strlen(buf) >= 64 && unhex(buf, seed, 32) == 0;
    fclose(f);
    return ok ? 0 : -1;
}

static void wallet_addr(const unsigned char seed[32], unsigned char addr[INGOT_ADDR_HASH_LEN],
                        char addr_str[64]) {
    unsigned char pk[32];
    ed25519_publickey(seed, pk);
    ingot_addr_hash(pk, addr);
    ingot_address(pk, addr_str, 64);
}

/* coins text -> base units: "12.345678" */
static int parse_amount(const char *s, uint64_t *out) {
    uint64_t whole = 0, frac = 0, scale = 1;
    const char *dot = strchr(s, '.');
    size_t wl = dot ? (size_t)(dot - s) : strlen(s);
    if (wl == 0 || wl > 12)
        return -1;
    for (size_t i = 0; i < wl; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        whole = whole * 10 + (uint64_t)(s[i] - '0');
    }
    if (dot) {
        const char *f = dot + 1;
        size_t fl = strlen(f);
        if (fl == 0 || fl > 8) return -1;
        for (size_t i = 0; i < fl; i++) {
            if (f[i] < '0' || f[i] > '9') return -1;
            frac = frac * 10 + (uint64_t)(f[i] - '0');
            scale *= 10;
        }
        while (scale < INGOT_COIN) {
            frac *= 10;
            scale *= 10;
        }
    }
    *out = whole * INGOT_COIN + frac;
    return *out > 0 ? 0 : -1;
}

static void print_amount(uint64_t v, char *out) {
    sprintf(out, "%llu.%08llu", (unsigned long long)(v / INGOT_COIN),
            (unsigned long long)(v % INGOT_COIN));
    /* trim trailing zeros after the point, keep at least one decimal */
    char *p = out + strlen(out) - 1;
    while (p > out && p[-1] != '.' && *p == '0')
        *p-- = 0;
}

static IngotChain *chain_load(void) {
    IngotChain *c = malloc(sizeof *c);
    if (!c) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    ingot_chain_init(c);
    ingot_store_load(c, store_path);
    return c;
}

static void chain_unload(IngotChain *c) {
    ingot_chain_free(c);
    free(c);
}

static int cmd_wallet_new(void) {
    unsigned char seed[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, seed, 32) != 32) {
        fprintf(stderr, "cannot read /dev/urandom\n");
        return 1;
    }
    if (fd >= 0) close(fd);
    /* O_EXCL: overwriting an existing wallet would destroy the keys.
     * 0600 at creation: no window where the seed is group/world-readable. */
    int wfd = open(wallet_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (wfd < 0) {
        if (errno == EEXIST)
            fprintf(stderr, "wallet already exists: %s\n", wallet_path);
        else
            perror("wallet");
        return 1;
    }
    FILE *f = fdopen(wfd, "w");
    if (!f) {
        perror("wallet");
        close(wfd);
        return 1;
    }
    char h[65];
    hex(seed, 32, h);
    fprintf(f, "%s\n", h);
    fclose(f);
    unsigned char addr[INGOT_ADDR_HASH_LEN];
    char as[64];
    wallet_addr(seed, addr, as);
    printf("wallet created: %s\n", wallet_path);
    printf("address: %s\n", as);
    return 0;
}

static int cmd_address(void) {
    unsigned char seed[32], addr[INGOT_ADDR_HASH_LEN];
    char as[64];
    if (wallet_load(seed) != 0) {
        fprintf(stderr, "no wallet yet - run: ingot wallet new\n");
        return 1;
    }
    wallet_addr(seed, addr, as);
    printf("%s\n", as);
    return 0;
}

static int cmd_balance(const char *addr_str) {
    unsigned char seed[32], addr[INGOT_ADDR_HASH_LEN];
    if (addr_str) {
        if (ingot_address_parse(addr_str, addr) != 1) {
            fprintf(stderr, "bad address: %s\n", addr_str);
            return 1;
        }
    } else {
        if (wallet_load(seed) != 0) {
            fprintf(stderr, "no wallet yet - run: ingot wallet new\n");
            return 1;
        }
        char as[64];
        wallet_addr(seed, addr, as);
    }
    IngotChain *c = chain_load();
    char pretty[64];
    print_amount(ingot_chain_balance(c, addr), pretty);
    printf("%s INGOT (height %d)\n", pretty, ingot_chain_height(c));
    chain_unload(c);
    return 0;
}

static int cmd_mine(int count) {
    unsigned char seed[32], addr[INGOT_ADDR_HASH_LEN];
    char as[64];
    if (wallet_load(seed) != 0) {
        fprintf(stderr, "no wallet yet - run: ingot wallet new\n");
        return 1;
    }
    wallet_addr(seed, addr, as);
    IngotChain *c = chain_load();
    IngotBlock *b = malloc(sizeof *b);
    int mined = 0;
    for (int i = 0; i < count; i++) {
        ingot_miner_template(c, addr, b);
        if (!ingot_miner_grind(b, 1u << 26, NULL)) {
            fprintf(stderr, "gave up grinding at height %d\n", ingot_chain_height(c) + 1);
            break;
        }
        IngotErr e = ingot_chain_add(c, b);
        if (e != INGOT_OK) {
            fprintf(stderr, "block rejected: %s\n", ingot_err_str(e));
            break;
        }
        ingot_store_append(store_path, b);
        mined++;
    }
    printf("mined %d block%s, height %d\n", mined, mined == 1 ? "" : "s",
           ingot_chain_height(c));
    free(b);
    chain_unload(c);
    return 0;
}

static int cmd_send(const char *to_str, const char *amount_str, const char *fee_str,
                    uint16_t port_default) {
    uint16_t port = port_default;
    if (getenv("INGOT_PORT"))
        port = (uint16_t)atoi(getenv("INGOT_PORT"));
    unsigned char seed[32], my[INGOT_ADDR_HASH_LEN], to[INGOT_ADDR_HASH_LEN];
    char as[64];
    uint64_t amount, fee = 0;
    if (wallet_load(seed) != 0) {
        fprintf(stderr, "no wallet yet - run: ingot wallet new\n");
        return 1;
    }
    if (ingot_address_parse(to_str, to) != 1) {
        fprintf(stderr, "bad address: %s\n", to_str);
        return 1;
    }
    if (parse_amount(amount_str, &amount) != 0 ||
        (fee_str && parse_amount(fee_str, &fee) != 0)) {
        fprintf(stderr, "bad amount\n");
        return 1;
    }
    wallet_addr(seed, my, as);
    IngotChain *c = chain_load();

    /* gather the wallet's UTXOs, largest first */
    IngotUtxo mine[256];
    int n = 0;
    for (int i = 0; i < INGOT_UTXO_SLOTS && n < 256; i++)
        if (c->utxo[i].used == 1 && memcmp(c->utxo[i].u.addr, my, INGOT_ADDR_HASH_LEN) == 0)
            mine[n++] = c->utxo[i].u;
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (mine[j].amount > mine[i].amount) {
                IngotUtxo tmp = mine[i];
                mine[i] = mine[j];
                mine[j] = tmp;
            }

    IngotTx tx;
    memset(&tx, 0, sizeof tx);
    uint64_t got = 0;
    while (got < amount + fee && tx.n_in < INGOT_MAX_TX_IN && tx.n_in < n) {
        tx.in[tx.n_in].index = mine[tx.n_in].idx;
        memcpy(tx.in[tx.n_in].prev_txid, mine[tx.n_in].txid, 32);
        got += mine[tx.n_in].amount;
        tx.n_in++;
    }
    if (got < amount + fee) {
        char pretty[64];
        print_amount(ingot_chain_balance(c, my), pretty);
        fprintf(stderr, "insufficient funds: have %s, need more than that\n", pretty);
        chain_unload(c);
        return 1;
    }
    tx.out[0].amount = amount;
    memcpy(tx.out[0].addr, to, INGOT_ADDR_HASH_LEN);
    tx.n_out = 1;
    if (got > amount + fee) {
        tx.out[1].amount = got - amount - fee;
        memcpy(tx.out[1].addr, my, INGOT_ADDR_HASH_LEN);
        tx.n_out = 2;
    }
    for (int i = 0; i < tx.n_in; i++)
        ingot_tx_sign(&tx, i, seed);

    unsigned char id[32];
    char idhex[65];
    ingot_txid(&tx, id);
    hex(id, 32, idhex);
    if (ingot_net_push_tx("127.0.0.1", port, &tx) != 0) {
        fprintf(stderr, "could not reach a local node on port %u\n", port);
        fprintf(stderr, "start one with: ingot node\n");
        chain_unload(c);
        return 1;
    }
    printf("sent: %s\n", idhex);
    chain_unload(c);
    return 0;
}

static int cmd_show(const char *arg) {
    IngotChain *c = chain_load();
    long h = strtol(arg, NULL, 10);
    const IngotNode *node = NULL;
    for (int i = 0; i < c->n_nodes; i++)
        if (c->nodes[i]->main && c->nodes[i]->height == (uint32_t)h)
            node = c->nodes[i];
    if (!node) {
        fprintf(stderr, "no main-chain block at height %s\n", arg);
        chain_unload(c);
        return 1;
    }
    char hh[65];
    hex(node->hash, 32, hh);
    char pretty[64];
    print_amount(node->b.tx[0].out[0].amount, pretty);
    printf("height:  %u\n", node->height);
    printf("hash:    %s\n", hh);
    printf("time:    %u\n", node->b.h.time);
    printf("bits:    %08x\n", node->b.h.bits);
    printf("nonce:   %u\n", node->b.h.nonce);
    printf("txs:     %d\n", node->b.n_tx);
    printf("reward:  %s\n", pretty);
    chain_unload(c);
    return 0;
}

static int cmd_node(int argc, char **argv) {
    uint16_t port = INGOT_PORT;
    const char *peers[16];
    int npeers = 0, mine = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--peer") && i + 1 < argc && npeers < 16)
            peers[npeers++] = argv[++i];
        else if (!strcmp(argv[i], "--mine"))
            mine = 1;
    }
    IngotChain *c = chain_load();
    int loaded = ingot_chain_height(c);
    fprintf(stderr, "chain loaded: height %d\n", loaded);

    IngotNet net;
    if (ingot_net_init(&net, c, store_path, port) != 0) {
        fprintf(stderr, "cannot listen on port %u\n", port);
        chain_unload(c);
        return 1;
    }
    for (int i = 0; i < npeers; i++) {
        char host[128];
        uint16_t pport = INGOT_PORT;
        const char *colon = strrchr(peers[i], ':');
        if (colon) {
            size_t hl = (size_t)(colon - peers[i]);
            if (hl >= sizeof host) hl = sizeof host - 1;
            memcpy(host, peers[i], hl);
            host[hl] = 0;
            pport = (uint16_t)atoi(colon + 1);
        } else {
            snprintf(host, sizeof host, "%s", peers[i]);
        }
        fprintf(stderr, "peer %s:%u %s\n", host, pport,
                ingot_net_connect(&net, host, pport) == 0 ? "connected" : "unreachable");
    }
    static unsigned char mine_addr[INGOT_ADDR_HASH_LEN];
    if (mine) {
        unsigned char seed[32];
        char as[64];
        if (wallet_load(seed) != 0) {
            fprintf(stderr, "no wallet yet - run: ingot wallet new\n");
            chain_unload(c);
            return 1;
        }
        wallet_addr(seed, mine_addr, as);
        ingot_net_mine(&net, mine_addr, 50000);
        fprintf(stderr, "mining to %s\n", as);
    }
    fprintf(stderr, "listening on :%u\n", port);
    ingot_net_run(&net);
    chain_unload(c);
    return 0;
}

static void usage(FILE *f) {
    fprintf(f,
        "ingot - a small blockchain from scratch\n"
        "\n"
        "  ingot wallet new            create a wallet (~/.ingot/wallet)\n"
        "  ingot address               print the wallet's address\n"
        "  ingot balance [address]     balance at the local chain\n"
        "  ingot mine <n>              mine n blocks offline\n"
        "  ingot send <to> <amt> [fee] send coins through a local node\n"
        "  ingot show <height>         print a main-chain block\n"
        "  ingot node [--port N] [--peer host[:port]]... [--mine]\n"
        "                              run a syncing node\n");
}

int main(int argc, char **argv) {
    paths_init();
    if (argc < 2) {
        usage(stderr);
        return 1;
    }
    if (!strcmp(argv[1], "wallet") && argc == 3 && !strcmp(argv[2], "new"))
        return cmd_wallet_new();
    if (!strcmp(argv[1], "address"))
        return cmd_address();
    if (!strcmp(argv[1], "balance"))
        return cmd_balance(argc > 2 ? argv[2] : NULL);
    if (!strcmp(argv[1], "mine") && argc == 3)
        return cmd_mine(atoi(argv[2]));
    if (!strcmp(argv[1], "send") && argc >= 4)
        return cmd_send(argv[2], argv[3], argc > 4 ? argv[4] : NULL, INGOT_PORT);
    if (!strcmp(argv[1], "show") && argc == 3)
        return cmd_show(argv[2]);
    if (!strcmp(argv[1], "node"))
        return cmd_node(argc - 2, argv + 2);
    usage(stderr);
    return 1;
}
