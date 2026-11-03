#include "store.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STORE_MAGIC 0x54474e49u   /* "INGT" little-endian */

int ingot_store_load(IngotChain *c, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;   /* first run */
    static unsigned char buf[INGOT_MAX_BLOCK_SIZE];
    int n = 0;
    for (;;) {
        unsigned char hdr[8];
        if (fread(hdr, 1, 8, f) != 8)
            break;   /* clean EOF or a torn tail: stop at the last good record */
        uint32_t magic, len;
        memcpy(&magic, hdr, 4);
        memcpy(&len, hdr + 4, 4);
        if (magic != STORE_MAGIC || len == 0 || len > sizeof buf)
            break;
        if (fread(buf, 1, len, f) != len)
            break;
        IngotBlock *b = malloc(sizeof *b);
        if (!b)
            break;
        if (ingot_block_parse(buf, len, b) != len) {
            free(b);
            break;
        }
        IngotErr e = ingot_chain_add(c, b);
        if (e == INGOT_OK || e == INGOT_ERR_DUP) {
            /* it is already in the file: do not offer it back for
             * persistence on the next network block */
            unsigned char h[32];
            ingot_block_hash(b, h);
            const IngotNode *node = ingot_chain_find(c, h);
            if (node)
                ((IngotNode *)node)->stored = 1;
        }
        free(b);
        /* records land out of order when the node synced while a peer
         * pushed broadcasts: orphans connect when their parents arrive
         * later in the file, so keep replaying past them */
        if (e != INGOT_OK && e != INGOT_ERR_DUP && e != INGOT_ERR_ORPHAN)
            break;
        if (e != INGOT_ERR_ORPHAN)
            n++;
    }
    fclose(f);
    return n;
}

int ingot_store_append(const char *path, const IngotBlock *b) {
    static unsigned char buf[INGOT_MAX_BLOCK_SIZE];
    size_t len = ingot_block_serialize(b, buf, sizeof buf);
    if (!len)
        return -1;
    FILE *f = fopen(path, "ab");
    if (!f)
        return -1;
    unsigned char hdr[8];
    uint32_t magic = STORE_MAGIC, l32 = (uint32_t)len;
    memcpy(hdr, &magic, 4);
    memcpy(hdr + 4, &l32, 4);
    int ok = fwrite(hdr, 1, 8, f) == 8 && fwrite(buf, 1, len, f) == len;
    fclose(f);
    return ok ? 0 : -1;
}
