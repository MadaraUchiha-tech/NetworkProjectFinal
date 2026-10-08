/* proto.c — BHTTP/1 framing and header-block coding. */
#include "proto.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

const char *const bh_static_table[BH_STATIC_COUNT + 1] = {
    NULL,               /* 0 is the literal marker, never an index */
    ":method",          /* 1 */
    ":path",            /* 2 */
    ":status",          /* 3 */
    "host",             /* 4 */
    "user-agent",       /* 5 */
    "accept",           /* 6 */
    "content-type",     /* 7 */
    "content-length",   /* 8 */
    "server",           /* 9 */
    "date",             /* 10 */
};

/* ---------------------------------------------------------------- I/O */

/* 1 = filled, 0 = EOF before the first octet, -1 = error or short read. */
static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0)
            return got == 0 ? 0 : -1;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 1;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

int bh_read_frame(int fd, bh_frame *f)
{
    uint8_t h[BH_HDR_LEN];
    int r = read_full(fd, h, sizeof h);
    if (r <= 0)
        return r;
    f->len   = (uint16_t)(h[0] << 8 | h[1]);
    f->type  = h[2];
    f->flags = h[3];
    f->id    = (uint32_t)h[4] << 24 | (uint32_t)h[5] << 16 |
               (uint32_t)h[6] << 8  | (uint32_t)h[7];
    /* The payload is always read in full, whatever the type: that is what
     * lets a receiver skip a type it does not know and stay in sync. */
    if (f->len > 0 && read_full(fd, f->payload, f->len) != 1)
        return -1;
    return 1;
}

int bh_write_frame(int fd, uint8_t type, uint8_t flags, uint32_t id,
                   const void *payload, size_t len)
{
    if (len > BH_MAX_PAYLOAD)
        return -1;
    uint8_t h[BH_HDR_LEN] = {
        (uint8_t)(len >> 8), (uint8_t)len, type, flags,
        (uint8_t)(id >> 24), (uint8_t)(id >> 16), (uint8_t)(id >> 8), (uint8_t)id,
    };
    if (write_full(fd, h, sizeof h) < 0)
        return -1;
    return len ? write_full(fd, payload, len) : 0;
}

/* ------------------------------------------------------- header blocks */

static int static_index(const char *name)
{
    for (int i = 1; i <= BH_STATIC_COUNT; i++)
        if (strcmp(bh_static_table[i], name) == 0)
            return i;
    return 0;
}

void bh_block_init(bh_block *b)
{
    b->len = 0;
    b->overflow = 0;
}

static void put(bh_block *b, const void *p, size_t n)
{
    if (b->overflow || n > sizeof b->buf - b->len) {
        b->overflow = 1;
        return;
    }
    memcpy(b->buf + b->len, p, n);
    b->len += n;
}

void bh_block_add(bh_block *b, const char *name, const void *value, size_t vlen)
{
    size_t nlen = strlen(name);
    int idx = static_index(name);
    if (nlen == 0 || nlen > 255 || vlen > 0xFFFF) {
        b->overflow = 1;
        return;
    }
    if (idx) {
        uint8_t i = (uint8_t)idx;
        put(b, &i, 1);
    } else {
        uint8_t hdr[2] = { BH_LITERAL, (uint8_t)nlen };
        put(b, hdr, 2);
        put(b, name, nlen);
    }
    uint8_t vl[2] = { (uint8_t)(vlen >> 8), (uint8_t)vlen };
    put(b, vl, 2);
    put(b, value, vlen);
}

void bh_block_adds(bh_block *b, const char *name, const char *value)
{
    bh_block_add(b, name, value, strlen(value));
}

int bh_block_parse(const uint8_t *p, size_t len, bh_field *out, int max)
{
    size_t i = 0;
    int n = 0;
    while (i < len) {
        if (n == max)
            return -1;
        bh_field *f = &out[n];
        uint8_t prefix = p[i++];
        if (prefix == BH_LITERAL) {
            if (i >= len)
                return -1;
            size_t nlen = p[i++];
            if (nlen == 0 || nlen > len - i)
                return -1;
            for (size_t k = 0; k < nlen; k++) {
                uint8_t c = p[i + k];
                if (c <= 0x20 || c >= 0x7F || (c >= 'A' && c <= 'Z'))
                    return -1;
            }
            f->name = (const char *)p + i;
            f->nlen = nlen;
            f->index = 0;
            i += nlen;
        } else if (prefix <= BH_STATIC_COUNT) {
            f->name = bh_static_table[prefix];
            f->nlen = strlen(f->name);
            f->index = prefix;
        } else {
            return -1;              /* 0x0B..0xFF: unassigned in v1 */
        }
        if (len - i < 2)
            return -1;
        size_t vlen = (size_t)p[i] << 8 | p[i + 1];
        i += 2;
        if (vlen > len - i)
            return -1;
        f->value = p + i;
        f->vlen = vlen;
        i += vlen;
        n++;
    }
    return n;
}

int bh_field_eq(const bh_field *f, const char *s)
{
    size_t n = strlen(s);
    return f->vlen == n && memcmp(f->value, s, n) == 0;
}

const bh_field *bh_find(const bh_field *fs, int n, const char *name)
{
    size_t nlen = strlen(name);
    for (int i = 0; i < n; i++)
        if (fs[i].nlen == nlen && memcmp(fs[i].name, name, nlen) == 0)
            return &fs[i];
    return NULL;
}

/* ------------------------------------------------------------ -v dump */

const char *bh_type_name(uint8_t type)
{
    switch (type) {
    case BH_T_DATA:    return "DATA";
    case BH_T_HEADERS: return "HEADERS";
    default:           return "UNKNOWN";
    }
}

static void dump_escaped(FILE *out, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (isprint(p[i]) && p[i] != '\\')
            fputc(p[i], out);
        else
            fprintf(out, "\\x%02x", p[i]);
    }
}

void bh_dump_frame(FILE *out, char dir, uint8_t type, uint8_t flags,
                   uint32_t id, const uint8_t *payload, size_t len)
{
    fprintf(out, "%c %s(0x%02x) len=%zu flags=0x%02x%s id=%u%s\n",
            dir, bh_type_name(type), type, len, flags,
            (type <= BH_T_HEADERS && (flags & BH_F_END)) ? "(END)" : "",
            id, type > BH_T_HEADERS ? "  -> skipped" : "");

    if (type == BH_T_HEADERS) {
        bh_field fs[BH_MAX_FIELDS];
        int n = bh_block_parse(payload, len, fs, BH_MAX_FIELDS);
        if (n < 0)
            fprintf(out, "%c   (malformed header block)\n", dir);
        for (int i = 0; i < n; i++) {
            if (fs[i].index)
                fprintf(out, "%c   [%2d] ", dir, fs[i].index);
            else
                fprintf(out, "%c   [lit] ", dir);
            fprintf(out, "%.*s: ", (int)fs[i].nlen, fs[i].name);
            dump_escaped(out, fs[i].value, fs[i].vlen);
            fputc('\n', out);
        }
    }

    uint8_t h[BH_HDR_LEN] = {
        (uint8_t)(len >> 8), (uint8_t)len, type, flags,
        (uint8_t)(id >> 24), (uint8_t)(id >> 16), (uint8_t)(id >> 8), (uint8_t)id,
    };
    size_t total = BH_HDR_LEN + len;
    for (size_t off = 0; off < total; off += 16) {
        fprintf(out, "%c   %04zx  ", dir, off);
        for (size_t k = 0; k < 16; k++) {
            if (off + k < total) {
                size_t j = off + k;
                fprintf(out, "%02x ", j < BH_HDR_LEN ? h[j] : payload[j - BH_HDR_LEN]);
            } else {
                fputs("   ", out);
            }
            if (k == 7)
                fputc(' ', out);
        }
        fputs(" |", out);
        for (size_t k = 0; k < 16 && off + k < total; k++) {
            size_t j = off + k;
            uint8_t c = j < BH_HDR_LEN ? h[j] : payload[j - BH_HDR_LEN];
            fputc(isprint(c) ? c : '.', out);
        }
        fputs("|\n", out);
    }
}
