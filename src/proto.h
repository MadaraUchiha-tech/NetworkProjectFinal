/* proto.h — BHTTP/1 framing and header-block coding, shared by bserve and bcurl.
 *
 * Frame header (8 octets, network byte order):
 *
 *   0               1               2               3
 *   +---------------+---------------+---------------+---------------+
 *   |          Length (16)          |   Type (8)    |   Flags (8)   |
 *   +---------------+---------------+---------------+---------------+
 *   |                        Request ID (32)                        |
 *   +---------------+---------------+---------------+---------------+
 *
 * See docs/SPEC.pdf for the full specification.
 */
#ifndef BHTTP_PROTO_H
#define BHTTP_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define BH_HDR_LEN       8
#define BH_MAX_PAYLOAD   65535u
#define BH_DEFAULT_PORT  "9000"

/* Frame types. Everything else is unassigned and MUST be skipped. */
#define BH_T_DATA        0x00
#define BH_T_HEADERS     0x01

/* Flags. Unknown flag bits MUST be ignored. */
#define BH_F_END         0x01   /* last frame of this message */

/* Header-block field prefix octet. */
#define BH_LITERAL       0x00   /* literal name follows */
#define BH_STATIC_COUNT  10     /* indexes 1..10 name the static table */

typedef struct {
    uint16_t len;
    uint8_t  type;
    uint8_t  flags;
    uint32_t id;
    uint8_t  payload[BH_MAX_PAYLOAD];
} bh_frame;

/* A decoded header field. Pointers alias the frame payload; nothing is
 * NUL-terminated. `index` is the static-table index, or 0 for a literal. */
typedef struct {
    const char    *name;
    size_t         nlen;
    const uint8_t *value;
    size_t         vlen;
    int            index;
} bh_field;

#define BH_MAX_FIELDS 64

typedef struct {
    uint8_t buf[BH_MAX_PAYLOAD];
    size_t  len;
    int     overflow;
} bh_block;

extern const char *const bh_static_table[BH_STATIC_COUNT + 1];

/* I/O. bh_read_frame returns 1 on a frame, 0 on clean EOF before any octet
 * of a header, -1 on error or EOF inside a frame. */
int bh_read_frame(int fd, bh_frame *f);
int bh_write_frame(int fd, uint8_t type, uint8_t flags, uint32_t id,
                   const void *payload, size_t len);

/* Header-block encoding: uses a static index when the name is in the table,
 * a literal otherwise. Sets b->overflow instead of writing past the end. */
void bh_block_init(bh_block *b);
void bh_block_add(bh_block *b, const char *name, const void *value, size_t vlen);
void bh_block_adds(bh_block *b, const char *name, const char *value);

/* Header-block decoding. Returns the number of fields, or -1 if the block is
 * malformed (truncated, unassigned index, empty or upper-case literal name,
 * or more than `max` fields). */
int bh_block_parse(const uint8_t *p, size_t len, bh_field *out, int max);

/* Finds a field by name; returns NULL if absent. */
const bh_field *bh_find(const bh_field *fs, int n, const char *name);
int bh_field_eq(const bh_field *f, const char *s);

/* -v output: frame summary, decoded fields, and a hexdump of every octet. */
const char *bh_type_name(uint8_t type);
void bh_dump_frame(FILE *out, char dir, uint8_t type, uint8_t flags,
                   uint32_t id, const uint8_t *payload, size_t len);

#endif
