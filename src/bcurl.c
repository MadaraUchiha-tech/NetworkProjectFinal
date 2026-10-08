/* bcurl — BHTTP/1 client.
 *
 *   usage: bcurl [-v] [-I] [-g] URL [URL | /path ...]
 *
 *   URL is [bhttp://]host[:port][/path]; the default port is 9000.
 *   Further arguments may be bare paths ("/a.css") or URLs naming the same
 *   host and port: every request goes down ONE connection, in order.
 *
 *   -v  hexdump every frame sent and received (stderr)
 *   -I  HEAD instead of GET; print the response headers to stdout
 *   -g  "grease": send an unassigned frame type before every request, to
 *       prove that the server skips frame types it does not know
 *
 * Exit status: 0 all responses 1xx-3xx, 4 any 4xx, 5 any 5xx,
 *              1 network/protocol error, 2 usage error.
 */
#include "proto.h"

#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GREASE_TYPE 0xBA

static int verbose, head, grease;

typedef struct {
    char host[256];
    char port[8];
    const char *path;
} url;

static void die(int code, const char *msg)
{
    fprintf(stderr, "bcurl: %s\n", msg);
    exit(code);
}

/* Parses [bhttp://]host[:port][/path]. IPv6 literals go in brackets. */
static int parse_url(const char *s, url *u)
{
    if (strncmp(s, "bhttp://", 8) == 0)
        s += 8;
    else if (strstr(s, "://"))
        return -1;
    const char *slash = strchr(s, '/');
    const char *hend = slash ? slash : s + strlen(s);
    const char *colon = NULL;
    const char *hstart = s;

    if (*s == '[') {
        const char *rb = memchr(s, ']', (size_t)(hend - s));
        if (!rb)
            return -1;
        hstart = s + 1;
        if (rb + 1 < hend && rb[1] == ':')
            colon = rb + 1;
        else if (rb + 1 != hend)
            return -1;
        hend = rb;
    } else {
        colon = memchr(s, ':', (size_t)(hend - s));
    }
    const char *hlast = colon && *s != '[' ? colon : hend;
    size_t hl = (size_t)(hlast - hstart);
    if (hl == 0 || hl >= sizeof u->host)
        return -1;
    memcpy(u->host, hstart, hl);
    u->host[hl] = '\0';

    const char *pend = slash ? slash : s + strlen(s);
    if (colon) {
        size_t pl = (size_t)(pend - colon - 1);
        if (pl == 0 || pl >= sizeof u->port)
            return -1;
        memcpy(u->port, colon + 1, pl);
        u->port[pl] = '\0';
        for (size_t i = 0; i < pl; i++)
            if (u->port[i] < '0' || u->port[i] > '9')
                return -1;
    } else {
        strcpy(u->port, BH_DEFAULT_PORT);
    }
    u->path = slash ? slash : "/";
    return 0;
}

static int dial(const url *u)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res;
    int e = getaddrinfo(u->host, u->port, &hints, &res);
    if (e) {
        fprintf(stderr, "bcurl: %s: %s\n", u->host, gai_strerror(e));
        exit(1);
    }
    /* Try each address until one connects; only that one is ever used. */
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "bcurl: cannot connect to %s port %s\n", u->host, u->port);
        exit(1);
    }
    return fd;
}

static void send_frame(int fd, uint8_t type, uint8_t flags, uint32_t id,
                       const void *p, size_t n)
{
    if (verbose)
        bh_dump_frame(stderr, '>', type, flags, id, p, n);
    if (bh_write_frame(fd, type, flags, id, p, n) < 0)
        die(1, "connection lost while sending");
}

/* Sends one request and reads its whole response. Returns the status. */
static int fetch(int fd, uint32_t id, const url *u, const char *authority)
{
    static bh_frame f;
    bh_block b;
    bh_block_init(&b);
    bh_block_adds(&b, ":method", head ? "HEAD" : "GET");
    bh_block_adds(&b, ":path", u->path);
    bh_block_adds(&b, "host", authority);
    bh_block_adds(&b, "user-agent", "bcurl/1");
    bh_block_adds(&b, "accept", "*/*");
    if (b.overflow)
        die(2, "request too large for one HEADERS frame");

    if (grease)
        send_frame(fd, GREASE_TYPE, 0xFF, id, "v2?", 3);
    send_frame(fd, BH_T_HEADERS, BH_F_END, id, b.buf, b.len);

    int status = 0;
    for (;;) {
        int r = bh_read_frame(fd, &f);
        if (r <= 0)
            die(1, "connection closed before the response ended");
        if (verbose)
            bh_dump_frame(stderr, '<', f.type, f.flags, f.id, f.payload, f.len);

        if (f.type != BH_T_HEADERS && f.type != BH_T_DATA)
            continue;                    /* unknown type: skip it cleanly */
        if (f.id != id)
            die(1, "protocol error: response for a request we did not send");

        if (f.type == BH_T_HEADERS) {
            if (status)
                die(1, "protocol error: second HEADERS in one response");
            bh_field fs[BH_MAX_FIELDS];
            int n = bh_block_parse(f.payload, f.len, fs, BH_MAX_FIELDS);
            if (n < 0)
                die(1, "protocol error: malformed header block");
            const bh_field *st = bh_find(fs, n, ":status");
            if (!st || st->vlen != 3 || st->value[0] < '1' || st->value[0] > '5')
                die(1, "protocol error: missing or bad :status");
            status = (st->value[0] - '0') * 100 + (st->value[1] - '0') * 10 + (st->value[2] - '0');
            if (head)
                for (int i = 0; i < n; i++)
                    printf("%.*s: %.*s\n", (int)fs[i].nlen, fs[i].name,
                           (int)fs[i].vlen, (const char *)fs[i].value);
        } else {
            if (!status)
                die(1, "protocol error: DATA before HEADERS");
            fwrite(f.payload, 1, f.len, stdout);
        }
        if (f.flags & BH_F_END)
            break;
    }
    fflush(stdout);
    return status;
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "vIg")) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'I': head = 1; break;
        case 'g': grease = 1; break;
        default:  goto usage;
        }
    }
    int nurls = argc - optind;
    if (nurls < 1)
        goto usage;

    url *urls = calloc((size_t)nurls, sizeof *urls);
    if (!urls || parse_url(argv[optind], &urls[0]) < 0)
        die(2, "bad URL (want [bhttp://]host[:port][/path])");
    /* Validate everything before dialing: never a second connection. */
    for (int i = 1; i < nurls; i++) {
        const char *a = argv[optind + i];
        if (a[0] == '/') {
            urls[i] = urls[0];
            urls[i].path = a;
        } else if (parse_url(a, &urls[i]) < 0) {
            die(2, "bad URL (want [bhttp://]host[:port][/path])");
        } else if (strcmp(urls[i].host, urls[0].host) || strcmp(urls[i].port, urls[0].port)) {
            die(2, "all URLs must share one host:port (bcurl never opens a second connection)");
        }
    }

    char authority[300];
    snprintf(authority, sizeof authority, strchr(urls[0].host, ':') ? "[%s]:%s" : "%s:%s",
             urls[0].host, urls[0].port);

    int fd = dial(&urls[0]);
    int worst = 0;
    for (int i = 0; i < nurls; i++) {
        int st = fetch(fd, (uint32_t)i + 1, &urls[i], authority);
        if (verbose)
            fprintf(stderr, "* request %d: %s -> %d\n", i + 1, urls[i].path, st);
        if (st / 100 > worst)
            worst = st / 100;
    }
    close(fd);
    free(urls);
    return worst >= 4 ? worst : 0;

usage:
    fprintf(stderr, "usage: bcurl [-v] [-I] [-g] URL [URL | /path ...]\n");
    return 2;
}
