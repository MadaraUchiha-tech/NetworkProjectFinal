/* bserve — BHTTP/1 static file server.
 *
 *   usage: bserve [-v] [-g] ROOT PORT
 *
 *   -v  hexdump every frame sent and received (stderr)
 *   -g  "grease": send an unassigned frame type before every response, to
 *       prove that clients skip frame types they do not know
 *
 * One process per connection; the connection stays open across requests
 * until the client closes it or is idle for IDLE_TIMEOUT seconds.
 */
#include "proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define IDLE_TIMEOUT 60
#define CHUNK        16384
#define GREASE_TYPE  0xBB

static int verbose, grease;
static char root[PATH_MAX];

typedef struct {
    int      status;             /* 0 = valid so far; else the error status */
    int      head;               /* HEAD rather than GET */
    char     path[PATH_MAX];     /* decoded, query stripped */
    char     raw[1024];          /* for the log line */
} request;

static int send_frame(int fd, uint8_t type, uint8_t flags, uint32_t id,
                      const void *p, size_t n)
{
    if (verbose)
        bh_dump_frame(stderr, '>', type, flags, id, p, n);
    return bh_write_frame(fd, type, flags, id, p, n);
}

/* ------------------------------------------------------ request parsing */

static int unhex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Strips ?query and #fragment and percent-decodes. 0 on success. */
static int decode_path(const uint8_t *in, size_t n, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; i < n && in[i] != '?' && in[i] != '#'; i++) {
        int c = in[i];
        if (c == '%') {
            int hi, lo;
            if (i + 2 >= n || (hi = unhex(in[i + 1])) < 0 || (lo = unhex(in[i + 2])) < 0)
                return -1;
            c = hi << 4 | lo;
            i += 2;
        }
        if (c == 0 || o + 1 >= cap)
            return -1;
        out[o++] = (char)c;
    }
    out[o] = '\0';
    return 0;
}

static void parse_request(const bh_frame *f, request *rq)
{
    bh_field fs[BH_MAX_FIELDS];
    memset(rq, 0, sizeof *rq);
    strcpy(rq->raw, "?");

    int n = bh_block_parse(f->payload, f->len, fs, BH_MAX_FIELDS);
    if (n < 0 || f->id == 0) {
        rq->status = 400;
        return;
    }
    const bh_field *method = NULL, *path = NULL;
    for (int i = 0; i < n; i++) {
        const bh_field **slot = fs[i].nlen == 7 && !memcmp(fs[i].name, ":method", 7) ? &method
                              : fs[i].nlen == 5 && !memcmp(fs[i].name, ":path", 5)   ? &path
                              : NULL;
        if (slot && *slot) {             /* a pseudo-header appears twice */
            rq->status = 400;
            return;
        }
        if (slot)
            *slot = &fs[i];
    }
    if (!method || !path || path->vlen == 0 || path->value[0] != '/') {
        rq->status = 400;
        return;
    }
    snprintf(rq->raw, sizeof rq->raw, "%.*s %.*s",
             (int)(method->vlen > 16 ? 16 : method->vlen), method->value,
             (int)(path->vlen > 900 ? 900 : path->vlen), path->value);
    if (decode_path(path->value, path->vlen, rq->path, sizeof rq->path) < 0) {
        rq->status = 400;
        return;
    }
    if (bh_field_eq(method, "HEAD"))
        rq->head = 1;
    else if (!bh_field_eq(method, "GET"))
        rq->status = 405;
}

/* ------------------------------------------------------------ responses */

static const char *content_type(const char *path)
{
    static const char *const map[][2] = {
        { ".html", "text/html; charset=utf-8" }, { ".htm", "text/html; charset=utf-8" },
        { ".txt",  "text/plain; charset=utf-8" }, { ".css", "text/css" },
        { ".js",   "text/javascript" },           { ".json", "application/json" },
        { ".png",  "image/png" },                 { ".jpg", "image/jpeg" },
        { ".jpeg", "image/jpeg" },                { ".gif", "image/gif" },
        { ".svg",  "image/svg+xml" },             { ".ico", "image/x-icon" },
        { ".pdf",  "application/pdf" },
    };
    const char *dot = strrchr(path, '.');
    if (dot && !strchr(dot, '/'))
        for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
            if (strcasecmp(dot, map[i][0]) == 0)
                return map[i][1];
    return "application/octet-stream";
}

static const char *reason(int status)
{
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    default:  return "Internal Server Error";
    }
}

static int send_head(int fd, uint32_t id, int status, const char *ctype,
                     long long length, int end)
{
    char st[4], cl[32], date[64];
    time_t now = time(NULL);
    strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));
    snprintf(st, sizeof st, "%d", status);
    snprintf(cl, sizeof cl, "%lld", length);

    bh_block b;
    bh_block_init(&b);
    bh_block_adds(&b, ":status", st);
    bh_block_adds(&b, "server", "bserve/1");
    bh_block_adds(&b, "date", date);
    bh_block_adds(&b, "content-type", ctype);
    bh_block_adds(&b, "content-length", cl);

    if (grease) {
        static const char g[] = "unassigned frame type: receivers MUST skip this";
        if (send_frame(fd, GREASE_TYPE, 0xFF, id, g, sizeof g - 1) < 0)
            return -1;
    }
    return send_frame(fd, BH_T_HEADERS, end ? BH_F_END : 0, id, b.buf, b.len);
}

static int send_error(int fd, uint32_t id, int status, int head)
{
    char body[64];
    int n = snprintf(body, sizeof body, "%d %s\n", status, reason(status));
    if (send_head(fd, id, status, "text/plain; charset=utf-8", n, head) < 0)
        return -1;
    return head ? 0 : send_frame(fd, BH_T_DATA, BH_F_END, id, body, (size_t)n);
}

/* Resolves rq->path under root. Returns an open fd, or -1 (=> 404). */
static int open_under_root(const char *path, struct stat *st, char *resolved)
{
    char full[PATH_MAX * 2];
    int n = snprintf(full, sizeof full, "%s%s%s", root, path,
                     path[strlen(path) - 1] == '/' ? "index.html" : "");
    if (n < 0 || (size_t)n >= sizeof full)
        return -1;                      /* truncated: would name a different file */
    if (!realpath(full, resolved))
        return -1;
    size_t rl = strlen(root);
    /* Must be root itself or below it — no "..", no symlink escapes. */
    if (strncmp(resolved, root, rl) != 0 || (resolved[rl] != '/' && resolved[rl] != '\0'))
        return -1;
    if (stat(resolved, st) < 0)
        return -1;
    if (S_ISDIR(st->st_mode)) {
        strncat(resolved, "/index.html", PATH_MAX - strlen(resolved) - 1);
        if (stat(resolved, st) < 0)
            return -1;
    }
    if (!S_ISREG(st->st_mode))
        return -1;
    return open(resolved, O_RDONLY);
}

/* Returns -1 only if the connection is no longer usable. */
static int serve(int fd, uint32_t id, const request *rq)
{
    if (rq->status) {
        fprintf(stderr, "bserve[%d]: #%u %s -> %d\n", getpid(), id, rq->raw, rq->status);
        return send_error(fd, id, rq->status, rq->head);
    }
    struct stat st;
    char resolved[PATH_MAX + 16];
    int file = open_under_root(rq->path, &st, resolved);
    if (file < 0) {
        fprintf(stderr, "bserve[%d]: #%u %s -> 404\n", getpid(), id, rq->raw);
        return send_error(fd, id, 404, rq->head);
    }
    fprintf(stderr, "bserve[%d]: #%u %s -> 200 (%lld bytes)\n",
            getpid(), id, rq->raw, (long long)st.st_size);

    int empty = rq->head || st.st_size == 0;
    if (send_head(fd, id, 200, content_type(resolved), st.st_size, empty) < 0)
        goto fail;
    if (!empty) {
        static uint8_t buf[CHUNK];
        long long left = st.st_size;
        for (;;) {
            ssize_t r = read(file, buf, left < CHUNK ? (size_t)left : CHUNK);
            if (r < 0 && errno == EINTR)
                continue;
            if (r < 0)
                goto fail;            /* status already sent; just drop */
            left -= r;
            int last = r == 0 || left <= 0;   /* r == 0: file shrank */
            if (send_frame(fd, BH_T_DATA, last ? BH_F_END : 0, id, buf, (size_t)r) < 0)
                goto fail;
            if (last)
                break;
        }
    }
    close(file);
    return 0;
fail:
    close(file);
    return -1;
}

/* ----------------------------------------------------------- connection */

static void handle(int fd)
{
    static bh_frame f;
    static request pending;
    uint32_t pending_id = 0;
    int have_pending = 0;

    struct timeval tv = { IDLE_TIMEOUT, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    for (;;) {
        int r = bh_read_frame(fd, &f);
        if (r <= 0)
            break;                      /* client closed, timed out, or cut a frame */
        if (verbose)
            bh_dump_frame(stderr, '<', f.type, f.flags, f.id, f.payload, f.len);

        if (f.type == BH_T_HEADERS) {
            if (have_pending) {         /* new request before the last one ended */
                request bad = { .status = 400 };
                strcpy(bad.raw, "(HEADERS while a request body is open)");
                if (serve(fd, f.id, &bad) < 0)
                    break;
                continue;
            }
            parse_request(&f, &pending);
            if (f.flags & BH_F_END) {
                if (serve(fd, f.id, &pending) < 0)
                    break;
            } else {                    /* a body follows; read and discard it */
                have_pending = 1;
                pending_id = f.id;
            }
        } else if (f.type == BH_T_DATA) {
            if (have_pending && f.id == pending_id) {
                if (f.flags & BH_F_END) {
                    have_pending = 0;
                    if (serve(fd, f.id, &pending) < 0)
                        break;
                }
            } else {
                request bad = { .status = 400 };
                strcpy(bad.raw, "(DATA with no open request)");
                if (serve(fd, f.id, &bad) < 0)
                    break;
            }
        }
        /* Any other type: payload already consumed by bh_read_frame; skip it. */
    }
    close(fd);
}

static int listen_on(const char *port)
{
    char *end;
    long p = strtol(port, &end, 10);
    if (*end || p < 1 || p > 65535) {
        fprintf(stderr, "bserve: bad port '%s'\n", port);
        exit(2);
    }
    int one = 1, zero = 0;
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s >= 0) {                       /* dual-stack: serves ::1 and 127.0.0.1 */
        struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons((uint16_t)p),
                                   .sin6_addr = in6addr_any };
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        if (bind(s, (struct sockaddr *)&a6, sizeof a6) == 0)
            goto bound;
        close(s);
    }
    s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a4 = { .sin_family = AF_INET, .sin_port = htons((uint16_t)p),
                              .sin_addr.s_addr = htonl(INADDR_ANY) };
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (s < 0 || bind(s, (struct sockaddr *)&a4, sizeof a4) < 0) {
        perror("bserve: bind");
        exit(1);
    }
bound:
    if (listen(s, 64) < 0) {
        perror("bserve: listen");
        exit(1);
    }
    return s;
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "vg")) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'g': grease = 1; break;
        default:  goto usage;
        }
    }
    if (argc - optind != 2)
        goto usage;
    if (!realpath(argv[optind], root)) {
        fprintf(stderr, "bserve: root '%s': %s\n", argv[optind], strerror(errno));
        return 2;
    }
    if (strcmp(root, "/") == 0)
        root[0] = '\0';                 /* so root + "/x" is "/x", not "//x" */

    int s = listen_on(argv[optind + 1]);
    signal(SIGCHLD, SIG_IGN);           /* auto-reap connection workers */
    signal(SIGPIPE, SIG_IGN);           /* a vanished client is EPIPE, not death */
    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "bserve: serving %s on port %s\n", root[0] ? root : "/", argv[optind + 1]);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) {
            if (errno != EINTR)
                perror("bserve: accept");
            continue;
        }
        pid_t pid = fork();
        if (pid == 0) {
            close(s);
            handle(c);
            _exit(0);
        }
        if (pid < 0)
            perror("bserve: fork");
        close(c);
    }

usage:
    fprintf(stderr, "usage: bserve [-v] [-g] ROOT PORT\n");
    return 2;
}
