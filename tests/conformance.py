#!/usr/bin/env python3
"""BHTTP/1 conformance tests.

An independent implementation of the wire format, written from the spec and
sharing no code with bserve/bcurl. It drives:

  * bserve with raw, hand-built frames (valid, malformed, and unknown), and
  * bcurl against a tiny Python server that exercises everything the spec
    lets a server do (unknown frame types, unknown flags, literal names,
    zero-length DATA, many small frames).

Run from the project root:  python3 tests/conformance.py
"""
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BSERVE = os.path.join(ROOT, "bserve")
BCURL = os.path.join(ROOT, "bcurl")

STATIC = [None, ":method", ":path", ":status", "host", "user-agent",
          "accept", "content-type", "content-length", "server", "date"]
DATA, HEADERS, END = 0x00, 0x01, 0x01


# ------------------------------------------------------------- wire format

def frame(ftype, flags, rid, payload=b""):
    return struct.pack(">HBBI", len(payload), ftype, flags, rid) + payload


def field(name, value, literal=False):
    value = value.encode() if isinstance(value, str) else value
    if name in STATIC and not literal:
        head = bytes([STATIC.index(name)])
    else:
        n = name.encode()
        head = bytes([0, len(n)]) + n
    return head + struct.pack(">H", len(value)) + value


def block(*pairs):
    return b"".join(field(n, v) for n, v in pairs)


def get(path, method="GET"):
    return block((":method", method), (":path", path), ("host", "test"))


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def read_frame(sock):
    length, ftype, flags, rid = struct.unpack(">HBBI", recv_exact(sock, 8))
    return ftype, flags, rid, recv_exact(sock, length)


def parse_block(p):
    out, i = [], 0
    while i < len(p):
        pre = p[i]; i += 1
        if pre == 0:
            nl = p[i]; i += 1
            name = p[i:i + nl].decode(); i += nl
        else:
            assert 1 <= pre <= 10, f"unassigned index {pre}"
            name = STATIC[pre]
        vl = struct.unpack(">H", p[i:i + 2])[0]; i += 2
        out.append((name, p[i:i + vl])); i += vl
    return dict(out)


def read_response(sock, rid):
    """Reads one response, skipping unknown types. Returns (headers, body, frames)."""
    headers, body, frames = None, b"", []
    while True:
        ftype, flags, fid, payload = read_frame(sock)
        frames.append((ftype, flags, len(payload)))
        if ftype not in (DATA, HEADERS):
            continue
        assert fid == rid, f"response id {fid} != request id {rid}"
        if ftype == HEADERS:
            assert headers is None, "two HEADERS in one response"
            headers = parse_block(payload)
        else:
            assert headers is not None, "DATA before HEADERS"
            body += payload
        if flags & END:
            return headers, body, frames


# ------------------------------------------------------------- harness

results = []


def check(name):
    def wrap(fn):
        try:
            fn()
            results.append((name, None))
            print(f"  ok    {name}")
        except Exception as e:  # noqa: BLE001
            results.append((name, e))
            print(f"  FAIL  {name}: {e!r}")
        return fn
    return wrap


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_listening(port):
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not start")


# ============================================================ bserve tests

def server_tests():
    site = tempfile.mkdtemp(prefix="bhttp-site-")
    outside = tempfile.mkdtemp(prefix="bhttp-outside-")
    with open(os.path.join(site, "index.html"), "wb") as f:
        f.write(b"<h1>hi</h1>\n")
    with open(os.path.join(site, "empty.txt"), "wb"):
        pass
    big = random.Random(7).randbytes(200_000)
    with open(os.path.join(site, "big.bin"), "wb") as f:
        f.write(big)
    with open(os.path.join(outside, "secret.txt"), "wb") as f:
        f.write(b"secret\n")
    os.symlink(os.path.join(outside, "secret.txt"), os.path.join(site, "link.txt"))
    os.mkdir(os.path.join(site, "sub"))
    with open(os.path.join(site, "sub", "index.html"), "wb") as f:
        f.write(b"sub\n")

    port = free_port()
    proc = subprocess.Popen([BSERVE, site, str(port)], stderr=subprocess.DEVNULL)
    try:
        wait_listening(port)

        def conn():
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            return s

        def roundtrip(s, rid, payload, flags=END):
            s.sendall(frame(HEADERS, flags, rid, payload))
            return read_response(s, rid)

        print("bserve:")

        @check("GET returns 200, body, content-length, content-type")
        def _():
            with conn() as s:
                h, body, _ = roundtrip(s, 1, get("/index.html"))
                assert h[":status"] == b"200"
                assert body == b"<h1>hi</h1>\n"
                assert h["content-length"] == b"12"
                assert h["content-type"].startswith(b"text/html")

        @check("connection stays open: 5 requests, 1 connection")
        def _():
            with conn() as s:
                for rid in range(1, 6):
                    h, _, _ = roundtrip(s, rid, get("/index.html" if rid % 2 else "/missing"))
                    assert h[":status"] == (b"200" if rid % 2 else b"404")

        @check("pipelined requests answered in order")
        def _():
            with conn() as s:
                s.sendall(frame(HEADERS, END, 7, get("/missing")) +
                          frame(HEADERS, END, 8, get("/index.html")))
                assert read_response(s, 7)[0][":status"] == b"404"
                assert read_response(s, 8)[0][":status"] == b"200"

        @check("frame split into 1-octet TCP writes")
        def _():
            with conn() as s:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                for b in frame(HEADERS, END, 1, get("/index.html")):
                    s.send(bytes([b]))
                assert read_response(s, 1)[0][":status"] == b"200"

        @check("404 for a missing file")
        def _():
            with conn() as s:
                assert roundtrip(s, 1, get("/nope.html"))[0][":status"] == b"404"

        @check("404 for traversal: /../, %2e%2e, symlink out of root")
        def _():
            with conn() as s:
                for rid, p in enumerate(["/../" + os.path.basename(outside) + "/secret.txt",
                                         "/%2e%2e/%2e%2e/etc/passwd", "/link.txt"], 1):
                    h, body, _ = roundtrip(s, rid, get(p))
                    assert h[":status"] == b"404", (p, h[":status"])
                    assert b"secret" not in body

        @check("directory and trailing slash map to index.html; query stripped")
        def _():
            with conn() as s:
                assert roundtrip(s, 1, get("/"))[1] == b"<h1>hi</h1>\n"
                assert roundtrip(s, 2, get("/sub"))[1] == b"sub\n"
                assert roundtrip(s, 3, get("/sub/"))[1] == b"sub\n"
                assert roundtrip(s, 4, get("/index.html?x=1#frag"))[0][":status"] == b"200"
                assert roundtrip(s, 5, get("/%69ndex.html"))[0][":status"] == b"200"

        @check("large file arrives in several DATA frames, intact")
        def _():
            with conn() as s:
                h, body, frames = roundtrip(s, 1, get("/big.bin"))
                assert body == big
                assert h["content-length"] == str(len(big)).encode()
                data = [f for f in frames if f[0] == DATA]
                assert len(data) > 1 and all(n <= 65535 for _, _, n in data)
                assert all(not (fl & END) for _, fl, _ in data[:-1]) and data[-1][1] & END

        @check("empty file: HEADERS carries END, no DATA")
        def _():
            with conn() as s:
                h, body, frames = roundtrip(s, 1, get("/empty.txt"))
                assert h[":status"] == b"200" and body == b"" and len(frames) == 1

        @check("HEAD: headers only, END on HEADERS")
        def _():
            with conn() as s:
                h, body, frames = roundtrip(s, 1, get("/index.html", "HEAD"))
                assert h[":status"] == b"200" and h["content-length"] == b"12"
                assert body == b"" and frames == [(HEADERS, END, frames[0][2])]

        @check("405 for an unsupported method")
        def _():
            with conn() as s:
                assert roundtrip(s, 1, get("/index.html", "POST"))[0][":status"] == b"405"

        malformed = {
            "truncated block":          get("/index.html")[:-3],
            "unassigned index 0x0B":    get("/index.html") + b"\x0b\x00\x00",
            "unassigned index 0xFF":    b"\xff\x00\x00" + get("/index.html"),
            "empty literal name":       get("/index.html") + b"\x00\x00\x00\x00",
            "upper-case literal name":  get("/index.html") + field("X-Foo", "1"),
            "value length overruns":    get("/index.html") + b"\x06\xff\xff",
            "missing :path":            block((":method", "GET")),
            "missing :method":          block((":path", "/index.html")),
            ":path without leading /":  block((":method", "GET"), (":path", "index.html")),
            "duplicate :path":          get("/index.html") + field(":path", "/x"),
            "bad percent escape":       get("/index%zz.html"),
            "percent-encoded NUL":      get("/index.html%00.txt"),
        }
        for label, payload in malformed.items():
            @check(f"400 for malformed request ({label}), then connection still works")
            def _(payload=payload):
                with conn() as s:
                    assert roundtrip(s, 1, payload)[0][":status"] == b"400"
                    assert roundtrip(s, 2, get("/index.html"))[0][":status"] == b"200"

        @check("very long paths are refused, not truncated into another file")
        def _():
            with conn() as s:
                for rid, n in enumerate([1000, 5000, 60000], 1):
                    h, body, _ = roundtrip(s, rid, get("/" + "a" * n))
                    assert h[":status"] in (b"400", b"404"), (n, h[":status"])
                assert roundtrip(s, 9, get("/index.html"))[0][":status"] == b"200"

        @check("400 for request ID 0")
        def _():
            with conn() as s:
                assert roundtrip(s, 0, get("/index.html"))[0][":status"] == b"400"

        @check("unknown frame types (0x02, 0x7f, 0xff; 0, 5, 65535 octets) are skipped")
        def _():
            with conn() as s:
                junk = (frame(0x02, 0, 0) + frame(0x7F, 0xFF, 1, b"hello") +
                        frame(0xFF, 0, 9, b"\x01" * 65535))
                s.sendall(junk + frame(HEADERS, END, 1, get("/index.html")))
                h, body, frames = read_response(s, 1)
                assert h[":status"] == b"200" and body == b"<h1>hi</h1>\n"
                # And nothing was sent in reply to the unknown frames.
                assert frames[0][0] == HEADERS

        @check("unknown frame between a request's HEADERS and its DATA is skipped")
        def _():
            with conn() as s:
                s.sendall(frame(HEADERS, 0, 1, get("/index.html")) +
                          frame(0x42, 0, 1, b"xx") +
                          frame(DATA, 0, 1, b"ignored body") +
                          frame(DATA, END, 1, b""))
                assert read_response(s, 1)[0][":status"] == b"200"

        @check("unknown flag bits are ignored")
        def _():
            with conn() as s:
                assert roundtrip(s, 1, get("/index.html"), flags=0xFE | END)[0][":status"] == b"200"

        @check("literal name for a static-table name is accepted")
        def _():
            with conn() as s:
                p = field(":method", "GET", literal=True) + field(":path", "/index.html", literal=True)
                assert roundtrip(s, 1, p)[0][":status"] == b"200"

        @check("unknown literal headers are ignored")
        def _():
            with conn() as s:
                p = get("/index.html") + field("x-custom", "\x00\xffbinary ok")
                assert roundtrip(s, 1, p)[0][":status"] == b"200"

        @check("400 for DATA with no open request")
        def _():
            with conn() as s:
                s.sendall(frame(DATA, END, 3, b"stray"))
                assert read_response(s, 3)[0][":status"] == b"400"
                assert roundtrip(s, 4, get("/index.html"))[0][":status"] == b"200"

        @check("two concurrent connections")
        def _():
            a, b = conn(), conn()
            with a, b:
                a.sendall(frame(HEADERS, 0, 1, get("/index.html")))   # a's body still open
                assert roundtrip(b, 1, get("/index.html"))[0][":status"] == b"200"
                a.sendall(frame(DATA, END, 1))
                assert read_response(a, 1)[0][":status"] == b"200"

        @check("bcurl -g (unknown frame before each request) against bserve")
        def _():
            r = subprocess.run([BCURL, "-g", f"127.0.0.1:{port}/index.html", "/sub/"],
                               capture_output=True, timeout=10)
            assert r.returncode == 0 and r.stdout == b"<h1>hi</h1>\nsub\n", r
    finally:
        proc.terminate()
        proc.wait()

    # bserve -g sends an unknown frame before each response; bcurl must skip it.
    port = free_port()
    proc = subprocess.Popen([BSERVE, "-g", site, str(port)], stderr=subprocess.DEVNULL)
    try:
        wait_listening(port)

        @check("bserve -g (unknown frame before each response) against bcurl")
        def _():
            r = subprocess.run([BCURL, f"127.0.0.1:{port}/index.html", "/missing"],
                               capture_output=True, timeout=10)
            assert r.stdout == b"<h1>hi</h1>\n404 Not Found\n" and r.returncode == 4, r
    finally:
        proc.terminate()
        proc.wait()


# ============================================================ bcurl tests

class MiniServer:
    """A deliberately awkward but conforming server, built from the spec."""

    def __init__(self, routes):
        self.routes = routes          # path -> (status, body)
        self.accepts = 0
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.accepts += 1
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        with c:
            while True:
                try:
                    ftype, flags, rid, payload = read_frame(c)
                except (EOFError, OSError):
                    return
                if ftype != HEADERS:
                    continue
                h = parse_block(payload)
                status, body = self.routes.get(h[":path"].decode(), (404, b"nope\n"))
                out = frame(0x99, 0xFF, rid, b"skip me")
                out += frame(HEADERS, 0xF0, rid,
                             field(":status", str(status)) +
                             field("content-type", "text/plain", literal=True) +
                             field("x-weird", b"\x00\x01"))
                out += frame(0x10, 0, 0)
                out += frame(DATA, 0, rid, b"")
                for i in range(0, len(body), 3):           # tiny frames
                    out += frame(DATA, 0, rid, body[i:i + 3])
                    out += frame(0xEE, 0, rid, b"\x00" * (i % 5))
                out += frame(DATA, END, rid, b"")
                c.sendall(out)

    def close(self):
        self.sock.close()


def client_tests():
    print("bcurl:")
    srv = MiniServer({"/a": (200, b"alpha body\n"), "/b": (200, b"bravo\n"),
                      "/boom": (503, b"down\n"), "/gone": (410, b"gone\n")})
    base = f"127.0.0.1:{srv.port}"
    try:
        def run(*args):
            return subprocess.run([BCURL, *args], capture_output=True, timeout=10)

        @check("body to stdout; unknown types, flags, literals, tiny frames tolerated")
        def _():
            r = run(f"{base}/a")
            assert r.returncode == 0 and r.stdout == b"alpha body\n", r

        @check("bhttp:// scheme prefix accepted")
        def _():
            assert run(f"bhttp://{base}/b").stdout == b"bravo\n"

        @check("exit 4 on 4xx, body still printed")
        def _():
            r = run(f"{base}/gone")
            assert r.returncode == 4 and r.stdout == b"gone\n", r

        @check("exit 5 on 5xx")
        def _():
            assert run(f"{base}/boom").returncode == 5

        @check("several URLs share exactly one connection")
        def _():
            before = srv.accepts
            r = run(f"{base}/a", "/b", f"bhttp://{base}/gone", "/a")
            assert r.stdout == b"alpha body\nbravo\ngone\nalpha body\n", r
            assert r.returncode == 4
            time.sleep(0.1)
            assert srv.accepts - before == 1, srv.accepts - before

        @check("a URL on a different host:port is refused, no connection made")
        def _():
            before = srv.accepts
            r = run(f"{base}/a", "127.0.0.1:1/x")
            assert r.returncode == 2 and srv.accepts == before, r

        @check("-v hexdumps every frame, both directions")
        def _():
            r = run("-v", f"{base}/a")
            err = r.stderr.decode()
            sent = [l for l in err.splitlines() if l.startswith("> ") and "len=" in l]
            recvd = [l for l in err.splitlines() if l.startswith("< ") and "len=" in l]
            # 1 HEADERS out; in: 2 unknown + HEADERS + empty DATA + 4 DATA
            # + 4 unknown + final DATA = 13.
            assert len(sent) == 1 and len(recvd) == 13, (len(sent), len(recvd))
            assert "<   0000  00 07 99 ff" in err     # the skipped frame, dumped

        @check("exit 1 when the connection cannot be made")
        def _():
            assert run(f"127.0.0.1:{free_port()}/").returncode == 1
    finally:
        srv.close()


if __name__ == "__main__":
    for exe in (BSERVE, BCURL):
        if not os.access(exe, os.X_OK):
            sys.exit(f"{exe} not built; run `make` first")
    server_tests()
    client_tests()
    failed = [n for n, e in results if e]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)
