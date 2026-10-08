# BHTTP/1 — HTTP, in binary

A fixed-header binary framing for HTTP semantics, with a server (`bserve`), a
client (`bcurl`), and an independent conformance suite.

## Deliverables

| # | What | Where |
|---|------|-------|
| 1 | The spec (two pages) | [`docs/SPEC.pdf`](docs/SPEC.pdf) (source: `docs/spec.html`) |
| 2 | The program | `src/` — `bserve.c`, `bcurl.c`, shared `proto.c`/`proto.h`; `Makefile` |
| 3 | Annotated hexdump of one request + response | [`docs/HEXDUMP.pdf`](docs/HEXDUMP.pdf) (raw capture: `docs/capture.txt`) |

## The protocol in one screen

```
 frame header, 8 octets, big-endian
+---------------+-------+-------+-------------------------------+
|  Length (16)  | Type  | Flags |        Request ID (32)        |  then Length payload octets
+---------------+-------+-------+-------------------------------+
 types: 0x00 DATA, 0x01 HEADERS, 0x02-0xFF unassigned -> receiver MUST skip
 flags: 0x01 END (last frame of the message); unknown bits ignored

 header field:  idx(1)=0x01..0x0A  vlen(2) value          -- static table name
                0x00 nlen(1) name  vlen(2) value          -- literal name
 static table:  1 :method  2 :path  3 :status  4 host  5 user-agent
                6 accept   7 content-type  8 content-length  9 server  10 date
```

## Build and run

```sh
make                                   # builds ./bserve and ./bcurl (C11, no deps)

./bserve ./www 9000                    # terminal 1
./bcurl -v localhost:9000/index.html   # terminal 2: body on stdout, frames hexdumped on stderr
```

More client examples:

```sh
./bcurl localhost:9000/index.html /about.html /style.css   # 3 requests, ONE connection
./bcurl -I localhost:9000/index.html                       # HEAD, print headers
./bcurl localhost:9000/missing; echo $?                    # 404 body, exit status 4
./bcurl -g localhost:9000/                                 # sends an unknown frame type first; server skips it
./bserve -g ./www 9000                                     # server sends unknown frames; bcurl skips them
./bserve -v ./www 9000                                     # server hexdumps its frames too
```

Exit status of `bcurl`: `0` all responses 1xx–3xx, `4` any 4xx, `5` any 5xx,
`1` network/protocol error, `2` usage error.

## Tests

```sh
make test
```

`tests/conformance.py` is a second, independent implementation of the spec
(Python, no shared code). 42 checks, including:

- **bserve**: 200/404/405, HEAD, empty files, multi-frame bodies, keep-alive,
  pipelining, 1-octet TCP writes, path traversal and symlink escape, 12 kinds
  of malformed request (each must produce 400 *and leave the connection usable*),
  unknown frame types of size 0 / 5 / 65 535, unknown flags, literal names.
- **bcurl**: run against a deliberately awkward Python server that interleaves
  unknown frames, sends unknown flags, literal names and zero-length DATA,
  and counts TCP connections, which must be exactly one for several URLs.

Linux build plus memory checking (AddressSanitizer, UBSan, LeakSanitizer and
Valgrind), via Docker:

```sh
docker build -t bhttp-test tests/linux
docker run --rm -v "$PWD":/src:ro bhttp-test sh /src/tests/linux/run.sh
```

## Regenerating the docs

```sh
./bserve ./www 9000 &
./bcurl -v localhost:9000/index.html 2> docs/capture.txt
python3 docs/make_hexdump.py           # checks every annotation against the bytes
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless=new --no-pdf-header-footer --print-to-pdf=docs/SPEC.pdf    docs/spec.html
"$CHROME" --headless=new --no-pdf-header-footer --print-to-pdf=docs/HEXDUMP.pdf docs/hexdump.html
```
