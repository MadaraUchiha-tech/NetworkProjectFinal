#!/usr/bin/env python3
"""Builds docs/hexdump.html from docs/capture.txt (the stderr of `bcurl -v`).

The annotations below are written by hand, one entry per field. The script only
lays them over the captured octets — and asserts that they tile every frame
exactly and that each length/value claim matches the bytes on the wire.

    ./bcurl -v localhost:9000/index.html 2> docs/capture.txt
    python3 docs/make_hexdump.py
"""
import html
import os
import re
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def frames_from_capture(path):
    """Returns [(direction, bytes)] — one entry per frame in the -v output."""
    out, cur = [], None
    for line in open(path):
        if re.match(r"^[<>] \w+\(0x", line):
            cur = [line[0], bytearray()]
            out.append(cur)
        m = re.match(r"^[<>]   [0-9a-f]{4}  (.*?)\s*\|", line)
        if m and cur:
            cur[1] += bytes.fromhex(m.group(1))
    return [(d, bytes(b)) for d, b in out]


# (octets, field, meaning). A value of None for octets means "the rest".
# `check` entries are verified against the real bytes.
def hdr(length, ftype, tname, flags, fdesc, rid):
    return [
        (2, "Length", f"0x{length:04x} = {length}: payload octets after this 8-octet header"),
        (1, "Type", f"0x{ftype:02x} = {tname}"),
        (1, "Flags", fdesc),
        (4, "Request ID", f"{rid}: {'first request on this connection' if rid == 1 else ''}"),
    ]


def field(idx, name, value, note=""):
    v = value.encode()
    return [
        (1, "prefix", f"0x{idx:02x}: static index {idx} = <code>{name}</code> (name costs 1 octet)"),
        (2, "value length", f"0x{len(v):04x} = {len(v)}"),
        (len(v), "value", f"\"{html.escape(value)}\"{(' — ' + note) if note else ''}"),
    ]


REQUEST = (
    hdr(53, 1, "HEADERS", 0x01, "0x01 = END: no request body follows", 1)
    + field(1, ":method", "GET")
    + field(2, ":path", "/index.html")
    + field(4, "host", "localhost:9000")
    + field(5, "user-agent", "bcurl/1")
    + field(6, "accept", "*/*")
)


def response_headers(date):
    return (
        hdr(81, 1, "HEADERS", 0x00, "0x00: END clear, so DATA frames follow", 1)
        + field(3, ":status", "200", "three ASCII digits")
        + field(9, "server", "bserve/1")
        + field(10, "date", date, "RFC 1123 time, 29 octets")
        + field(7, "content-type", "text/html; charset=utf-8", "chosen from the .html extension")
        + field(8, "content-length", "39", "advisory; END is what ends the body")
    )


def response_data(body):
    return hdr(len(body), 0, "DATA", 0x01, "0x01 = END: last frame of this response", 1) + [
        (len(body), "body", "the 39 octets of www/index.html, sent unchanged: "
                            + html.escape(repr(body.decode()))),
    ]


def render_frame(title, data, ann, base):
    total = sum(n for n, _, _ in ann)
    assert total == len(data), f"{title}: annotations cover {total} octets, frame is {len(data)}"
    # Cross-check every claim against the wire.
    length = struct.unpack(">H", data[:2])[0]
    assert length == len(data) - 8, title
    rows, off = [], 0
    for i, (n, name, meaning) in enumerate(ann):
        chunk = data[off:off + n]
        if name == "value length":
            want = struct.unpack(">H", chunk)[0]
            assert ann[i + 1][0] == want, f"{title}: value length {want} != {ann[i + 1][0]}"
        if name == "value":
            m = re.match(r'^"(.*?)"', html.unescape(meaning))
            assert m and chunk == m.group(1).encode(), f"{title}: {chunk!r} vs {meaning}"
        hexs = " ".join(f"{b:02x}" for b in chunk)
        if n > 12:
            hexs = " ".join(f"{b:02x}" for b in chunk[:12]) + f" … ({n} octets)"
        rng = f"{base + off:04x}" if n == 1 else f"{base + off:04x}–{base + off + n - 1:04x}"
        cls = "hdr" if off < 8 else ("pre" if name == "prefix" else ("len" if "length" in name else "val"))
        rows.append(f'<tr class="{cls}"><td>{rng}</td><td class="hx">{hexs}</td>'
                    f"<td>{name}</td><td>{meaning}</td></tr>")
        off += n
    dump = []
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in row[:8]) + "  " + " ".join(f"{b:02x}" for b in row[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        dump.append(f"{base + i:04x}  {hx:<49} |{html.escape(asc)}|")
    return (f"<h2>{title}</h2><pre>{chr(10).join(dump)}</pre>"
            f"<table class=\"f\"><tr><th>Offset</th><th>Octets</th><th>Field</th><th>Meaning</th></tr>"
            f"{''.join(rows)}</table>")


def main():
    frames = frames_from_capture(os.path.join(HERE, "capture.txt"))
    assert [d for d, _ in frames] == [">", "<", "<"], frames
    (_, req), (_, rh), (_, rd) = frames
    date = re.search(rb"\x0a\x00\x1d(.{29})", rh).group(1).decode()

    parts = [
        render_frame("Client → server: frame 1, HEADERS (the request) — 61 octets", req, REQUEST, 0),
        render_frame("Server → client: frame 1, HEADERS (the response head) — 89 octets",
                     rh, response_headers(date), 0),
        render_frame("Server → client: frame 2, DATA (the body) — 47 octets",
                     rd, response_data(rd[8:]), len(rh)),
    ]
    page = open(os.path.join(HERE, "hexdump.template.html")).read()
    page = page.replace("<!--FRAMES-->", "\n".join(parts))
    open(os.path.join(HERE, "hexdump.html"), "w").write(page)
    print("wrote docs/hexdump.html")


if __name__ == "__main__":
    main()
