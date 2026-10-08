#!/bin/sh
# Runs inside the Docker container (see tests/linux/README in the top README):
#   1. Linux build with gcc, warnings as errors, conformance suite
#   2. AddressSanitizer + UBSan + LeakSanitizer build, conformance suite
#   3. Valgrind memcheck on bserve (incl. forked children) and bcurl
# Exits non-zero if any stage finds a problem.
cp -r /src/. /work/ && cd /work || exit 1
CF="-std=c11 -Wall -Wextra -Wpedantic -Werror -D_DEFAULT_SOURCE"
fail=0

echo "=== 1. Linux build (gcc $(gcc -dumpversion), -Werror) + conformance suite"
make clean >/dev/null
if make CFLAGS="$CF -O2" >/tmp/build.log 2>&1; then echo "build ok, no warnings"
else cat /tmp/build.log; exit 1; fi
python3 tests/conformance.py >/tmp/t1.log 2>&1 || fail=1
grep FAIL /tmp/t1.log; tail -1 /tmp/t1.log

echo "=== 2. ASan + UBSan + LeakSanitizer build + conformance suite"
make clean >/dev/null
make CFLAGS="$CF -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" >/dev/null 2>&1 || exit 1
rm -f /tmp/san.*
# Reports go to files: the suite sends bserve's stderr to /dev/null.
ASAN_OPTIONS=log_path=/tmp/san.asan UBSAN_OPTIONS=log_path=/tmp/san.ubsan:print_stacktrace=1 \
    python3 tests/conformance.py >/tmp/t2.log 2>&1 || fail=1
grep FAIL /tmp/t2.log; tail -1 /tmp/t2.log
reports=$(ls /tmp/san.* 2>/dev/null)
if [ -n "$reports" ]; then echo "SANITIZER REPORTS:"; cat $reports; fail=1
else echo "no sanitizer reports"; fi

echo "=== 3. Valgrind memcheck"
make clean >/dev/null; make CFLAGS="$CF -g -O0" >/dev/null 2>&1 || exit 1
VG="valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite,indirect --trace-children=yes"
$VG --log-file=/tmp/vg.server.%p ./bserve -g ./www 9000 2>/dev/null &
srv=$!
sleep 3
$VG --log-file=/tmp/vg.client.%p ./bcurl -v -g localhost:9000/index.html /about.html /nope /docs/ >/dev/null 2>&1
echo "bcurl exit: $? (4 expected: one 404)"
python3 - <<'PY'
import socket, struct, time
fr = lambda t, f, i, p=b"": struct.pack(">HBBI", len(p), t, f, i) + p
s = socket.create_connection(("127.0.0.1", 9000))
# malformed blocks, a full-size unknown frame, stray DATA, a long path, a good request
s.sendall(fr(1, 1, 1, b"\x0b\x00\x00") + fr(1, 1, 2, b"\x01\xff") + fr(0x7f, 0, 0, b"x" * 65535)
          + fr(0, 1, 3, b"stray") + fr(1, 1, 4, b"\x01\x00\x03GET\x02\xea\x60/" + b"a" * 59999)
          + fr(1, 1, 5, b"\x01\x00\x03GET\x02\x00\x01/"))
time.sleep(2); s.close(); time.sleep(1)
print("raw-socket abuse sent")
PY
kill -INT $srv; sleep 2; kill $srv 2>/dev/null
# "ERROR SUMMARY: 0 errors" and no definite/indirect leaks in every log.
bad=0
for f in /tmp/vg.*; do
  grep -q "ERROR SUMMARY: 0 errors" "$f" || { echo "--- $f"; cat "$f"; bad=1; }
done
n=$(ls /tmp/vg.* | wc -l)
if [ $bad = 0 ]; then echo "valgrind: 0 errors, 0 leaks in all $n processes (server, its children, client)"
else fail=1; fi

[ $fail = 0 ] && echo "=== ALL LINUX CHECKS PASSED" || echo "=== SOME LINUX CHECKS FAILED"
exit $fail
