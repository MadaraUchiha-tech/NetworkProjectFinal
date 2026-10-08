CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE

all: bserve bcurl

bserve: src/bserve.c src/proto.c src/proto.h
	$(CC) $(CFLAGS) -o $@ src/bserve.c src/proto.c

bcurl: src/bcurl.c src/proto.c src/proto.h
	$(CC) $(CFLAGS) -o $@ src/bcurl.c src/proto.c

test: all
	python3 tests/conformance.py

clean:
	rm -rf bserve bcurl *.dSYM

.PHONY: all test clean
