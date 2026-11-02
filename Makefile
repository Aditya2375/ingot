CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2 -g -Wall -Wextra -Werror -Isrc
EXTRA   ?=

CORE    := src/sha256.c src/sha512.c src/ed25519.c src/base58.c src/keys.c src/tx.c src/block.c

all: build/test-unit

build:
	mkdir -p build

HDRS    := $(wildcard src/*.h)

build/test-unit: tests/unit/test-unit.c $(CORE) $(HDRS) | build
	$(CC) $(CFLAGS) $(EXTRA) $^ -o $@ -lm

test: build/test-unit
	./build/test-unit

clean:
	rm -rf build

.PHONY: all test clean
