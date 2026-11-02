CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2 -g
# Warnings are not negotiable; keep them outside CFLAGS so a host
# environment cannot strip them.
WARN    := -Wall -Wextra -Werror -Isrc
EXTRA   ?=

CORE    := src/sha256.c src/sha512.c src/ed25519.c src/base58.c src/keys.c src/tx.c src/block.c src/chain.c

all: build/test-unit

build:
	mkdir -p build

HDRS    := $(wildcard src/*.h)

build/test-unit: tests/unit/test-unit.c $(CORE) $(HDRS) | build
	$(CC) $(CFLAGS) $(WARN) $(EXTRA) $^ -o $@ -lm

test: build/test-unit
	./build/test-unit

clean:
	rm -rf build

.PHONY: all test clean
