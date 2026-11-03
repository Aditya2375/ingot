CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2 -g
# Warnings are not negotiable; keep them outside CFLAGS so a host
# environment cannot strip them.
WARN    := -Wall -Wextra -Werror -Isrc
EXTRA   ?=

CORE    := src/sha256.c src/sha512.c src/ed25519.c src/base58.c src/keys.c src/tx.c src/block.c src/chain.c src/miner.c

all: build/test-unit

build:
	mkdir -p build

HDRS    := $(wildcard src/*.h)

build/test-unit: tests/unit/test-unit.c $(CORE) $(HDRS) | build
	$(CC) $(CFLAGS) $(WARN) $(EXTRA) $^ -o $@ -lm

test: build/test-unit
	./build/test-unit

build/ingot: src/main.c $(CORE) src/store.c src/net.c $(HDRS) | build
	$(CC) $(CFLAGS) $(WARN) $(EXTRA) src/main.c $(CORE) src/store.c src/net.c -o $@ -lm

build/test-fuzz: tests/fuzz/fuzz-driver.c $(CORE) $(HDRS) | build
	$(CC) $(CFLAGS) $(WARN) $(EXTRA) tests/fuzz/fuzz-driver.c $(CORE) -o $@ -lm

sanitize: EXTRA=-fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=all -fno-omit-frame-pointer
sanitize: clean build/test-unit build/test-fuzz
	./build/test-unit
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 python3 tests/fuzz.py --blobs 60

wasm:
	sh wasm/build.sh
	node tests/wasm-smoke.js

clean:
	rm -rf build

.PHONY: all test sanitize wasm clean
