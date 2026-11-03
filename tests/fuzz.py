#!/usr/bin/env python3
"""Fuzz the wire parsers: random and mutated-structured blobs through the
fuzz driver. Deterministic per --seed."""
import argparse, random, subprocess, sys

p = argparse.ArgumentParser()
p.add_argument("--blobs", type=int, default=200)
p.add_argument("--seed", type=int, default=1)
p.add_argument("--driver", default="build/test-fuzz")
a = p.parse_args()
rng = random.Random(a.seed)

DRIVER = a.driver
def run(blob, label):
    r = subprocess.run([DRIVER], input=blob, capture_output=True)
    if r.returncode != 0:
        print("FAIL(%s, seed=%d): rc=%d\n%s" % (label, a.seed, r.returncode,
              r.stderr.decode(errors="replace")[:2000]))
        sys.exit(1)

# a structurally valid block, mined at build time by the driver itself? No:
# keep the generator pure - random blobs plus parser-shaped mutations.
for i in range(a.blobs):
    n = rng.randrange(0, 2048)
    blob = bytes(rng.randrange(256) for _ in range(n))
    run(blob, "random %d" % i)

# header-shaped: plausible magics/lengths/counts to reach deeper paths
for i in range(a.blobs // 4):
    blob = bytearray(rng.randrange(256) for _ in range(rng.randrange(80, 400)))
    for off in (0, 4, 68, 76):
        if off + 4 <= len(blob):
            blob[off:off+4] = rng.choice([b"\x00\x00\x00\x00", b"\x01\x00\x00\x00",
                                          b"\xff\xff\xff\xff", b" \x00\xff\xff"])
    run(bytes(blob), "shaped %d" % i)
print("fuzz ok: %d blobs, seed %d" % (a.blobs + a.blobs // 4, a.seed))
