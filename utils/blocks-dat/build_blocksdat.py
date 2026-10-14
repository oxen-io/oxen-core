#!/usr/bin/env python3
"""
Builds a block hash list (as compiled into oxend from src/blocks/<net>_blocks.dat) from the block
hashes in an oxend LMDB data directory, read with `mdb_dump` (so that no oxend needs to run).

The file is a little-endian uint32 count N followed by N 32-byte group hashes, each the keccak-256
of the 256 consecutive block hashes of heights 256*i .. 256*i+255; so it covers heights 0 to
256*N-1, and STOP_HEIGHT must be of that form.  See README.md for how to use and verify it.

usage: build_blocksdat.py LMDB_DIR STOP_HEIGHT OUTPUT_FILE
"""

import hashlib
import struct
import subprocess
import sys

STEP = 256

# Each block_info value (mdb_block_info): bi_height, bi_timestamp, bi_coins, bi_weight, bi_diff
# (5 u64), bi_hash (32 bytes), bi_cum_rct (u64), bi_long_term_block_weight (u64).
BI_SIZE = 88
BI_HASH_OFF = 40


def keccak256(data):
    return hashlib.new("keccak-256", data).digest()


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__.strip())
    lmdb_dir, stop, out_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    if (stop + 1) % STEP != 0:
        sys.exit(f"stop height {stop} is not of the form k*{STEP}-1")
    try:
        keccak256(b"")
    except ValueError:
        sys.exit("this Python's hashlib has no keccak-256 (it needs OpenSSL 3.2 or later)")
    ngroups = (stop + 1) // STEP

    proc = subprocess.Popen(
        ["mdb_dump", "-s", "block_info", lmdb_dir],
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1 << 20,
    )

    # mdb_dump prints a header, then alternating key and value lines in hex.  block_info is a
    # dup-sorted table under a single zero key, with the values in height order.
    header_done = False
    expect_key = True
    height = 0
    group = []
    groups = []
    for line in proc.stdout:
        if not header_done:
            if line.strip() == "HEADER=END":
                header_done = True
            continue
        if line.strip() == "DATA=END":
            break
        data = bytes.fromhex(line.strip())
        if expect_key:
            if data != b"\0" * 8:
                sys.exit(f"unexpected block_info key {data.hex()}")
            expect_key = False
            continue
        expect_key = True
        if len(data) != BI_SIZE:
            sys.exit(f"unexpected block_info value size {len(data)} at entry {height}")
        (h,) = struct.unpack_from("<Q", data, 0)
        if h != height:
            sys.exit(f"block_info entry {height} has bi_height {h}")
        if height <= stop:
            group.append(data[BI_HASH_OFF : BI_HASH_OFF + 32])
            if len(group) == STEP:
                groups.append(keccak256(b"".join(group)))
                group = []
        height += 1

    rc = proc.wait()
    if rc != 0:
        sys.exit(f"mdb_dump exited with {rc}")

    top = height - 1
    print(f"block_info entries: {height}; top height {top}")
    if top < stop:
        sys.exit(f"database top height {top} is below stop height {stop}")
    assert len(groups) == ngroups and not group

    with open(out_path, "wb") as f:
        f.write(struct.pack("<I", ngroups))
        for g in groups:
            f.write(g)
    print(f"wrote {out_path}: {ngroups} groups covering heights 0..{stop}, {4 + 32 * ngroups} bytes")


if __name__ == "__main__":
    main()
