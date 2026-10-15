#!/usr/bin/env python3
"""
Verifies a regenerated block hash list against the one it replaces and against block hashes fetched
over RPC from nodes independent of the database it was built from.

Checks that the new file is well-formed and covers heights 0..STOP_HEIGHT, that the old file is an
exact prefix of it, and that every group hash it adds matches the hashes (and the prev_hash links)
of the blocks the RPC nodes report.  Exits non-zero on any mismatch.

usage: verify_blocksdat.py OLD_DAT NEW_DAT STOP_HEIGHT PRIMARY_RPC_URL FALLBACK_RPC_URL

Each batch of blocks is asked of the primary first, and only goes to the fallback if the primary
can't serve it (e.g. a load-balanced address whose nodes aren't all synced that far).
"""

import hashlib
import json
import struct
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

STEP = 256
GROUPS_PER_BATCH = 3  # 768 blocks: under the 1000-block limit of restricted (public) RPC
PRIMARY_ATTEMPTS = 8
FALLBACK_ATTEMPTS = 5


def keccak256(data):
    return hashlib.new("keccak-256", data).digest()


def parse(path, name):
    data = open(path, "rb").read()
    (count,) = struct.unpack_from("<I", data, 0)
    if len(data) != 4 + count * 32:
        sys.exit(f"{name}: size {len(data)} != 4 + {count}*32")
    return len(data), count, [data[4 + 32 * i : 36 + 32 * i] for i in range(count)]


def rpc(url, start, end):
    """Fetches the (hash, prev_hash) of each block in [start, end]; or (None, error)."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_block_headers_range",
            "params": {"start_height": start, "end_height": end},
        }
    ).encode()
    req = urllib.request.Request(url + "/json_rpc", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        d = json.load(resp)
    if "error" in d:
        return None, d["error"].get("message")
    hdrs = d["result"]["headers"]
    if len(hdrs) != end - start + 1:
        return None, f"got {len(hdrs)} headers"
    for i, h in enumerate(hdrs):
        if h["height"] != start + i:
            return None, f"header {i} has height {h['height']}"
    return [(bytes.fromhex(h["hash"]), bytes.fromhex(h["prev_hash"])) for h in hdrs], None


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__.strip())
    old_path, new_path, stop, primary_url, fallback_url = sys.argv[1:6]
    stop = int(stop)
    try:
        keccak256(b"")
    except ValueError:
        sys.exit("this Python's hashlib has no keccak-256 (it needs OpenSSL 3.2 or later)")

    old_size, old_count, old_groups = parse(old_path, "old")
    new_size, new_count, new_groups = parse(new_path, "new")
    if (stop + 1) % STEP or new_count != (stop + 1) // STEP:
        sys.exit(f"new count {new_count} does not match stop height {stop}")
    print(
        f"structure: old {old_count} groups ({old_size} bytes), new {new_count} groups "
        f"({new_size} bytes), 4 + count*32 == size for both, new count == (stop+1)/256 == "
        f"{(stop + 1) // STEP}"
    )
    if new_groups[:old_count] != old_groups:
        bad = next(i for i in range(old_count) if new_groups[i] != old_groups[i])
        sys.exit(f"old file is NOT a prefix of new file: first differing group {bad}")
    print(f"prefix: all {old_count} old groups (heights 0..{old_count * STEP - 1}) identical in new file")

    def fetch(g0):
        start = g0 * STEP
        end = min(g0 + GROUPS_PER_BATCH, new_count) * STEP - 1
        err = None
        for _ in range(PRIMARY_ATTEMPTS):
            try:
                hashes, err = rpc(primary_url, start, end)
            except Exception as e:
                hashes, err = None, str(e)
            if hashes:
                return g0, "primary", hashes
        for attempt in range(FALLBACK_ATTEMPTS):
            try:
                hashes, err = rpc(fallback_url, start, end)
            except Exception as e:
                hashes, err = None, str(e)
            if hashes:
                return g0, "fallback", hashes
            time.sleep(2 + attempt * 3)
        raise RuntimeError(f"could not fetch {start}..{end}: {err}")

    batches = list(range(old_count, new_count, GROUPS_PER_BATCH))
    results = {}
    with ThreadPoolExecutor(4) as ex:
        for n, (g0, src, hashes) in enumerate(ex.map(fetch, batches), 1):
            results[g0] = (src, hashes)
            if n % 200 == 0:
                print(f"  fetched {n}/{len(batches)} batches", flush=True)

    mismatches = []
    matched = 0
    src_ranges = []  # [source, first height, last height] of each run from the same node
    prev = None
    prev_link_breaks = 0
    for g0 in batches:
        src, hashes = results[g0]
        lo = g0 * STEP
        hi = lo + len(hashes) - 1
        if src_ranges and src_ranges[-1][0] == src and src_ranges[-1][2] == lo - 1:
            src_ranges[-1][2] = hi
        else:
            src_ranges.append([src, lo, hi])
        for h, ph in hashes:
            if prev is not None and ph != prev:
                prev_link_breaks += 1
            prev = h
        for k in range(len(hashes) // STEP):
            calc = keccak256(b"".join(h for h, _ in hashes[k * STEP : (k + 1) * STEP]))
            if calc == new_groups[g0 + k]:
                matched += 1
            else:
                mismatches.append(g0 + k)

    checked = new_count - old_count
    print(f"cross-check: groups {old_count}..{new_count - 1} (heights {old_count * STEP}..{stop}), {checked} groups")
    for src, lo, hi in src_ranges:
        url = primary_url if src == "primary" else fallback_url
        print(f"  heights {lo}..{hi} ({hi - lo + 1} blocks, {(hi - lo + 1) // STEP} groups) from {src} {url}")
    print(f"  prev_hash chain breaks within fetched range: {prev_link_breaks}")
    print(
        f"  matched {matched}/{checked} groups; mismatches: {len(mismatches)}"
        + (f" first at group {mismatches[0]}" if mismatches else "")
    )
    sys.exit(1 if mismatches or matched != checked or prev_link_breaks else 0)


if __name__ == "__main__":
    main()
