# Regenerating the compiled-in block hash list

oxend compiles in a list of known mainnet block hashes (`src/blocks/mainnet_blocks.dat`), and skips
the expensive verification of blocks it covers while syncing.  Past the end of the list, every block
is fully verified, which is far slower, so the list should be extended from time to time.

The file is a little-endian `uint32` count N followed by N 32-byte group hashes: group `i` is the
keccak-256 of the 256 block hashes of heights `256*i` .. `256*i + 255`, so the file covers heights
0 to `256*N - 1`.

## Requirements

- A fully synced mainnet node's LMDB data directory (e.g. `~/.oxen/lmdb`).  It can keep running:
  `mdb_dump` reads a consistent snapshot.
- `mdb_dump` (Debian/Ubuntu package `lmdb-utils`).
- Python 3 whose `hashlib` provides keccak-256 (OpenSSL 3.2 or later); both scripts check this.
- RPC access to two nodes that are independent of the data directory above, for verification:
  any mainnet node's RPC will do (e.g. a public RPC node), as only `get_block_headers_range` is
  used, in batches small enough for restricted RPC.

## Steps

1. Pick the stop height: of the form `256*k - 1`, and comfortably (some thousands of blocks) below
   the chain tip, so that nothing it covers can still be reorganised.

2. Build the new list:

       utils/blocks-dat/build_blocksdat.py ~/.oxen/lmdb STOP_HEIGHT new_blocks.dat

3. Verify it against the current list and two independent nodes:

       utils/blocks-dat/verify_blocksdat.py src/blocks/mainnet_blocks.dat new_blocks.dat STOP_HEIGHT \
           http://PRIMARY_NODE:22023 https://FALLBACK_NODE

   This checks that the file is well-formed, that the current list is an exact prefix of it, and
   that every added group matches the block hashes (and their `prev_hash` links) that the nodes
   report.  It exits non-zero on any problem.  Each batch goes to the primary node, and only to
   the fallback when the primary can't serve it.

4. Install it: copy `new_blocks.dat` over `src/blocks/mainnet_blocks.dat`, and update
   `EXPECTED_SHA256_HASH` in `Blockchain::load_compiled_in_block_hashes`
   (`src/cryptonote_core/blockchain.cpp`) to its `sha256sum`.  The build re-embeds the file when
   it changes.

## Example

The 2026-10-09 regeneration (stop height 2,215,423), verified against a node independent of the
one it was built from:

    structure: old 1941 groups (62116 bytes), new 8654 groups (276932 bytes), 4 + count*32 == size for both, new count == (stop+1)/256 == 8654
    prefix: all 1941 old groups (heights 0..496895) identical in new file
      fetched 200/2238 batches
      ...
      fetched 2200/2238 batches
    cross-check: groups 1941..8653 (heights 496896..2215423), 6713 groups
      heights 496896..2215423 (1718528 blocks, 6713 groups) from primary http://PRIMARY_NODE:22023
      prev_hash chain breaks within fetched range: 0
      matched 6713/6713 groups; mismatches: 0
