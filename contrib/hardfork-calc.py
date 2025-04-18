#!/usr/bin/python3

import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

# Block target times starting at HF16 are calculated from the timestamp of the last HF15 block:
REFERENCE_BLOCK, REFERENCE_TIME = 641110, 1602469341

def unix_to_block(ts):
    return round((ts - REFERENCE_TIME) / 120) + REFERENCE_BLOCK

def block_to_unix(blockno):
    # The reference timestamp is 21s after an event minute, so when doing this conversion subtract
    # that off to effectively round to the nearest minute:
    return REFERENCE_TIME + (blockno - REFERENCE_BLOCK) * 120 - 21

try:
    dates = []
    for a in sys.argv[1:]:
        if all(c in "0123456789" for c in a):
            ts = int(a)
            if ts < 1_000_000_000:
                # Not a recent timestamp: interpret as a block number
                ts = block_to_unix(ts)
            dates.append(datetime.fromtimestamp(ts))
        else:
            dates.append(datetime.fromisoformat(a))

    if not dates:
        raise RuntimeError("No date(s) provided!")
except Exception as e:
    print(
        f"""
Invalid arguments: {e}

Usage: {sys.argv[0]} 2025-04-29T09:30:00+10:00 [1745884800 1234567 ...] -- calculates Oxen fork block & timestamps.

Arguments can be:
- iso8601 timestamps
- unix seconds
- block numbers
""",
        file=sys.stderr,
    )
    sys.exit(1)

zones = [
    ("Melbourne", ZoneInfo("Australia/Melbourne")),
    ("Fredericton", ZoneInfo("America/Halifax")),
]

for d in dates:
    x = d.astimezone(timezone.utc)
    z = d.timestamp()
    print("\n\nFork block & timestamp for hardfork.cpp:\n")
    # Blocks since HF16 are based on the timestamp of the last block before HF15, which was block
    # 641110 with timestamp 1602469341:
    print(
        f"        hard_fork{{hf::hf???, ?, {unix_to_block(z)}, {int(z)} /*{x:%a, %e %b %Y %H:%M}*/}},\n"
    )
    for name, zone in zones:
        y = d.astimezone(zone)
        print(f"{name} time: {y:%A, %B %e, %Y %H:%M %Z}")
    print()
