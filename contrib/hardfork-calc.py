#!/usr/bin/python3

import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

try:
    dates = [datetime.fromisoformat(a) for a in sys.argv[1:]]
    if not dates:
        raise RuntimeError("No date(s) provided!")
except Exception as e:
    print(
        f"""
Invalid arguments: {e}

Usage: {sys.argv[0]} 2025-04-29T09:30:00+10:00 [...] -- calculates Oxen fork block & timestamps.
""",
        file=sys.stderr,
    )
    sys.exit(1)

zones = [
        ("Melbourne", ZoneInfo("Australia/Melbourne")),
        ("Fredericton", ZoneInfo("America/Halifax"))
        ]

for d in dates:
    x = d.astimezone(timezone.utc)
    z = d.timestamp()
    print("\n\nFork block & timestamp for hardfork.cpp:\n")
    # Blocks since HF16 are based on the timestamp of the last block before HF15, which was block
    # 641110 with timestamp 1602469341:
    print(f"    {((z - 1602469341) / 120) + 641110},")
    print(f"    {int(z)} /* {x:%A, %B %e, %Y %H:%M} UTC */\n")
    for name, zone in zones:
        y = d.astimezone(zone)
        print(f"{name} time: {y:%A, %B %e, %Y %H:%M %Z}")
    print()
