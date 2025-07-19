#!/usr/bin/python3

# This script generates the src/blockchain_db/sqlite/snapshots.cpp
#
# Usage: pass the path to oxend's sqlite.db file as the only argument.

import web3
import sqlite3
import sys

sqlite_db = sys.argv[1]

conn = sqlite3.connect(f"file:{sqlite_db}?mode=ro", uri=True)
cur = conn.cursor()

cur.execute("SELECT MAX(height) FROM batched_payments_accrued_archive")
height = cur.fetchone()[0]

print(
    f"""// This file is generated from contrib/mk_delayed_payments_snapshot.py

#include "snapshots.h"

#include <crypto/literals.h>

namespace cryptonote::snapshots {{

using namespace crypto::literals;

const int64_t height = {height};

static constexpr std::initializer_list<DelayedPayment> delayed_payments_impl{{
        // clang-format off"""
)


def famt(amt, sesh_digits=5):
    return (
        f"{amt // 1_000_000_000:{sesh_digits}d}'{amt % 1_000_000_000:09d}"
        if amt >= 1_000_000_000
        else f"{amt:{sesh_digits + 10}d}"
    )


def fbig(amt):
    return famt(amt, 7)


for row in cur.execute(
    """
    SELECT eth_address, amount, payout_height, height, block_height, block_tx_index, contributor_index, liquidation_amount
    FROM delayed_payments
    WHERE height <= ?
    ORDER BY height, block_height, block_tx_index
    """,
    (height,),
):

    eth, amt, ph, h, bh, tx, icont, liq = row

    print(
        f'    {{"{web3.Web3.to_checksum_address(eth)}"_eth, {famt(amt)}, {ph:7d}, {h:7d}, {bh:7d}, {tx:2d}, {icont}, {liq}}},'
    )

print(
    """
        // clang-format on
};
const std::span<const DelayedPayment> delayed_payments{delayed_payments_impl};

static constexpr std::initializer_list<BatchedPaymentAccrued> batched_payments_impl{
        // clang-format off"""
)


for row in cur.execute(
    """
    SELECT address, amount, lifetime_locked_stakes, lifetime_unlocked_stakes, lifetime_liquidated_stakes, lifetime_rewards
    FROM batched_payments_accrued_archive
    WHERE height = ?
    """,
    (height,),
):
    eth, amt, lls, lus, lqs, lr = row
    print(
        f'    {{"{web3.Web3.to_checksum_address(eth)}"_eth, {fbig(amt)}, {fbig(lls)}, {fbig(lus)}, {fbig(lqs)}, {fbig(lr)}}},'
    )


print(
    """
        //clang-format on
};
const std::span<const BatchedPaymentAccrued> batched_payments{batched_payments_impl};

}  // namespace cryptonote::snapshots""",
)
