import pytest
import time
import re
from functools import partial

from service_node_network import coins, vprint
from ledgerapi import LedgerAPI
from expected import *
import daemons


def balance(c):
    """Shortcut for coins(c,c), particularly useful when c is complex"""
    return coins(c, c)


def test_init(net, mike, hal, ledger):
    """
    Tests that the node fakenet got initialized properly, and that the wallet starts up and shows
    the right address.
    """

    # All nodes should be at the same height:
    heights = [x.rpc("/get_height").json()["height"] for x in net.all_nodes]
    height = max(heights)
    assert heights == [height] * len(net.all_nodes)

    assert mike.height(refresh=True) == height
    assert mike.balances() > (0, 0)
    assert hal.height(refresh=True) == height
    assert hal.balances() == (0, 0)

    address = hal.address()

    def check_addr(_, m):
        assert address.startswith(m[1][1]) and address.endswith(m[1][2])

    check_interactions(
        ledger,
        MatchScreen([r"^OXEN wallet$", r"^(\w+)\.\.(\w+)$"], check_addr),
        Do.both,  # Hitting both on the main screen shows us the full address details
        ExactScreen(["Regular address", "(fakenet)"]),
        Do.right,
        MatchMulti("Address", address),
        Do.right,
        ExactScreen(["Back"]),
        Do.both,
        MatchScreen([r"^OXEN wallet$", r"^(\w+)\.\.(\w+)$"], check_addr),
    )


def test_receive(net, mike, hal):
    mike.transfer(hal, coins(100))
    net.mine(blocks=2)
    assert hal.balances(refresh=True) == coins(100, 0)
    net.mine(blocks=7)
    assert hal.balances(refresh=True) == coins(100, 0)
    net.mine(blocks=1)
    assert hal.balances(refresh=True) == coins(100, 100)


class StoreFee:
    def __init__(self):
        self.fee = None

    def __call__(self, _, m):
        self.fee = float(m[1][1])


def test_send(net, mike, alice, hal, ledger):
    mike.transfer(hal, coins(100))
    net.mine()
    hal.refresh()

    store_fee = StoreFee()

    run_with_interactions(
        ledger,
        partial(hal.transfer, alice, coins(42.5)),
        ExactScreen(["Processing TX"]),
        MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.left,
        Do.both,
        ExactScreen(["Confirm Amount", "42.5"], fail_index=1),
        Do.right,
        MatchMulti("Recipient", alice.address()),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.right,  # This loops back around to the amount:
        ExactScreen(["Confirm Amount", "42.5"]),
        Do.left,
        Do.left,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing TX"]),
    )

    net.mine(1)
    remaining = coins(100 - 42.5 - store_fee.fee)
    hal_bal = hal.balances(refresh=True)
    assert hal_bal[0] == remaining
    assert hal_bal[1] < remaining
    assert alice.balances(refresh=True) == coins(42.5, 0)
    net.mine(9)
    assert hal.balances(refresh=True) == (remaining, remaining)
    assert alice.balances(refresh=True) == coins(42.5, 42.5)


def test_multisend(net, mike, alice, bob, hal, ledger):
    mike.transfer(hal, coins(105))
    net.mine()

    assert hal.balances(refresh=True) == coins(105, 105)

    store_fee = StoreFee()

    recipient_addrs = []

    def store_addr(val):
        nonlocal recipient_addrs
        recipient_addrs.append(val)

    recipient_amounts = []

    def store_amount(_, m):
        nonlocal recipient_addrs
        recipient_amounts.append(m[1][1])

    recipient_expected = [
        (alice.address(), "18.0"),
        (bob.address(), "19.0"),
        (alice.address(), "20.0"),
        (alice.address(), "21.0"),
        (hal.address(), "22.0"),
    ]

    hal.timeout = 120  # creating this tx with the ledger takes ages
    run_with_interactions(
        ledger,
        partial(hal.multi_transfer, [alice, bob, alice, alice, hal], coins(18, 19, 20, 21, 22)),
        ExactScreen(["Processing TX"]),
        MatchScreen([r"^Confirm Fee$", r"^(0\.\d{1,9})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        *(
            cmds
            for i in range(len(recipient_expected))
            for cmds in [
                MatchScreen([r"^Confirm Amount$", r"^(\d+\.\d+)$"], store_amount, fail_index=1),
                Do.right,
                MatchMulti("Recipient", None, callback=store_addr),
                Do.right,
                ExactScreen(["Accept"]),
                Do.both,
            ]
        ),
        ExactScreen(["Processing TX"]),
        timeout=120,
    )

    recipient_expected.sort()

    recipient_got = list(zip(recipient_addrs, recipient_amounts))
    recipient_got.sort()

    assert recipient_expected == recipient_got

    net.mine(1)
    remaining = coins(105 - 100 - store_fee.fee + 22)
    hal_bal = hal.balances(refresh=True)
    assert hal_bal[0] == remaining
    assert hal_bal[1] < remaining
    assert alice.balances(refresh=True) == coins(18 + 20 + 21, 0)
    assert bob.balances(refresh=True) == coins(19, 0)
    net.mine(9)
    assert hal.balances(refresh=True) == (remaining,) * 2
    assert alice.balances(refresh=True) == balance(18 + 20 + 21)
    assert bob.balances(refresh=True) == balance(19)


def test_reject_send(net, mike, alice, hal, ledger):
    mike.transfer(hal, coins(100))
    net.mine()
    hal.refresh()

    with pytest.raises(daemons.TransferFailed):
        run_with_interactions(
            ledger,
            partial(hal.transfer, alice, coins(42.5)),
            ExactScreen(["Processing TX"]),
            MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], fail_index=1),
            Do.right,
            ExactScreen(["Accept"]),
            Do.right,
            ExactScreen(["Reject"]),
            Do.both,
        )

    with pytest.raises(daemons.TransferFailed):
        run_with_interactions(
            ledger,
            partial(hal.transfer, alice, coins(42.5)),
            ExactScreen(["Processing TX"]),
            MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], fail_index=1),
            Do.right,
            ExactScreen(["Accept"]),
            Do.both,
            ExactScreen(["Confirm Amount", "42.5"], fail_index=1),
            Do.right,
            MatchMulti("Recipient", alice.address()),
            Do.right,
            ExactScreen(["Accept"]),
            Do.right,
            ExactScreen(["Reject"]),
            Do.both,
        )

    store_fee = StoreFee()

    run_with_interactions(
        ledger,
        partial(hal.transfer, alice, coins(42.5)),
        ExactScreen(["Processing TX"]),
        MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Confirm Amount", "42.5"], fail_index=1),
        Do.right,
        MatchMulti("Recipient", alice.address()),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
    )

    net.mine(10)
    assert hal.balances(refresh=True) == balance(100 - 42.5 - store_fee.fee)


def test_subaddr_receive(net, mike, hal):
    hal.json_rpc("create_address", {"count": 3})
    subaddrs = [hal.get_subaddress(0, i) for i in range(1, 4)]
    mike.multi_transfer(subaddrs, coins([5] * len(subaddrs)))

    subaddr0 = "LQM2cdzDY311111111111111111111111111111111111111111111111111111111111111111111111111111116onhCC"
    subaddrZ = "La3hdSoi9JWjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVrgyHVC"

    for s in subaddrs:
        assert subaddr0 <= s <= subaddrZ

    assert len(set(subaddrs)) == len(subaddrs)

    net.mine(blocks=2)
    assert hal.balances(refresh=True) == coins(5 * len(subaddrs), 0)
    net.mine(blocks=8)
    assert hal.balances(refresh=True) == balance(5 * len(subaddrs))

    subaccounts = []
    for i in range(3):
        r = hal.json_rpc("create_account").json()["result"]
        assert r["account_index"] == i + 1
        assert subaddr0 <= r["address"] <= subaddrZ
        subaccounts.append(r["address"])
        hal.json_rpc("create_address", {"account_index": i + 1, "count": 1})

    assert len(set(subaccounts + subaddrs)) == len(subaccounts) + len(subaddrs)

    for i in range(3):
        assert subaccounts[i] == hal.get_subaddress(i + 1, 0)
        subaddrs.append(hal.get_subaddress(i + 1, 1))

    for s in subaddrs:
        assert subaddr0 <= s <= subaddrZ

    assert len(set(subaccounts + subaddrs)) == len(subaccounts) + len(subaddrs)

    assert len(subaccounts) + len(subaddrs) == 9

    mike.multi_transfer(
        subaddrs + subaccounts, coins(list(range(1, 1 + len(subaddrs) + len(subaccounts))))
    )

    net.mine()

    hal.refresh()
    balances = []
    for i in range(len(subaccounts) + 1):
        r = hal.json_rpc(
            "get_balance", {"account_index": i, "subaddress_indices": list(range(10))}
        ).json()["result"]
        balances.append(
            (
                r["balance"],
                r["unlocked_balance"],
                {x["address"]: x["unlocked_balance"] for x in r["per_subaddress"]},
            )
        )

    assert balances == [
        (coins(21), coins(21), {subaddrs[i]: coins(5 + i + 1) for i in range(3)}),
        (coins(11), coins(11), {subaddrs[3]: coins(4), subaccounts[0]: coins(7)}),
        (coins(13), coins(13), {subaddrs[4]: coins(5), subaccounts[1]: coins(8)}),
        (coins(15), coins(15), {subaddrs[5]: coins(6), subaccounts[2]: coins(9)}),
    ]


def test_subaddr_send(net, mike, alice, bob, hal, ledger):
    mike.transfer(hal, coins(100))
    net.mine()

    alice.json_rpc("create_address", {"count": 2})
    bob.json_rpc("create_address", {"count": 2})

    hal.refresh()
    mike_bal = mike.balances(refresh=True)

    to = [
        addrs
        for w in (alice, bob)
        for addrs in (w.address(), w.get_subaddress(0, 1), w.get_subaddress(0, 2))
    ]

    assert len(to) == 6

    amounts = list(range(1, len(to) + 1))

    store_fee = StoreFee()

    recipient_addrs = []

    def store_addr(val):
        nonlocal recipient_addrs
        recipient_addrs.append(val)

    recipient_amounts = []

    def store_amount(_, m):
        nonlocal recipient_addrs
        recipient_amounts.append(m[1][1])

    recipient_expected = [(addr, f"{amt}.0") for addr, amt in zip(to, amounts)]

    hal.timeout = 180  # creating this tx with the ledger takes ages
    run_with_interactions(
        ledger,
        partial(hal.multi_transfer, to, [coins(a) for a in amounts]),
        ExactScreen(["Processing TX"]),
        MatchScreen([r"^Confirm Fee$", r"^(0\.\d{1,9})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        *(
            cmds
            for i in range(len(recipient_expected))
            for cmds in [
                MatchScreen([r"^Confirm Amount$", r"^(\d+\.\d+)$"], store_amount, fail_index=1),
                Do.right,
                MatchMulti("Recipient", None, callback=store_addr),
                Do.right,
                ExactScreen(["Accept"]),
                Do.both,
            ]
        ),
        ExactScreen(["Processing TX"]),
        timeout=180,
    )

    assert 0.03 < store_fee.fee < 1

    recipient_expected.sort()

    recipient_got = sorted(zip(recipient_addrs, recipient_amounts))

    assert recipient_expected == recipient_got

    vprint("recipients look good, checking final balances")

    net.mine()
    assert alice.balances(refresh=True) == coins(6, 6)
    assert bob.balances(refresh=True) == coins(15, 15)
    assert hal.balances(refresh=True) == balance(100 - sum(amounts) - store_fee.fee)


def check_sn_rewards(net, hal, sn, starting_bal, reward):
    net.mine(5)  # 5 blocks until it starts earning rewards (testnet/fakenet)

    hal_bal = hal.balances(refresh=True)

    batch_offset = None
    assert hal_bal == coins(starting_bal, 0)
    # We don't know where our batch payment occurs yet, but let's look for it:
    for i in range(20):
        net.mine(1)
        if hal.balances(refresh=True)[0] > coins(starting_bal):
            batch_offset = sn.height() % 20
            break

    assert batch_offset is not None

    hal_bal = hal.balances()

    net.mine(19)
    assert hal.balances(refresh=True)[0] == hal_bal[0]
    net.mine(1)  # Should be our batch height
    assert hal.balances(refresh=True)[0] == hal_bal[0] + coins(20 * reward)


def test_sn_register(net, mike, hal, ledger, sn):
    mike.transfer(hal, coins(101))
    net.mine()

    assert hal.balances(refresh=True) == coins(101, 101)

    store_fee = StoreFee()

    run_with_interactions(
        ledger,
        partial(hal.register_sn, sn),
        ExactScreen(["Processing Stake"]),
        MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Confirm Stake", "100.0"], fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.left,
        Do.both,
        ExactScreen(["Processing Stake"]),
    )

    # We are half the SN network, so get half of the block reward per block:
    reward = 0.5 * 16.5
    check_sn_rewards(net, hal, sn, 101 - store_fee.fee, reward)


def test_sn_stake(net, mike, alice, hal, ledger, sn):
    mike.multi_transfer([hal, alice], coins(13.02, 87.02))
    net.mine()

    assert hal.balances(refresh=True) == coins(13.02, 13.02)
    assert alice.balances(refresh=True) == coins(87.02, 87.02)

    alice.register_sn(sn, stake=coins(87))
    net.mine(1)

    store_fee = StoreFee()

    run_with_interactions(
        ledger,
        partial(hal.stake_sn, sn, coins(13)),
        ExactScreen(["Processing Stake"]),
        MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], store_fee, fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Confirm Stake", "13.0"], fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.left,
        Do.both,
        ExactScreen(["Processing Stake"]),
    )

    # Our SN is 1 or 2 registered, so we get 50% of the 16.5 reward, 10% is removed for operator
    # fee, then hal gets 13/100 of the rest:
    reward = 0.5 * 16.5 * 0.9 * 0.13

    check_sn_rewards(net, hal, sn, 13 - store_fee.fee, reward)


def test_sn_reject(net, mike, hal, ledger, sn):
    mike.transfer(hal, coins(101))
    net.mine()

    assert hal.balances(refresh=True) == coins(101, 101)

    store_fee = StoreFee()

    with pytest.raises(RuntimeError, match=r"Fee denied on device\.$"):
        run_with_interactions(
            ledger,
            partial(hal.register_sn, sn),
            ExactScreen(["Processing Stake"]),
            MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], store_fee, fail_index=1),
            Do.right,
            Do.right,
            ExactScreen(["Reject"]),
            Do.both,
        )

    with pytest.raises(RuntimeError, match=r"Transaction denied on device\.$"):
        run_with_interactions(
            ledger,
            partial(hal.register_sn, sn),
            ExactScreen(["Processing Stake"]),
            MatchScreen([r"^Confirm Fee$", r"^(0\.01\d{1,7})$"], store_fee, fail_index=1),
            Do.right,
            ExactScreen(["Accept"]),
            Do.both,
            ExactScreen(["Confirm Stake", "100.0"], fail_index=1),
            Do.right,
            ExactScreen(["Accept"]),
            Do.right,
            ExactScreen(["Reject"]),
            Do.both,
        )


def test_sn_unstake(net, mike, hal, ledger, sn):
    # Do the full registration:
    test_sn_register(net, mike, hal, ledger, sn)

    run_with_interactions(
        ledger,
        partial(hal.unstake_sn, sn),
        ExactScreen(["Confirm Service", "Node Unlock"]),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.left,
        Do.both,
    )
    # A fakechain unlock takes 30 blocks, plus add another 20 just so we are sure we've received the
    # last batch reward:
    net.mine(30 + 20)

    hal_bal = hal.balances(refresh=True)
    net.mine(20)
    assert hal.balances(refresh=True) == hal_bal
