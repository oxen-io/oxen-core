import pytest
from functools import partial

from utils import *
from expected import *
import daemons


def test_receive(net, mike, hal):
    mike.transfer(hal, coins(100))
    net.mine(blocks=2)
    assert hal.balances(refresh=True) == coins(100, 0)
    net.mine(blocks=7)
    assert hal.balances(refresh=True) == coins(100, 0)
    net.mine(blocks=1)
    assert hal.balances(refresh=True) == coins(100, 100)


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

    recipient_expected = ledger.buggy_crap(
        [
            (alice.address(), "18.0"),
            (bob.address(), "19.0"),
            (alice.address(), "20.0"),
            (alice.address(), "21.0"),
            (hal.address(), "22.0"),
        ]
    )
    recipient_expected.sort()

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

    recipient_expected = ledger.buggy_crap([(addr, f"{amt}.0") for addr, amt in zip(to, amounts)])
    recipient_expected.sort()

    hal.timeout = 300  # creating this tx with the ledger takes ages
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

    recipient_got = sorted(zip(recipient_addrs, recipient_amounts))

    assert recipient_expected == recipient_got

    vprint("recipients look good, checking final balances")

    net.mine()
    assert alice.balances(refresh=True) == coins(6, 6)
    assert bob.balances(refresh=True) == coins(15, 15)
    assert hal.balances(refresh=True) == balance(100 - sum(amounts) - store_fee.fee)
