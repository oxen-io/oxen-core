import pytest
from functools import partial

from utils import *
from expected import *
import daemons


ONS_BASE_FEE = 7


def test_ons_buy(net, mike, hal, ledger):
    mike.transfer(hal, coins(10))
    net.mine()
    assert hal.balances(refresh=True) == coins(10, 10)

    store_fee = [StoreFee() for _ in range(3)]

    run_with_interactions(
        ledger,
        partial(
            hal.buy_ons,
            "session",
            "testsession",
            "05ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            backup_owner="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee[0], fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.right,
        ExactScreen(["Reject"]),
        Do.left,
        Do.both,
        ExactScreen(["Processing ONS"]),
    )

    mike.transfer(hal, coins(10))
    net.mine()
    assert hal.balances(refresh=True) == balance(20 - store_fee[0].fee)

    run_with_interactions(
        ledger,
        partial(hal.buy_ons, "wallet", "testwallet", mike.address()),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee[1], fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )

    mike.transfer(hal, coins(50))
    net.mine()
    assert hal.balances(refresh=True) == balance(70 - store_fee[0].fee - store_fee[1].fee)

    run_with_interactions(
        ledger,
        partial(
            hal.buy_ons,
            "lokinet_10y",
            "test.loki",
            "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
        ),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({6*ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee[2], fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )

    net.mine()
    assert hal.balances(refresh=True) == balance(70 - sum(s.fee for s in store_fee))

    assert hal.get_ons() == [
        {
            "type": "lokinet",
            "name": "test.loki",
            "hashed": "onTp6G7+2UEwBMEPjK149gY5phWt6SbhgkQYD5DBMXU=",
            "value": "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
            "owner": hal.address(),
        },
        {
            "type": "session",
            "name": "testsession",
            "hashed": "IcWqJAa2t5u4WMgDu6c6O1GvbI80r/GLUCVBZ8P/UlQ=",
            "value": "05ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "owner": hal.address(),
            "backup_owner": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        },
        {
            "type": "wallet",
            "name": "testwallet",
            "hashed": "bFhh6FtiV16PT3twIllC8zyxU3E2sS0AilOkcv69WB8=",
            "value": mike.address(),
            "owner": hal.address(),
        },
    ]


def test_ons_update(net, mike, hal, ledger):
    mike.buy_ons(
        "session",
        "testsession",
        "05ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        backup_owner=hal.address(),
    )
    mike.buy_ons("wallet", "testwallet", mike.address(), backup_owner=hal.address())
    mike.transfer(hal, coins(ONS_BASE_FEE + 1))

    for _ in range(5):
        mike.refresh()
        mike.transfer(hal, coins(1))
        net.mine(3)
    net.mine(6)
    mike.buy_ons(
        "lokinet_10y",
        "test.loki",
        "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
        backup_owner=hal.address(),
    )
    net.mine(1)
    hal.refresh()

    run_with_interactions(
        ledger,
        partial(
            hal.buy_ons,
            "session",
            "another",
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ExactScreen(["Processing ONS"]),
        MatchScreen([r"^Confirm ONS Fee$", rf"^{ONS_BASE_FEE}\.\d{{1,9}}$"], fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )
    net.mine(1)

    # ONS has a bug where you can't *clear* a backup owner, nor can you set both owner and
    # backup_owner to yourself, so we stuff in this dummy backup_owner in lieu of being able to
    # clear it:
    no_backup = "0000000000000000000000000000000000000000000000000000000000000000"

    run_with_interactions(
        ledger,
        partial(
            hal.update_ons,
            "session",
            "testsession",
            value="05eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            owner=hal.address(),
            backup_owner=no_backup,
        ),
        ExactScreen(["Confirm Oxen", "Name Service TX"]),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
        MatchScreen([r"^Confirm ONS Fee$", r"^0\.\d{1,9}$"], fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )

    run_with_interactions(
        ledger,
        partial(
            hal.update_ons,
            "wallet",
            "testwallet",
            value=hal.address(),
            owner=hal.address(),
            backup_owner=no_backup,
        ),
        ExactScreen(["Confirm Oxen", "Name Service TX"]),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
        MatchScreen([r"^Confirm ONS Fee$", r"^0\.\d{1,9}$"], fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )

    run_with_interactions(
        ledger,
        partial(
            hal.update_ons,
            "lokinet",
            "test.loki",
            value="444444444444444444444444444444444444444444444444444o.loki",
        ),
        ExactScreen(["Confirm Oxen", "Name Service TX"]),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
        MatchScreen([r"^Confirm ONS Fee$", r"^0\.\d{1,9}$"], fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )

    run_with_interactions(
        ledger,
        partial(
            hal.update_ons,
            "session",
            "another",
            value="051234123412341234123412341234123412341234123412341234123412341234",
            backup_owner="2222333322223333222233332222333322223333222233332222333322223333",
        ),
        ExactScreen(["Confirm Oxen", "Name Service TX"]),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
        MatchScreen([r"^Confirm ONS Fee$", r"^0\.\d{1,9}$"], fail_index=1),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )
    net.mine(1)
    hal.refresh()

    assert hal.get_ons() == [
        {
            "type": "lokinet",
            "name": "test.loki",
            "hashed": "onTp6G7+2UEwBMEPjK149gY5phWt6SbhgkQYD5DBMXU=",
            "value": "444444444444444444444444444444444444444444444444444o.loki",
            "owner": mike.address(),
            "backup_owner": hal.address(),
        },
        {
            "type": "session",
            "name": "another",
            "hashed": "ZvuFxErXKyzGIPhiXjlxOLADdwaG/APS6AH+Qq4Bw0o=",
            "value": "051234123412341234123412341234123412341234123412341234123412341234",
            "owner": hal.address(),
            "backup_owner": "2222333322223333222233332222333322223333222233332222333322223333",
        },
        {
            "type": "session",
            "name": "testsession",
            "hashed": "IcWqJAa2t5u4WMgDu6c6O1GvbI80r/GLUCVBZ8P/UlQ=",
            "value": "05eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "owner": hal.address(),
        },
        {
            "type": "wallet",
            "name": "testwallet",
            "hashed": "bFhh6FtiV16PT3twIllC8zyxU3E2sS0AilOkcv69WB8=",
            "value": hal.address(),
            "owner": hal.address(),
        },
    ]


def test_ons_renew(net, mike, hal, ledger):
    for _ in range(5):
        mike.transfer(hal, coins(50))
        net.mine(1)
    net.mine(9)
    bal = 250
    assert hal.balances(refresh=True) == balance(bal)

    store_fee = StoreFee()

    run_with_interactions(
        ledger,
        partial(
            hal.buy_ons,
            "lokinet_2y",
            "test.loki",
            "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
        ),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({2*ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee, fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )

    bal -= store_fee.fee
    net.mine(1)
    reg_height = net.nodes[0].height() - 1
    # On regtest our 1/2/5/10-year expiries become 2/4/10/20 *blocks* for expiry testing purposes
    exp_height = reg_height + 4
    assert hal.get_ons(include_height=True) == [
        {
            "type": "lokinet",
            "name": "test.loki",
            "hashed": "onTp6G7+2UEwBMEPjK149gY5phWt6SbhgkQYD5DBMXU=",
            "value": "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
            "owner": hal.address(),
            "update_height": reg_height,
            "expiration_height": exp_height,
        }
    ]

    run_with_interactions(
        ledger,
        partial(hal.renew_ons, "lokinet_5y", "test.loki"),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({4*ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee, fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )
    bal -= store_fee.fee
    net.mine(1)
    hal.refresh()
    run_with_interactions(
        ledger,
        partial(hal.renew_ons, "lokinet", "test.loki"),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee, fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )
    bal -= store_fee.fee
    net.mine(2)

    assert hal.get_ons(include_height=True) == [
        {
            "type": "lokinet",
            "name": "test.loki",
            "hashed": "onTp6G7+2UEwBMEPjK149gY5phWt6SbhgkQYD5DBMXU=",
            "value": "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
            "owner": hal.address(),
            "update_height": reg_height + 2,
            "expiration_height": exp_height + 10 + 2,
        }
    ]

    run_with_interactions(
        ledger,
        partial(hal.renew_ons, "lokinet_10y", "test.loki"),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({6*ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee, fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
        ExactScreen(["Processing ONS"]),
    )
    net.mine(10)
    bal -= store_fee.fee
    assert hal.balances(refresh=True) == balance(bal)
    assert hal.get_ons(include_height=True) == [
        {
            "type": "lokinet",
            "name": "test.loki",
            "hashed": "onTp6G7+2UEwBMEPjK149gY5phWt6SbhgkQYD5DBMXU=",
            "value": "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
            "owner": hal.address(),
            "update_height": reg_height + 4,
            "expiration_height": exp_height + 10 + 2 + 20,
        }
    ]


def test_ons_reject(net, mike, hal, ledger):
    mike.transfer(hal, coins(100))
    net.mine(10)
    assert hal.balances(refresh=True) == balance(100)

    with pytest.raises(RuntimeError, match=r'.*Fee denied on device\.$'):
        run_with_interactions(
            ledger,
            partial(
                hal.buy_ons,
                "lokinet_10y",
                "test.loki",
                "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
            ),
            ExactScreen(["Processing ONS"]),
            MatchScreen([r"^Confirm ONS Fee$", rf"^({6*ONS_BASE_FEE}\.\d{{1,9}})$"], fail_index=1),
            Do.right,
            ExactScreen(["Accept"]),
            Do.right,
            ExactScreen(["Reject"]),
            Do.both,
        )

    store_fee = StoreFee()
    run_with_interactions(
        ledger,
        partial(
            hal.buy_ons,
            "lokinet_10y",
            "test.loki",
            "yoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyoyo.loki",
        ),
        ExactScreen(["Processing ONS"]),
        MatchScreen(
            [r"^Confirm ONS Fee$", rf"^({6*ONS_BASE_FEE}\.\d{{1,9}})$"], store_fee, fail_index=1
        ),
        Do.right,
        ExactScreen(["Accept"]),
        Do.both,
    )

    net.mine(10)
    hal.refresh()
    with pytest.raises(RuntimeError, match=r'.*Fee denied on device\.$'):
        run_with_interactions(
            ledger,
            partial(hal.renew_ons, "lokinet_5y", "test.loki"),
            ExactScreen(["Processing ONS"]),
            MatchScreen([r"^Confirm ONS Fee$", rf"^({4*ONS_BASE_FEE}\.\d{{1,9}})$"], fail_index=1),
            Do.right,
            ExactScreen(["Accept"]),
            Do.right,
            ExactScreen(["Reject"]),
            Do.both,
        )

    assert hal.balances(refresh=True) == balance(100 - store_fee.fee)
    net.mine(1)
    assert hal.balances(refresh=True) == balance(100 - store_fee.fee)
