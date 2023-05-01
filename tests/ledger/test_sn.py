import pytest
from functools import partial

from utils import *
from expected import *


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
