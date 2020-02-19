import pytest
import time

from service_node_network import coins, vprint

def test_init(net):
    """Tests that the service node test network got initialized properly.  (This isn't really a test
    so much as it is a verification that the test code is working as it is supposed to)."""

    # All nodes should be at the same height:
    heights = [x.rpc("/get_height").json()["height"] for x in net.all_nodes]
    assert heights == [max(heights)] * len(net.all_nodes)

    # All nodes should have sent proofs to each other
    active_sns = net.nodes[0].json_rpc("get_n_service_nodes", dict(
        fields=dict(quorumnet_port=True, pubkey_ed25519=True),
        active_only=True)
        ).json()['result']['service_node_states']
    assert len(net.sns) == sum(x['pubkey_ed25519'] != "" and x['quorumnet_port'] > 0 for x in active_sns)

    # We should have active blink quorums for the current height (minus blink quorum lag), and all
    # nodes should agree on them
    q_heights = [heights[0] - (heights[0] % 5) - 35]
    q_heights.append(q_heights[0] + 5)
    blink_quorums = [
            [
                q['quorum']['validators']
                for q in sn.json_rpc("get_quorum_state",
                    dict(quorum_type=2, start_height=q_heights[0], end_height=q_heights[1])).json()['result']['quorums']
                if 'quorum' in q and 'validators' in q['quorum']
            ]
            for sn in net.all_nodes
    ]
    assert len(blink_quorums) == len(net.all_nodes)                  # Got responses from every node
    assert blink_quorums == [blink_quorums[0]] * len(net.all_nodes)  # All nodes returned the same response
    assert len(blink_quorums[0]) == 2                                # Got both quorums
    assert tuple(len(q) for q in blink_quorums[0]) == (10, 10)       # Both quorum responses have full blink quorums
    # We should also get different quorums.  (Technically it is possible that the two quorums are
    # identical, but the probability of getting *exactly* the same quorum in the same order with 20
    # SN network is 1/(20*19*18*...*11) = 1.491552e-12):
    assert blink_quorums[0][0] != blink_quorums[0][1]


def diff(b1, b2):
    return tuple(y - x for x, y in zip(b1, b2))


def test_basic_blink(net, alice, bob, mike):
    """Tests sending a basic blink (alongside a non-blink tx) and verifies the it is accepted and
    received as expected."""

    a1 = alice.balances()
    mike.transfer(alice, coins(100))
    net.mine(5, sync=True)
    a2 = alice.balances()
    assert diff(a1, a2) == coins(100, 0)
    net.mine(5, sync=True)
    a2 = alice.balances()
    assert diff(a1, a2) == coins(100, 100)

    b1 = bob.balances()

    sent_blink = alice.transfer(bob, coins(10), priority=5)
    assert sent_blink['amount_list'] == [coins(10)]
    assert len(sent_blink['tx_hash_list']) == 1

    sent_normal = mike.transfer(bob, coins(3), priority=1)
    assert sent_normal['amount_list'] == [coins(3)]
    assert len(sent_normal['tx_hash_list']) == 1

    time.sleep(0.5)  # Should be more than enough time to propagate between 24 localhost nodes
    bob.refresh()

    recv_blink, recv_normal = bob.find_transfers(x['tx_hash_list'][0] for x in (sent_blink, sent_normal))
    assert recv_blink is not None
    assert recv_normal is not None

    exp_blink  = {'type': 'in',   'address': bob.address(), 'amount': coins(10), 'blink_mempool': True,  'was_blink': True}
    exp_normal = {'type': 'pool', 'address': bob.address(), 'amount': coins(3),  'blink_mempool': False, 'was_blink': False}
    assert exp_blink.items() <= recv_blink.items()
    assert exp_normal.items() <= recv_normal.items()
    assert diff(b1, bob.balances()) == coins(10, 0)  # Blink balance shows up now, mempool after being mined.

    net.mine(1, sync=True)

    assert diff(b1, bob.balances()) == coins(13, 0)
    recv_blink, recv_normal = bob.find_transfers(x['tx_hash_list'][0] for x in (sent_blink, sent_normal))
    exp_blink['blink_mempool'] = False
    assert exp_blink.items() <= recv_blink.items()
    exp_normal['type'] = 'in'
    assert exp_normal.items() <= recv_normal.items()

    net.mine(8, sync=True)

    assert diff(b1, bob.balances()) == coins(13, 0)
    recv_blink, recv_normal = bob.find_transfers(x['tx_hash_list'][0] for x in (sent_blink, sent_normal))
    assert exp_blink.items() <= recv_blink.items()
    assert exp_normal.items() <= recv_normal.items()

    net.mine(1, sync=True)

    assert diff(b1, bob.balances()) == coins(13, 13)
    recv_blink, recv_normal = bob.find_transfers(x['tx_hash_list'][0] for x in (sent_blink, sent_normal))
    assert exp_blink.items() <= recv_blink.items()
    assert exp_normal.items() <= recv_normal.items()


def test_blink_sweep(net, mike, alice, bob):
    """Similar to the above, but tests blinking a sweep_all"""

    assert alice.balances() == (0, 0)
    assert bob.balances() == (0, 0)

    # Prepare two sweeps: one small one of just a few inputs that goes from bob -> alice, and one
    # huge one that requires multiple txes that alice blinks to bob.
    #
    # We want to pile in enough transfers that alice has to submit multiple txes to sweep to bob:
    # Normal tx limit is 100kB, and we hit that limit at around 130 inputs, so we'll send 150 to
    # alice.
    transfers = [[{"address": alice.address(), "amount": coins(1)}] * 15] * 10
    transfers.append([{"address": bob.address(), "amount": coins(3)}] * 3)
    for t in transfers:
        r = mike.json_rpc("transfer_split", {"destinations": t, "priority": 0}).json()
        if 'error' in r:
            raise TransferFailed("Transfer failed: {}".format(r['error']['message']), r)

    # Confirm the transfers
    net.mine(sync=True)
    assert alice.balances() == coins(150, 150)
    assert bob.balances() == coins(9, 9)

    sweep_a = bob.transfer(alice, sweep=True, priority=5)
    assert len(sweep_a['amount_list']) == 1
    amount_a = sweep_a['amount_list'][0]
    assert amount_a == coins(9) - sweep_a['fee_list'][0]
    assert bob.balances() == (0, 0)

    time.sleep(0.5)
    alice.refresh()
    assert alice.balances() == (coins(150) + amount_a, coins(150))

    sweep_b = alice.transfer(bob, sweep=True, priority=5)
    assert len(sweep_b['amount_list']) > 1
    amount_b = sum(sweep_b['amount_list'])
    assert amount_b == coins(150) - sum(sweep_b['fee_list'])
    assert alice.balances() == (amount_a, 0)

    time.sleep(0.5)
    bob.refresh()
    assert bob.balances() == (amount_b, 0)
    net.mine(sync=True)
    assert alice.balances() == (amount_a, amount_a)
    assert bob.balances() == (amount_b, amount_b)


def test_blink_fail_mempool(net, mike, alice, bob):
    """This test does a regular transfer then attempts to blink the same funds via a local node with
    a flushed txpool; the blink should get rejected by the quorum."""

    assert alice.balances() == (0, 0)
    assert bob.balances() == (0, 0)
    mike.transfer(alice, coins(40))
    net.mine(sync=True)
    assert alice.balances() == coins(40, 40)

    alice.transfer(bob, coins(25))
    time.sleep(0.5)  # Allow propagation to network
    assert alice.node.json_rpc("flush_txpool").json()['result']['status'] == 'OK'
    assert 'result' in alice.json_rpc("rescan_spent").json()
    # A non-blink should go through, since it only validates on the local node, and we just clear
    # its mempool:
    alice.transfer(bob, coins(7))

    # Clear it again, then try a blink:
    assert alice.node.json_rpc("flush_txpool").json()['result']['status'] == 'OK'
    assert 'result' in alice.json_rpc("rescan_spent").json()

    from daemons import TransferFailed
    with pytest.raises(TransferFailed, match='rejected by quorum') as exc_info:
        double_spend = alice.transfer(bob, coins(5), priority=5)  # Has to spend the same input, since we only have one input


def test_blink_replacement(net, mike, alice, chuck, chuck_double_spend):
    """Tests that a conflicting non-blink tx on a node gets replaced by the arrival of a
    blink tx that conflicts with it.

    We do this by setting up a network like this:

    [[REGULAR NETWORK NODES]]
            |   |
     [chuck's bridge node]
              |
     [chuck's hidden node]

    and then we shut down the bridge node, to leave us with a disconnected network (the hidden node
    *only* connects to the bridge node):

    [REGULAR NETWORK NODES]

     [chuck's hidden node]

    We then submit, from two copies of the same wallet, a double spend: a blink on the regular
    network and a non-blink on the hidden node.  The regular network accepts the blink, and the
    hidden node accepts the non-blink into its mempool.

    The bridge node then gets restarted, reconnecting to the regular network nodes and the hidden
    node.  Once it has synced to the main network, and the hidden node has synced with it, we should
    end up with the hidden tx deleted from the hidden node, and also not present on the bridge node
    (it may or may not exist momentarily on the bridge node, depending on the sync order, but if it
    does, it also gets deleted by the blink arrival).
    """

    blink_hash, hidden_hash = (x['tx_hash_list'][0] for x in chuck_double_spend)

    # Current state:
    # - all the regular network nodes have the blink tx
    # - mike's hidden node has the conflict tx
    # - mike's bridge node is offline
    #
    # We're going to bring mike's bridge node back online, wait for things to resync, then make sure
    # that the hidden tx is gone from everywhere and just the blink remains.

    vprint("Restarting bridge node")
    chuck.bridge.ready()

    give_up = time.time() + 10
    vprint("Waiting for bridge node to sync")
    while time.time() < give_up:
        info = chuck.bridge.rpc("/get_info").json()
        conns = info['outgoing_connections_count'] + info['incoming_connections_count']
        vprint("bridge node has {} ({}out+{}in) p2p connections".format(conns, info['outgoing_connections_count'], info['incoming_connections_count']))

        # We can have 2 connections (one in, one out) with the hidden node, and connect to 2 other
        # peers so we should have no problem getting to 4.
        if conns > 3:  # Check this *after* sleeping so that we give half a second after connecting for sync
            give_up = None
            break
        time.sleep(.5)
    assert give_up is None, "Gave up waiting for bridge node to sync"

    chuck.bridge.p2p_resync()
    time.sleep(1)  # Allow syncing with main network to finish.

    # Force the hidden node to resync with the bridge node (normally nodes do this with all their
    # peers every 60s, but we're impatient).
    chuck.hidden.node.p2p_resync()
    time.sleep(1)

    assert chuck.bridge.txpool_hashes() == [blink_hash]
    assert chuck.hidden.node.txpool_hashes() == [blink_hash]
    assert alice.node.txpool_hashes() == [blink_hash]


@pytest.mark.parametrize('rollback_size', (1, 5))
def test_blink_rollback(net, mike, alice, chuck, chuck_double_spend, rollback_size):
    """Tests that a mined, conflicting non-blink tx on a node gets rolled back by the arrival of a
    blink tx that conflicts with it.

    This is very similar to the above (replacement) scenario, except that in addition to the hidden
    tx going into the hidden node, it also gets mined into some blocks on that hidden node.  Upon
    network reconnection, then, the expected result is that the hidden node has rolled back to the
    height of the rest of the network, and the rest of the network didn't accepted the blocks in the
    first place.
    """

    blink_hash, hidden_hash = (x['tx_hash_list'][0] for x in chuck_double_spend)

    # Current state: (see previous test, this starts out the same)

    net.mine(rollback_size, chuck.hidden)

    time.sleep(1) # We should be disconnected with no propagation, but let's make sure.

    orig_alice_height = alice.node.height()
    assert chuck.hidden.node.height() == orig_alice_height + rollback_size

    vprint("Restarting bridge node")
    chuck.bridge.ready()

    give_up = time.time() + 20
    vprint("Waiting for bridge node to sync")
    while time.time() < give_up:
        info = chuck.bridge.rpc("/get_info").json()
        conns = info['outgoing_connections_count'] + info['incoming_connections_count']
        vprint("bridge node has {} ({}out+{}in) p2p connections".format(conns, info['outgoing_connections_count'], info['incoming_connections_count']))

        # We can have 2 connections (one in, one out) with the hidden node, and connect to 2 other
        # peers so we should have no problem getting to 4.
        if conns > 3:  # Check this *after* sleeping so that we give half a second after connecting for sync
            give_up = None
            break
        time.sleep(.5)
    assert give_up is None, "Gave up waiting for bridge node to sync"

    expiry = time.time() + 10
    while time.time() < expiry:
        ch, ah = chuck.bridge.height(), alice.node.height()
        if ch != ah:
            vprint("Waiting for chuck bridge ({}) to reach expected height ({})".format(ch, ah))
            chuck.bridge.p2p_resync()
            time.sleep(.5)

    assert chuck.bridge.height() == alice.node.height()

    # Now force the hidden node to resync with the bridge node (normally nodes do this with all their
    # peers every 60s, but we're impatient).  This *should* trigger a rollback since the hidden node
    # has the conflicting block and will get the blink from the bridge node.
    chuck.hidden.node.p2p_resync()
    time.sleep(1)

    expiry = time.time() + 10
    while time.time() < expiry:
        heights = [x.height() for x in net.all_nodes + [chuck.hidden.node, chuck.bridge]]
        hmin, hmax = min(heights), max(heights)
        if hmin == hmax:
            expiry = None
            break
        else:
            vprint("Waiting for consensus, current height range: [{}, {}], bridge: {}, hidden: {}".format(hmin, hmax, chuck.bridge.height(), chuck.hidden.node.height()))
            time.sleep(.5)

    assert expiry is None, "Time expired waiting for all nodes to get to the same height"

    assert alice.node.height() == orig_alice_height
    assert [x.height() for x in net.all_nodes] == [orig_alice_height for _ in net.all_nodes]
    assert chuck.bridge.height() == orig_alice_height
    assert chuck.hidden.node.height() == orig_alice_height

    assert chuck.bridge.txpool_hashes() == [blink_hash]
    assert chuck.hidden.node.txpool_hashes() == [blink_hash]
    assert alice.node.txpool_hashes() == [blink_hash]
    assert [x.txpool_hashes() for x in net.all_nodes] == [[blink_hash] for _ in net.all_nodes]
