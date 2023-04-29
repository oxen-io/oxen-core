#!/usr/bin/python3

import pytest
import os.path
import service_node_network


def pytest_addoption(parser):
    parser.addoption("--binary-dir", default="../../build/bin", action="store")


@pytest.fixture(scope="session")
def binary_dir(request):
    binpath = request.config.getoption("--binary-dir")
    for exe in ("oxend", "oxen-wallet-rpc"):
        b = f"{binpath}/{exe}"
        if not os.path.exists(b):
            raise FileNotFoundError(
                b,
                f"Required executable ({b}) not found; build the project, or specify an alternate build/bin dir with --binary-dir",
            )

    return binpath


@pytest.fixture
def net(pytestconfig, tmp_path, binary_dir):
    return service_node_network.sn_net(pytestconfig, tmp_path, binary_dir)


# Shortcuts for accessing the named wallets
@pytest.fixture
def alice(net):
    return net.alice


@pytest.fixture
def bob(net):
    return net.bob


@pytest.fixture
def mike(net):
    return net.mike


@pytest.fixture
def chuck(net):
    """
    `chuck` is the wallet of a potential attacker, with some extra add-ons.  The main `chuck` wallet
    is connected to one of the three network nodes (like alice or bob), and starts out empty.

    Chuck also has a second copy of the same wallet, `chuck.hidden`, which is connected to his own
    private node, `chuck.hidden.node`.  This node is connected to the network exclusively through a
    second node that Chuck runs, `chuck.bridge`.  This allows chuck to disconnect from the network
    by stopping the bridge node and reconnect by restarting it.  Note that the bridge and hidden
    nodes will not have received proofs (and so can't be used to submit blinks).
    """

    chuck = Wallet(
        node=net.nodes[0],
        name="Chuck",
        rpc_wallet=net.binpath + "/oxen-wallet-rpc",
        datadir=net.datadir,
    )
    chuck.ready(wallet="chuck")

    hidden_node = Daemon(oxend=net.binpath + "/oxend", datadir=net.datadir)
    bridge_node = Daemon(oxend=net.binpath + "/oxend", datadir=net.datadir)
    for x in (4, 7):
        bridge_node.add_peer(net.all_nodes[x])
    bridge_node.add_peer(hidden_node)
    hidden_node.add_peer(bridge_node)

    vprint(
        "Starting new chuck oxend bridge node with RPC on {}:{}".format(
            bridge_node.listen_ip, bridge_node.rpc_port
        )
    )
    bridge_node.start()
    bridge_node.wait_for_json_rpc("get_info")
    net.sync(extra_nodes=[bridge_node], extra_wallets=[chuck])

    vprint(
        "Starting new chuck oxend hidden node with RPC on {}:{}".format(
            hidden_node.listen_ip, hidden_node.rpc_port
        )
    )
    hidden_node.start()
    hidden_node.wait_for_json_rpc("get_info")
    net.sync(extra_nodes=[hidden_node, bridge_node], extra_wallets=[chuck])
    vprint("Done syncing chuck nodes")

    # RPC wallet doesn't provide a way to import from a key or mnemonic, so we have to stop the rpc
    # wallet then copy the underlying wallet file.
    chuck.refresh()
    chuck.stop()
    chuck.hidden = Wallet(
        node=hidden_node,
        name="Chuck (hidden)",
        rpc_wallet=net.binpath + "/oxen-wallet-rpc",
        datadir=net.datadir,
    )

    import shutil
    import os

    wallet_base = chuck.walletdir + "/chuck"
    assert os.path.exists(wallet_base)
    assert os.path.exists(wallet_base + ".keys")
    os.makedirs(chuck.hidden.walletdir, exist_ok=True)
    shutil.copy(wallet_base, chuck.hidden.walletdir + "/chuck2")
    shutil.copy(wallet_base + ".keys", chuck.hidden.walletdir + "/chuck2.keys")

    # Restart the regular wallet and the newly copied hidden wallet
    chuck.ready(wallet="chuck", existing=True)
    chuck.hidden.ready(wallet="chuck2", existing=True)
    chuck.refresh()
    chuck.hidden.refresh()

    assert chuck.address() == chuck.hidden.address()

    chuck.bridge = bridge_node
    return chuck


@pytest.fixture
def chuck_double_spend(net, alice, mike, chuck):
    """
    Importing this fixture (along with `chuck` itself!) extends the chuck setup to transfer 100
    coins to chuck, mine them to confirmation, then stop his bridge node to double-spend those
    funds.  This consists of a blink tx of 95 (sent to alice) on the connected network and a
    conflicting regular tx (sent to himself) submitted to the mempool of his local hidden (and now
    disconnected) node.

    The fixture value is a tuple of the submitted tx details as returned by the rpc wallet,
    `(blinked_tx, hidden_tx)`.
    """

    assert chuck.balances() == (0, 0)
    mike.transfer(chuck, coins(100))
    net.mine()
    net.sync(extra_nodes=[chuck.bridge, chuck.hidden.node], extra_wallets=[chuck, chuck.hidden])

    assert chuck.balances() == coins(100, 100)
    assert chuck.hidden.balances() == coins(100, 100)

    # Now we disconnect chuck's bridge node, which will isolate the hidden node.
    chuck.bridge.stop()

    tx_blink = chuck.transfer(alice, coins(95), priority=5)
    assert len(tx_blink["tx_hash_list"]) == 1
    blink_hash = tx_blink["tx_hash_list"][0]

    time.sleep(0.5)  # allow blink to propagate

    # ... but it shouldn't have propagated here because this is disconnected, so we can submit a
    # conflicting tx:
    tx_hidden = chuck.hidden.transfer(chuck, coins(95), priority=1)
    assert len(tx_hidden["tx_hash_list"]) == 1
    hidden_hash = tx_hidden["tx_hash_list"][0]
    assert hidden_hash != blink_hash

    vprint("double-spend txs: blink: {}, hidden: {}".format(blink_hash, hidden_hash))

    net.sync()
    alice.refresh()
    assert alice.balances() == coins(95, 0)

    mike_txpool = [
        x["id_hash"] for x in mike.node.rpc("/get_transaction_pool").json()["transactions"]
    ]
    assert mike_txpool == [blink_hash]

    hidden_txpool = [
        x["id_hash"] for x in chuck.hidden.node.rpc("/get_transaction_pool").json()["transactions"]
    ]
    assert hidden_txpool == [hidden_hash]

    return (tx_blink, tx_hidden)
