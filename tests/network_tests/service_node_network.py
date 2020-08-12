# Provides a pytest fixture of a configured service node network with 20 service nodes, 3 regular
# nodes, and 3 wallets (each connected to a different node).
#
# The 20 service nodes are registered, have mined enough to make the blink quorum active, and have
# sent uptime proofs to each other.
#
# The 3 nodes are ordinary, non-service node nodes.
#
# The 3 wallets are named alice, bob, and mike.
# - "mike the miner" is the miner and operator of the service nodes and so has an endlessly
#   increasing supply of coins as blocks are mined.
# - alice and bob will have any existing funds transferred to mike but may still have tx history of
# previous tests.  (The wallet-emptying sweep to mike, however, may not yet be confirmed).
#
# A fourth malicious wallet is available by importing the fixture `chuck`, which generates new
# wallets and nodes each time (see the fixture for details).


from daemons import Daemon, Wallet
import random
import time
from datetime import datetime
import uuid

import pytest

def coins(*args):
    if len(args) != 1:
        return tuple(coins(x) for x in args)
    x = args[0]
    if type(x) in (tuple, list):
        return type(x)(coins(i) for i in x)
    return round(x * 1000000000)


def wait_for(callback, timeout=10):
    expires = time.time() + timeout
    while True:
        try:
            if callback():
                return
        except:
            pass
        if time.time() >= expires:
            raise RuntimeError("task timeout expired")
        time.sleep(.25)


verbose = False
def vprint(*args, timestamp=True, **kwargs):
    global verbose
    if verbose:
        if timestamp:
            print(datetime.now(), end=" ")
        print(*args, **kwargs)

'''
sleep a few seconds, then call code that calls snn.mine
'''

class SNNetwork:
    def __init__(self, datadir, *, binpath='../../build/bin', sns=20, nodes=3):
        self.datadir = datadir
        self.binpath = binpath

        vprint("Using '{}' for data files and logs".format(datadir))

        nodeopts = dict(lokid=self.binpath+'/lokid', datadir=datadir)

        self.sns = [Daemon(service_node=True, **nodeopts) for _ in range(sns)]
        self.nodes = [Daemon(**nodeopts) for _ in range(nodes)]

        self.all_nodes = self.sns + self.nodes

        self.wallets = []
        for name in ('Alice', 'Bob', 'Mike'):
            self.wallets.append(Wallet(
                node=self.nodes[len(self.wallets) % len(self.nodes)],
                name=name,
                rpc_wallet=self.binpath+'/loki-wallet-rpc',
                datadir=datadir))

        self.alice, self.bob, self.mike = self.wallets

        # Interconnections
        for i in range(len(self.all_nodes)):
            for j in (2, 3, 5, 7, 11):
                k = (i + j) % len(self.all_nodes)
                if i != k:
                    self.all_nodes[i].add_peer(self.all_nodes[k])

        vprint("Starting new lokid service nodes with RPC on {} ports".format(self.sns[0].listen_ip), end="")
        for sn in self.sns:
            vprint(" {}".format(sn.rpc_port), end="", flush=True, timestamp=False)
            sn.start()
        vprint(timestamp=False)
        vprint("Starting new regular lokid nodes with RPC on {} ports".format(self.nodes[0].listen_ip), end="")
        for d in self.nodes:
            vprint(" {}".format(d.rpc_port), end="", flush=True, timestamp=False)
            d.start()
        vprint(timestamp=False)

        vprint("Waiting for all lokid's to get ready")
        for d in self.all_nodes:
            d.wait_for_json_rpc("get_info")

        vprint("Lokids are ready. Starting wallets")

        for w in self.wallets:
            vprint("Starting new RPC wallet {w.name} at {w.listen_ip}:{w.rpc_port}".format(w=w))
            w.start()
        for w in self.wallets:
            w.ready()
            w.refresh()
            vprint("Wallet {w.name} is ready: {a}".format(w=w, a=w.address()))

        for w in self.wallets:
            w.wait_for_json_rpc("refresh")

        # Mine some blocks; we need 100 per SN registration, and we can nearly 600 on fakenet before
        # it hits HF16 and kills mining rewards.  This lets us submit the first 5 SN registrations a
        # SN (at height 40, which is the earliest we can submit them without getting an occasional
        # spurious "Not enough outputs to use" error).
        # to unlock and the rest to have enough unlocked outputs for mixins), then more some more to
        # earn SN rewards.  We need 100 per SN registration, and each mined block gives us an input
        # of 18.9, which means each registration requires 6 inputs.  Thus we need a bare minimum of
        # 6(N-5) blocks, plus the 30 lock time on coinbase TXes = 6N more blocks (after the initial
        # 5 registrations).
        self.mine(50)
        vprint("Submitting first round of service node registrations: ", end="", flush=True)
        for sn in self.sns[0:5]:
            self.mike.register_sn(sn)
            vprint(".", end="", flush=True, timestamp=False)
        vprint(timestamp=False)
        if len(self.sns) > 5:
            vprint("Going back to mining", flush=True)

            self.mine(6*len(self.sns))

            vprint("Submitting more service node registrations: ", end="", flush=True)
            for sn in self.sns[5:]:
                self.mike.register_sn(sn)
                vprint(".", end="", flush=True, timestamp=False)
            vprint(timestamp=False)
            vprint("Done.")

        self.print_wallet_balances()

        vprint("Mining 40 blocks (registrations + blink quorum lag) and waiting for nodes to sync")
        self.sync_nodes(self.mine(40))

        self.print_wallet_balances()

        vprint("Sending fake lokinet/ss pings")
        for sn in self.sns:
            sn.ping()

        all_service_nodes_proofed = lambda sn: all(x['quorumnet_port'] > 0 for x in
                sn.json_rpc("get_n_service_nodes", {"fields":{"quorumnet_port":True}}).json()['result']['service_node_states'])

        vprint("Waiting for proofs to propagate: ", end="", flush=True)
        for sn in self.sns:
            wait_for(lambda: all_service_nodes_proofed(sn), timeout=120)
            vprint(".", end="", flush=True, timestamp=False)
        vprint(timestamp=False)
        vprint("Done.")

        vprint("Fake SN network setup complete!")


    def refresh_wallets(self, *, extra=[]):
        vprint("Refreshing wallets")
        for w in self.wallets + extra:
            w.refresh()
        vprint("All wallets refreshed")


    def mine(self, blocks=None, wallet=None, *, sync=False):
        """Mine some blocks to the given wallet (or self.mike if None) on the wallet's daemon.
        Returns the daemon's height after mining the blocks.  If blocks is omitted, mines enough to
        confirm regular transfers (i.e. 10 blocks).  If sync is specified, sync all nodes and then
        refresh all wallets after mining."""
        if wallet is None:
            wallet = self.mike
        if blocks is None:
            blocks = 10
        node = wallet.node
        vprint("Mining {} blocks to wallet {.name}".format(blocks, wallet))
        start_height = node.height()
        end_height = start_height + blocks
        node.mine_blocks(blocks, wallet)
        while node.rpc("/mining_status").json()["active"]:
            height = node.height()
            vprint("Mined {}/{}".format(height, end_height))
            time.sleep(0.05 if height >= end_height else 0.25)
        height = node.height()
        vprint("Mined {}/{}".format(height, end_height))

        if sync:
            self.sync_nodes(height)
            self.refresh_wallets()

        return height


    def sync_nodes(self, height=None, *, extra=[], timeout=10):
        """Waits for all nodes to reach the given height, typically invoked after mine()"""
        nodes = self.all_nodes + extra
        heights = [x.height() for x in nodes]
        if height is None:
            height = max(heights)
        if min(heights) >= height:
            vprint("All nodes already synced to height >= {}".format(height))
            return
        vprint("Waiting for all nodes to sync to height {}".format(height))
        last = None
        expiry = time.time() + timeout
        while nodes and time.time() < expiry:
            if heights[-1] < height:
                heights[-1] = nodes[-1].height()
            if heights[-1] >= height:
                heights.pop()
                nodes.pop()
                last = None
                continue
            if heights[-1] != last:
                vprint("waiting for {} [{} -> {}]".format(nodes[-1].name, heights[-1], height))
                last = heights[-1]
            time.sleep(0.1)
        if nodes:
            raise RuntimeError("Timed out waiting for node syncing")
        vprint("All nodes synced to height {}".format(height))


    def sync(self, extra_nodes=[], extra_wallets=[]):
        """Synchronizes everything: waits for all nodes to sync, then refreshes all wallets.  Can be
        given external wallets/nodes to sync."""
        self.sync_nodes(extra=extra_nodes)
        self.refresh_wallets(extra=extra_wallets)


    def print_wallet_balances(self):
        """Instructs the wallets to refresh and prints their balances (does nothing in non-verbose mode)"""
        global verbose
        if not verbose:
            return
        vprint("Balances:")
        for w in self.wallets:
            b = w.balances(refresh=True)
            vprint("    {:5s}: {:.9f} (total) with {:.9f} (unlocked)".format(
                w.name, b[0] * 1e-9, b[1] * 1e-9))


    def __del__(self):
        for n in self.all_nodes:
            n.terminate()
        for w in self.wallets:
            w.terminate()

snn = None

@pytest.fixture
def net(pytestconfig, tmp_path, binary_dir):
    """Fixture that returns the service node network.  It is persistent across tests: the first time
    it loads it starts the daemons and wallets, mines a bunch of blocks and submits SN
    registrations.  On subsequent loads it mines 5 blocks so that mike always has some available
    funds, and sets alice and bob to new wallets."""
    global snn, verbose
    if not snn:
        verbose = pytestconfig.getoption('verbose') >= 2
        if verbose:
            print("\nConstructing initial service node network")
        snn = SNNetwork(datadir=tmp_path, binpath=binary_dir)
    else:
        snn.alice.new_wallet()
        snn.bob.new_wallet()

        # Flush pools because some tests leave behind impossible txes
        for n in snn.all_nodes:
            assert n.json_rpc("flush_txpool").json()['result']['status'] == 'OK'

        # Mine a few to clear out anything in the mempool that can be cleared
        snn.mine(5, sync=True)

        vprint("Alice has new wallet: {}".format(snn.alice.address()))
        vprint("Bob   has new wallet: {}".format(snn.bob.address()))

    return snn


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

    chuck = Wallet(node=net.nodes[0], name='Chuck', rpc_wallet=net.binpath+'/loki-wallet-rpc', datadir=net.datadir)
    chuck.ready(wallet="chuck")

    hidden_node = Daemon(lokid=net.binpath+'/lokid', datadir=net.datadir)
    bridge_node = Daemon(lokid=net.binpath+'/lokid', datadir=net.datadir)
    for x in (4, 7):
        bridge_node.add_peer(net.all_nodes[x])
    bridge_node.add_peer(hidden_node)
    hidden_node.add_peer(bridge_node)

    vprint("Starting new chuck lokid bridge node with RPC on {}:{}".format(bridge_node.listen_ip, bridge_node.rpc_port))
    bridge_node.start()
    bridge_node.wait_for_json_rpc("get_info")
    net.sync(extra_nodes=[bridge_node], extra_wallets=[chuck])

    vprint("Starting new chuck lokid hidden node with RPC on {}:{}".format(hidden_node.listen_ip, hidden_node.rpc_port))
    hidden_node.start()
    hidden_node.wait_for_json_rpc("get_info")
    net.sync(extra_nodes=[hidden_node, bridge_node], extra_wallets=[chuck])
    vprint("Done syncing chuck nodes")

    # RPC wallet doesn't provide a way to import from a key or mnemonic, so we have to stop the rpc
    # wallet then copy the underlying wallet file.
    chuck.refresh()
    chuck.stop()
    chuck.hidden = Wallet(node=hidden_node, name='Chuck (hidden)', rpc_wallet=net.binpath+'/loki-wallet-rpc', datadir=net.datadir)

    import shutil
    import os
    wallet_base = chuck.walletdir + '/chuck'
    assert os.path.exists(wallet_base)
    assert os.path.exists(wallet_base + '.keys')
    os.makedirs(chuck.hidden.walletdir, exist_ok=True)
    shutil.copy(wallet_base, chuck.hidden.walletdir + '/chuck2')
    shutil.copy(wallet_base + '.keys', chuck.hidden.walletdir + '/chuck2.keys')

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

    assert(chuck.balances() == (0, 0))
    mike.transfer(chuck, coins(100))
    net.mine()
    net.sync(extra_nodes=[chuck.bridge, chuck.hidden.node], extra_wallets=[chuck, chuck.hidden])

    assert chuck.balances() == coins(100, 100)
    assert chuck.hidden.balances() == coins(100, 100)

    # Now we disconnect chuck's bridge node, which will isolate the hidden node.
    chuck.bridge.stop()

    tx_blink = chuck.transfer(alice, coins(95), priority=5)
    assert len(tx_blink['tx_hash_list']) == 1
    blink_hash = tx_blink['tx_hash_list'][0]

    time.sleep(0.5)  # allow blink to propagate

    # ... but it shouldn't have propagated here because this is disconnected, so we can submit a
    # conflicting tx:
    tx_hidden = chuck.hidden.transfer(chuck, coins(95), priority=1)
    assert len(tx_hidden['tx_hash_list']) == 1
    hidden_hash = tx_hidden['tx_hash_list'][0]
    assert hidden_hash != blink_hash

    vprint("double-spend txs: blink: {}, hidden: {}".format(blink_hash, hidden_hash))

    net.sync()
    alice.refresh()
    assert alice.balances() == coins(95, 0)

    mike_txpool = [x['id_hash'] for x in mike.node.rpc("/get_transaction_pool").json()['transactions']]
    assert mike_txpool == [blink_hash]

    hidden_txpool = [x['id_hash'] for x in chuck.hidden.node.rpc("/get_transaction_pool").json()['transactions']]
    assert hidden_txpool == [hidden_hash]

    return (tx_blink, tx_hidden)
