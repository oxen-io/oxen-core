# Provides a configured service node network with 20 service nodes, 3 regular nodes, and 3 wallets
# (each connected to a different node).
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

from daemons import Daemon, Wallet, coins
import vprint as v
from vprint import vprint
import random
import time
import uuid

import pytest


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
        time.sleep(0.25)


class SNNetwork:
    def __init__(self, datadir, *, binpath, sns=20, nodes=3, unstaked_sns=0):
        self.datadir = datadir
        self.binpath = binpath

        vprint("Using '{}' for data files and logs".format(datadir))

        nodeopts = dict(oxend=self.binpath + "/oxend", datadir=datadir)

        self.sns = [Daemon(service_node=True, **nodeopts) for _ in range(sns)]
        self.unstaked_sns = [Daemon(service_node=True, **nodeopts) for _ in range(unstaked_sns)]
        self.nodes = [Daemon(**nodeopts) for _ in range(nodes)]

        self.all_nodes = self.sns + self.unstaked_sns + self.nodes

        self.wallets = []
        for name in ("Alice", "Bob", "Mike"):
            self.wallets.append(
                Wallet(
                    node=self.nodes[len(self.wallets) % len(self.nodes)],
                    name=name,
                    rpc_wallet=self.binpath + "/oxen-wallet-rpc",
                    datadir=datadir,
                )
            )

        self.alice, self.bob, self.mike = self.wallets

        # Interconnections
        for i in range(len(self.all_nodes)):
            for j in (2, 3, 5, 7, 11):
                k = (i + j) % len(self.all_nodes)
                if i != k:
                    self.all_nodes[i].add_peer(self.all_nodes[k])

        vprint(
            "Starting new oxend service nodes with RPC on {} ports".format(self.sns[0].listen_ip),
            end="",
        )
        for sn in self.sns + self.unstaked_sns:
            vprint(" {}".format(sn.rpc_port), end="", flush=True, timestamp=False)
            sn.start()
        vprint(timestamp=False)
        vprint(
            "Starting new regular oxend nodes with RPC on {} ports".format(self.nodes[0].listen_ip),
            end="",
        )
        for d in self.nodes:
            vprint(" {}".format(d.rpc_port), end="", flush=True, timestamp=False)
            d.start()
        vprint(timestamp=False)

        vprint("Waiting for all oxend's to get ready")
        for d in self.all_nodes:
            d.wait_for_json_rpc("get_info")

        vprint("Oxends are ready. Starting wallets")

        for w in self.wallets:
            vprint("Starting new RPC wallet {w.name} at {w.listen_ip}:{w.rpc_port}".format(w=w))
            w.start()
        for w in self.wallets:
            w.ready()
            w.refresh()
            vprint("Wallet {w.name} is ready: {a}".format(w=w, a=w.address()))

        for w in self.wallets:
            w.wait_for_json_rpc("refresh")

        # Mine some blocks; we need 100 per SN registration, and we can mine ~473 on fakenet before
        # it hits HF16 and kills mining rewards.  This lets us submit the first 4 SN registrations
        # (at height 50, which is the earliest we can submit them without getting an occasional
        # spurious "Not enough outputs to use" error).
        # After this, we need more some more to earn SN rewards: 100 per SN registration, and each
        # mined block gives us an input of 18.9, which means each registration requires 6 inputs.
        # Thus we need a bare minimum of 6(N-5) blocks, plus the 30 lock time on coinbase TXes = 6N
        # more blocks (after the initial 4 registrations).
        self.mine(50)
        self.print_wallet_balances()
        vprint("Submitting first round of service node registrations: ", end="", flush=True)
        for sn in self.sns[0:3]:
            self.mike.register_sn(sn)
            vprint(".", end="", flush=True, timestamp=False)
        vprint(timestamp=False)
        if len(self.sns) > 4:
            vprint("Going back to mining", flush=True)

            self.mine(6 * (len(self.sns) - 4))

            self.print_wallet_balances()
            vprint("Submitting more service node registrations: ", end="", flush=True)
            for sn in self.sns[4:]:
                self.mike.register_sn(sn)
                vprint(".", end="", flush=True, timestamp=False)
            vprint(timestamp=False)
            vprint("Done.")

        self.print_wallet_balances()

        if len(self.sns) > 4:
            vprint(
                "Mining 40 blocks (registrations + blink quorum lag) and waiting for nodes to sync"
            )
            self.sync_nodes(self.mine(40))

            self.print_wallet_balances()
        else:
            vprint("Mining 2 blocks (registrations) and waiting for nodes to sync")

        vprint("Sending fake lokinet/ss pings")
        for sn in self.sns:
            sn.ping()

        if len(self.sns) > 1:
            all_service_nodes_proofed = lambda sn: all(
                x["quorumnet_port"] > 0
                for x in sn.json_rpc(
                    "get_n_service_nodes", {"fields": {"quorumnet_port": True}}
                ).json()["result"]["service_node_states"]
            )

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
        if not v.verbose:
            return
        vprint("Balances:")
        for w in self.wallets:
            b = w.balances(refresh=True)
            vprint(
                "    {:5s}: {:.9f} (total) with {:.9f} (unlocked)".format(
                    w.name, b[0] * 1e-9, b[1] * 1e-9
                )
            )

    def __del__(self):
        for n in self.all_nodes:
            n.terminate()
        for w in self.wallets:
            w.terminate()


snn = None


def sn_net(pytestconfig, tmp_path, binary_dir):
    """Fixture that returns the service node network.  It is persistent across tests: the first time
    it loads it starts the daemons and wallets, mines a bunch of blocks and submits SN
    registrations.  On subsequent loads it mines 5 blocks so that mike always has some available
    funds, and resets alice and bob to new wallets."""
    global snn
    if not snn:
        v.verbose = pytestconfig.getoption("verbose") >= 2
        if v.verbose:
            print("\nConstructing initial service node network")
        snn = SNNetwork(datadir=tmp_path, binpath=binary_dir)
    else:
        snn.alice.new_wallet()
        snn.bob.new_wallet()

        # Flush pools because some tests leave behind impossible txes
        for n in snn.all_nodes:
            assert n.json_rpc("flush_txpool").json()["result"]["status"] == "OK"

        # Mine a few to clear out anything in the mempool that can be cleared
        snn.mine(5, sync=True)

        vprint("Alice has new wallet: {}".format(snn.alice.address()))
        vprint("Bob   has new wallet: {}".format(snn.bob.address()))

    return snn


def basic_net(pytestconfig, tmp_path, binary_dir):
    """
    Fixture that returns a network of just one service node (solely for the rewards) and one
    regular node.  Unlike sn_net, it is not persistent across tests: it starts new daemons and
    wallets each time it is constructed.
    """
    v.verbose = pytestconfig.getoption("verbose") >= 2
    return SNNetwork(datadir=tmp_path, binpath=binary_dir, sns=1, nodes=1, unstaked_sns=1)
