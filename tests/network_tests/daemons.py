#!/usr/bin/python3

import sys
import random
import requests
import subprocess
import time


def coins(*args):
    if len(args) != 1:
        return tuple(coins(x) for x in args)
    x = args[0]
    if type(x) in (tuple, list):
        return type(x)(coins(i) for i in x)
    return round(x * 1_000_000_000)


# On linux we can pick a random 127.x.y.z IP which is highly likely to not have anything listening
# on it (so we make bind conflicts highly unlikely).  On most other OSes we have to listen on
# 127.0.0.1 instead, so we pick a random starting port instead to try to minimize bind conflicts.
LISTEN_IP, NEXT_PORT = (
    ("127." + ".".join(str(random.randint(1, 254)) for _ in range(3)), 1100)
    if sys.platform == "linux"
    else ("127.0.0.1", random.randint(5000, 20000))
)


def next_port():
    global NEXT_PORT
    port = NEXT_PORT
    NEXT_PORT += 1
    return port


class ProcessExited(RuntimeError):
    pass


class TransferFailed(RuntimeError):
    def __init__(self, message, json):
        super().__init__(message)
        self.message = message
        self.json = json


class RPCDaemon:
    def __init__(self, name):
        self.name = name
        self.proc = None
        self.terminated = False
        self.timeout = 10  # subclass should override if needed

    def __del__(self):
        self.stop()

    def terminate(self, repeat=False):
        """Sends a TERM signal if one hasn't already been sent (or even if it has, with
        repeat=True).  Does not wait for exit."""
        if self.proc and (repeat or not self.terminated):
            self.proc.terminate()
            self.terminated = True

    def start(self):
        if self.proc and self.proc.poll() is None:
            raise RuntimeError("Cannot start process that is already running!")
        self.proc = subprocess.Popen(
            self.arguments(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.terminated = False

    def stop(self, timeout=None):
        """Tries stopping with a term at first, then a kill if the term hasn't worked after 10s"""
        if self.proc:
            self.terminate()
            timeout = timeout or self.timeout
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                print(f"{self.name} took more than {timeout}s to exit, killing it")
                self.proc.kill()
            self.proc = None

    def arguments(self):
        """Returns the startup arguments; default is just self.args, but subclasses can override."""
        return self.args

    def json_rpc(self, method, params=None, *, timeout=None):
        """Sends a json_rpc request to the rpc port.  Returns the response object."""
        if not self.proc:
            raise RuntimeError("Cannot make rpc request before calling start()")
        json = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params:
            json["params"] = params

        return requests.post(
            f"http://{self.listen_ip}:{self.rpc_port}/json_rpc",
            json=json,
            timeout=timeout or self.timeout,
        )

    def rpc(self, path, params=None, *, timeout=None):
        """Sends a non-json_rpc rpc request to the rpc port at path `path`, e.g. /get_info.  Returns the response object."""
        if not self.proc:
            raise RuntimeError("Cannot make rpc request before calling start()")
        return requests.post(
            f"http://{self.listen_ip}:{self.rpc_port}{path}", json=params, timeout=timeout
        )

    def wait_for_json_rpc(self, method, params=None, *, timeout=None):
        """Calls `json_rpc', sleeping if it fails for up time `timeout' seconds (self.timeout if
        omitted).  Returns the response if it succeeds, raises the last exception if timeout is
        reached.  If the process exit, raises a RuntimeError"""

        until = time.time() + (timeout or self.timeout)
        now = time.time()
        while now < until:
            exit_status = self.proc.poll()
            if exit_status is not None:
                raise ProcessExited(
                    f"{self.name} exited ({exit_status}) while waiting for an RPC response"
                )

            timeout = until - now
            try:
                return self.json_rpc(method, params, timeout=timeout)
            except:
                if time.time() + 0.25 >= until:
                    raise
                time.sleep(0.25)
                now = time.time()
                if now >= until:
                    raise


class Daemon(RPCDaemon):
    base_args = ("--dev-allow-local-ips", "--fixed-difficulty=1", "--regtest", "--non-interactive")

    def __init__(
        self,
        *,
        oxend="oxend",
        listen_ip=None,
        p2p_port=None,
        rpc_port=None,
        zmq_port=None,
        qnet_port=None,
        ss_port=None,
        name=None,
        datadir=None,
        service_node=False,
        log_level=2,
        peers=(),
    ):
        self.rpc_port = rpc_port or next_port()
        if name is None:
            name = f"oxend@{self.rpc_port}"
        super().__init__(name)
        self.listen_ip = listen_ip or LISTEN_IP
        self.p2p_port = p2p_port or next_port()
        self.zmq_port = zmq_port or next_port()
        self.qnet_port = qnet_port or next_port()
        self.ss_port = ss_port or next_port()
        self.peers = []

        self.args = [oxend] + list(self.__class__.base_args)
        self.args += (
            f"--data-dir={datadir or '.'}/oxen-{self.listen_ip}-{self.rpc_port}",
            f"--log-level={log_level}",
            "--log-file=oxen.log",
            f"--p2p-bind-ip={self.listen_ip}",
            f"--p2p-bind-port={self.p2p_port}",
            f"--rpc-admin={self.listen_ip}:{self.rpc_port}",
            f"--quorumnet-port={self.qnet_port}",
        )

        for d in peers:
            self.add_peer(d)

        if service_node:
            self.args += (
                "--service-node",
                f"--service-node-public-ip={self.listen_ip}",
                f"--storage-server-port={self.ss_port}",
            )

    def arguments(self):
        return self.args + [
            f"--add-exclusive-node={node.listen_ip}:{node.p2p_port}" for node in self.peers
        ]

    def ready(self):
        """Waits for the daemon to get ready, i.e. for it to start returning something to a
        `get_info` rpc request.  Calls start() if it hasn't already been called."""
        if not self.proc:
            self.start()
        self.wait_for_json_rpc("get_info")

    def add_peer(self, node):
        """Adds a peer.  Must be called before starting."""
        if self.proc:
            raise RuntimeError("add_peer needs to be called before start()")
        self.peers.append(node)

    def remove_peer(self, node):
        """Removes a peer.  Must be called before starting."""
        if self.proc:
            raise RuntimeError("remove_peer needs to be called before start()")
        self.peers.remove(node)

    def mine_blocks(self, num_blocks, wallet, *, slow=True):
        a = wallet.address()
        self.rpc(
            "/start_mining",
            {"miner_address": a, "threads_count": 1, "num_blocks": num_blocks, "slow_mining": slow},
        )

    def sn_pubkey(self):
        return self.json_rpc("get_service_keys").json()["result"]["service_node_pubkey"]

    def height(self):
        return self.rpc("/get_height").json()["height"]

    def txpool_hashes(self):
        return [x["id_hash"] for x in self.rpc("/get_transaction_pool").json()["transactions"]]

    def ping(self, *, storage=True, lokinet=True):
        """Sends fake storage server and lokinet pings to the running oxend"""
        if storage:
            self.json_rpc(
                "storage_server_ping", {"version_major": 9, "version_minor": 9, "version_patch": 9}
            )
        if lokinet:
            self.json_rpc("lokinet_ping", {"version": [9, 9, 9]})

    def p2p_resync(self):
        """Triggers a p2p resync to happen soon (i.e. at the next p2p idle loop)."""
        self.json_rpc("test_trigger_p2p_resync")


class Wallet(RPCDaemon):
    base_args = (
        "--disable-rpc-login",
        "--non-interactive",
        "--password",
        "",
        "--regtest",
        "--disable-rpc-long-poll",
    )

    def __init__(
        self,
        node,
        *,
        rpc_wallet="oxen-wallet-rpc",
        name=None,
        datadir=None,
        listen_ip=None,
        rpc_port=None,
        ledger_api=None,  # e.g. "http://localhost:5000"
        ledger_apdu=None,  # e.g. "localhost:1111"
        log_level=2,
    ):
        self.listen_ip = listen_ip or LISTEN_IP
        self.rpc_port = rpc_port or next_port()
        self.node = node
        self.ledger_api = ledger_api
        self.ledger_apdu = ledger_apdu
        if bool(self.ledger_api) != bool(self.ledger_apdu):
            raise RuntimeError("ledger_api/ledger_apdu are mutually dependent")

        self.name = name or f"wallet@{self.rpc_port}"
        super().__init__(self.name)

        self.timeout = 60 if self.ledger_api else 10

        self.walletdir = f'{datadir or "."}/wallet-{self.listen_ip}-{self.rpc_port}'
        self.args = [rpc_wallet] + list(self.__class__.base_args)
        self.args += (
            f"--rpc-bind-ip={self.listen_ip}",
            f"--rpc-bind-port={self.rpc_port}",
            f"--log-level={log_level}",
            f"--log-file={self.walletdir}/log.txt",
            f"--shared-ringdb-dir",
            "",
            f"--daemon-address={node.listen_ip}:{node.rpc_port}",
            f"--wallet-dir={self.walletdir}",
        )

        self.wallet_address = None

    def ready(self, wallet="wallet", existing=False):
        """Makes the wallet ready, waiting for it to start up and create a new wallet (or load an
        existing one, if `existing`) within the rpc wallet.  Calls `start()` first if it hasn't
        already been called.  Does *not* explicitly refresh."""
        if not self.proc:
            self.start()

        self.wallet_filename = wallet
        if existing:
            r = self.wait_for_json_rpc("open_wallet", {"filename": wallet, "password": ""})
        else:
            params = {"filename": wallet, "password": "", "language": "English"}
            if self.ledger_api:
                params["hardware_wallet"] = True
                params["device_name"] = "LedgerTCP"
                params["debug_reset"] = True
                # These are fairly slow (~0.2s each) for the device to construct during
                # initialization, so severely reduce them for testing:
                params["subaddress_lookahead_major"] = 2
                params["subaddress_lookahead_minor"] = 2

            r = self.wait_for_json_rpc("create_wallet", params)
        if "result" not in r.json():
            raise RuntimeError(
                "Cannot open or create wallet: {}".format(
                    r["error"] if "error" in r else f"Unexpected response: {r.json()}"
                )
            )

    def refresh(self):
        return self.json_rpc("refresh")

    def address(self):
        if not self.wallet_address:
            self.wallet_address = self.json_rpc("get_address").json()["result"]["address"]

        return self.wallet_address

    def get_subaddress(self, account, subaddr):
        r = self.json_rpc(
            "get_address", {"account_index": account, "address_index": [subaddr]}
        ).json()
        if "result" not in r:
            raise RuntimeError(f"Unable to retrieve subaddr {account}.{subaddr}: {r['error']}")
        return r["result"]["addresses"][0]["address"]

    def new_wallet(self):
        self.wallet_address = None
        r = self.wait_for_json_rpc("close_wallet")
        if "result" not in r.json():
            raise RuntimeError(
                "Cannot close current wallet: {}".format(
                    r["error"] if "error" in r else f"Unexpected response: {r.json()}"
                )
            )
        if not hasattr(self, "wallet_suffix"):
            self.wallet_suffix = 2
        else:
            self.wallet_suffix += 1
        r = self.wait_for_json_rpc(
            "create_wallet",
            {
                "filename": f"{self.wallet_filename}_{self.wallet_suffix}",
                "password": "",
                "language": "English",
            },
        )
        if "result" not in r.json():
            raise RuntimeError(
                "Cannot create wallet: {}".format(
                    r["error"] if "error" in r else f"Unexpected response: {r.json()}"
                )
            )

    def height(self, refresh=False):
        """Returns current wallet height.  Can optionally refresh first."""
        if refresh:
            self.refresh()
        return self.json_rpc("get_height").json()["result"]["height"]

    def balances(self, refresh=False):
        """Returns (total, unlocked) balances.  Can optionally refresh first."""
        if refresh:
            self.refresh()
        b = self.json_rpc("get_balance").json()["result"]
        return (b["balance"], b["unlocked_balance"])

    def transfer(self, to, amount=None, *, priority=None, sweep=False):
        """Attempts a transfer.  Throws TransferFailed if it gets rejected by the daemon, otherwise
        returns the 'result' key."""
        if isinstance(to, Wallet):
            to = to.address()
        else:
            assert isinstance(to, str)

        if priority is None:
            priority = 1
        if sweep and not amount:
            r = self.json_rpc("sweep_all", {"address": to, "priority": priority})
        elif amount and not sweep:
            r = self.json_rpc(
                "transfer_split",
                {"destinations": [{"address": to, "amount": amount}], "priority": priority},
            )
        else:
            raise RuntimeError("Wallet.transfer: either `sweep` or `amount` must be given")

        r = r.json()
        if "error" in r:
            raise TransferFailed(f"Transfer failed: {r['error']['message']}", r)
        return r["result"]

    def multi_transfer(self, recipients, amounts, *, priority=None):
        """Attempts a transfer to multiple recipients at once.  Throws TransferFailed if it gets
        rejected by the daemon, otherwise returns the 'result' key."""
        assert 0 < len(recipients) == len(amounts)
        for i in range(len(recipients)):
            if isinstance(recipients[i], Wallet):
                recipients[i] = recipients[i].address()
            else:
                assert isinstance(recipients[i], str)

        if priority is None:
            priority = 1
        r = self.json_rpc(
            "transfer_split",
            {
                "destinations": [{"address": r, "amount": a} for r, a in zip(recipients, amounts)],
                "priority": priority,
            },
        )

        r = r.json()
        if "error" in r:
            raise TransferFailed(f"Transfer failed: {r['error']['message']}", r)
        return r["result"]

    def find_transfers(self, txids, in_=True, pool=True, out=True, pending=False, failed=False):
        transfers = self.json_rpc(
            "get_transfers",
            {"in": in_, "pool": pool, "out": out, "pending": pending, "failed": failed},
        ).json()["result"]

        def find_tx(txid):
            for type_, txs in transfers.items():
                for tx in txs:
                    if tx["txid"] == txid:
                        return tx

        return [find_tx(txid) for txid in txids]

    def register_sn(self, sn, stake=coins(100), fee=10):
        r = sn.json_rpc(
            "get_service_node_registration_cmd",
            {
                "operator_cut": "100" if stake == coins(100) else f"{fee}",
                "contributions": [{"address": self.address(), "amount": stake}],
                "staking_requirement": coins(100),
            },
        ).json()
        if "error" in r:
            raise RuntimeError(f"Registration cmd generation failed: {r['error']['message']}")
        cmd = r["result"]["registration_cmd"]
        if cmd == "":
            # everything about this command is dumb, include its error handling
            raise RuntimeError(f"Registration cmd generation failed: {r['result']['status']}")

        r = self.json_rpc("register_service_node", {"register_service_node_str": cmd}).json()
        if "error" in r:
            raise RuntimeError(
                "Failed to submit service node registration tx: {}".format(r["error"]["message"])
            )

    def stake_sn(self, sn, stake):
        r = self.json_rpc(
            "stake",
            {"destination": self.address(), "amount": stake, "service_node_key": sn.sn_pubkey()},
        ).json()
        if "error" in r:
            raise RuntimeError(f"Failed to submit stake: {r['error']['message']}")

    def unstake_sn(self, sn):
        r = self.json_rpc("request_stake_unlock", {"service_node_key": sn.sn_pubkey()}).json()
        if "error" in r:
            raise RuntimeError(f"Failed to submit unstake: {r['error']['message']}")
        if not r["result"]["unlocked"]:
            raise RuntimeError(f"Failed to submit unstake: {r['result']['msg']}")

    def buy_ons(self, onstype, name, value, *, owner=None, backup_owner=None):
        if onstype not in (
            "session",
            "wallet",
            "lokinet",
            "lokinet_2y",
            "lokinet_5y",
            "lokinet_10y",
        ):
            raise ValueError(f"Invalid ONS type '{onstype}'")

        params = {
            "type": onstype,
            "owner": self.address() if owner is None else owner,
            "name": name,
            "value": value,
        }
        if backup_owner:
            params["backup_owner"] = backup_owner

        r = self.json_rpc("ons_buy_mapping", params).json()
        if "error" in r:
            raise RuntimeError(f"Failed to buy ONS: {r['error']['message']}")
        return r

    def renew_ons(self, onstype, name):
        if onstype not in ("lokinet", "lokinet_2y", "lokinet_5y", "lokinet_10y"):
            raise ValueError(f"Invalid ONS renewal type '{onstype}'")

        r = self.json_rpc("ons_renew_mapping", {"type": onstype, "name": name}).json()
        if "error" in r:
            raise RuntimeError(f"Failed to buy ONS: {r['error']['message']}")
        return r

    def update_ons(self, onstype, name, *, value=None, owner=None, backup_owner=None):
        if onstype not in ("session", "wallet", "lokinet"):
            raise ValueError(f"Invalid ONS update type '{onstype}'")

        params = {"type": onstype, "name": name}
        if value is not None:
            params["value"] = value
        if owner is not None:
            params["owner"] = owner
        if backup_owner is not None:
            params["backup_owner"] = backup_owner

        r = self.json_rpc("ons_update_mapping", params).json()
        if "error" in r:
            raise RuntimeError(f"Failed to buy ONS: {r['error']['message']}")

        return r

    def get_ons(self, *, include_txid=False, include_encrypted=False, include_height=False):
        r = self.json_rpc("ons_known_names", {"decrypt": True}).json()
        if "error" in r:
            raise RuntimeError(f"Failed to buy ONS: {r['error']['message']}")

        names = sorted(r["result"]["known_names"], key=lambda x: (x["type"], x["name"]))
        if not include_txid:
            for n in names:
                del n["txid"]
        if not include_encrypted:
            for n in names:
                del n["encrypted_value"]
        if not include_height:
            for n in names:
                del n["update_height"]
                n.pop("expiration_height", None)
        return names
