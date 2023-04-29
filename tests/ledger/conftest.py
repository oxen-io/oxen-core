#!/usr/bin/python3

import pytest
import os.path
import service_node_network

from ledgerapi import LedgerAPI

from daemons import Wallet


def pytest_addoption(parser):
    parser.addoption("--binary-dir", default="../../build/bin", action="store")
    parser.addoption("--ledger-apdu", default="127.0.0.1:9999", action="store")
    parser.addoption("--ledger-api", default="http://127.0.0.1:5000", action="store")


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


@pytest.fixture(scope="session")
def ledger(request):
    return LedgerAPI(request.config.getoption("--ledger-api"))


@pytest.fixture
def net(pytestconfig, tmp_path, binary_dir):
    import vprint
    return service_node_network.basic_net(pytestconfig, tmp_path, binary_dir)


@pytest.fixture
def hal(net, request):
    """
    `hal` is a Ledger hardware-backed wallet.
    """

    hal = Wallet(
        node=net.nodes[0],
        name="HAL",
        rpc_wallet=net.binpath + "/oxen-wallet-rpc",
        datadir=net.datadir,
        ledger_api=request.config.getoption("--ledger-api"),
        ledger_apdu=request.config.getoption("--ledger-apdu"),
    )
    hal.ready(wallet="HAL")

    return hal


@pytest.fixture
def mike(net):
    return net.mike


@pytest.fixture
def alice(net):
    return net.alice


@pytest.fixture
def bob(net):
    return net.bob


# Gives you an (unstaked) sn
@pytest.fixture
def sn(net):
    return net.unstaked_sns[0]
