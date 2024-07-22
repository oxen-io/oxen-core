# Ledger hardware wallet test suite

This directory contains the Ledger hardware wallet test suite for testing the interactions of the
Oxen wallet (via the oxen-rpc-wallet) with a Ledger device.

It works by booting up a new "fakechain" oxen network for each set of tests where it mines a few
blocks and sets up wallets that interact to test various Ledger wallet functionality.  The test
suite itself manages this fake network and wallets; you do not need to do anything to run this fake
network.

## Requirements

1. Compiled oxend and oxen-wallet-cli binaries.  By default the test suite looks in ../../build/bin
   but you can specify a different path by running the tests with the `--binary-dir=...` argument.

   The build must include Ledger support, which
   requires libhidapi-dev on the system; during cmake invocation there should be a line such as:

        -- Using HIDAPI /usr/lib/x86_64-linux-gnu/libhidapi-libusb.so (includes at /usr/include/hidapi)

   If it instead gives a message about HIDAPI not found then you will need to install the headers
   and rebuild.

2. Running the test code on the client side requires Python 3.8 (or higher) with
   [pytest](https://pytest.org) and the `requests` modules installed.

3. A debug build of the [Oxen Ledger hardware wallet app](https://github.com/LedgerHQ/app-oxen).  As
   per Ledger requirements, this is built inside a docker container, using `BOLOS_SDK=$NANOS_SDK
   make DEBUG=1` from the app directory (changing the device SDK as needed for the device type to be
   tested).

4. A working [Speculos device emulator](https://github.com/LedgerHQ/speculos) to emulate the
   hardware wallet and run the wallet code.

## Running the tests

### Starting the emulator

Start the speculos emulator using:

    python3 /path/to/speculos/speculos.py /path/to/bin/app.elf -m nanos

for a Nano S emulator; change `nanos` to `nanox` to emulate the Nano X.

`app.elf` here is the app built in the app-oxen repository.

Then the tests start running you should see an emulated Ledger screen appear with a testnet wallet
(starting with `T`).  If it comes up with a mainnet Oxen wallet (starting with `L`) then you are not
running a debug build and should rebuild the device application.

Leave speculos running for the duration of the tests.

### Pytest

With the emulator running, invoke `pytest` (or `python3 -mpytest` if a pytest binary is not
installed) from the tests/ledger directory of the oxen-core project.  You should start to see it
running the tests, and should activity in speculos (both in its terminal, and on the screen).

Running the full test suite takes about 3-5 minutes.

#### Advanced testing output

- If you want more verbosity as the tests run add `-vv` to the pytest invocation.

- To run a specific test use `-k test_whatever` to run just tests matching `test_whatever`.  For
  example, `-k test_transfers.py` will run just the transfer tests, and `-k test_sn_stake` will run
  just the SN staking test.  `pytest --collect-only` will list all available tests.

- For extremely verbose output use `-vv -s`; this increase verbosity *and* adds various test suite
  debugging statements as the tests run.

- Each test creates temporary directories for the oxend and oxen-wallet-rpc instances that get
  created; if you run with `-vv -s` the debug output will include the path where these are being
  created; typically /tmp/pytest-of-$USERNAME/pytest-current will symlink to the latest run.  You
  can drill into these directories to look at oxend or oxen-wallet-rpc logs, if necessary for
  diagnosing test issues.
