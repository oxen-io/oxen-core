# Wallet application overview:


# How the wallet library will be used

*"User" below refers not to the actual person running a wallet,
but e.g. a python implementation of a GUI wallet which uses this library.*

## Creating a wallet

There should probably be standalone helper functions for wallet creation,
especially for key generation, but as of now this is unspecified.  It may be
decided that the majority of this functionality should be handled by the user.

## Using an existing wallet

1. User creates configuration object (detailed later) in whatever way makes sense,
e.g. loaded from an ini file, modified by cli flags, modified by a GUI

2. User creates a Keyring object loaded with wallet public keys, and private keys somehow:
    * user-provided getter function with timeout?

3. User creates any other Wallet injected dependencies as needed/desired,
e.g. test suite can inject a mock daemon rpc interface

4. User creates a Wallet object initialized with the config, keyring,
and any other dependencies as created above.
At this point, the Wallet will initialize itself and, provided it gives no error
here, is "running".

5. From here, user interacts with the running Wallet via oxenmq RPC.
    This may be within the same application, a separate process on the same machine,
    or a separate process on another machine, depending on how the user wants
    to interact and how the Wallet RPC is configured.

    * User can at this point subscribe to events via oxenmq as well,
      e.g. block arrivals, transaction receipt, ons changes, etc.
      The interface and usage for this are as-yet undefined.

# What is in a Wallet

## A Wallet consists of / contains instances of the following objects:

- DaemonComms
- RequestHandler
- TransactionScanner
- TransactionConstructor
- Database
- Keyring
- OxenMQ
- OmqRPC
- Legacy HTTP RPC


## DaemonComms

DaemonComms handles communication with an oxend.  This consists of:

- fetching batches of blocks for synchronizing a new (or behind) Wallet with the
blockchain
- subscribing to block updates from the blockchain to be supplied to the Wallet
    this includes new blocks, unmined transactions, and chain reorgs
- fetching decoy outputs for transaction construction
- submitting transactions to the blockchain


## RequestHandler

RequestHandler executes RPC requests from user.

This might be as simple as getting the current chain height from the db
and returning it, or it might be a multi-call process of create, sign, and submit
a transaction to the chain.

The scope of this functionality is large enough that enumerating all of it here
would be unweildy; Refer to the [RPC definitions](../../src/wallet3/rpc/commands.h).


## TransactionScanner

TransactionScanner scans a transaction for receipts, spends, and metadata
relevant to the wallet.  At this time, Wallet handles inserting these data
into the database, but in future this functionality may move into this class.

The Keyring class is used to compute the output keys to match against, and
for decoding amounts of received and spent outputs in the case of a match.

The Database is checked against spent key images for detecting our spends.

Multithreading can eventually be used for scanning as follows:
    1. A batch of blocks comes in and is passed to threads in chunks to be
    scanned for incoming receipts.
    2. When every block from that batch is scanned for receipts, any receipts
    are added to the database.
    3. After receipts are handles, the blocks are then passed to threads to be
    scanned for spends.  This has to wait on the receipt scan as we may spend
    an output within a small number of blocks of receiving it.
    4. Any spends are added to the database.


## TransactionConstructor

TransactionConstructor...creates transactions.  This includes selecting inputs,
fetching decoy inputs, and compiling these along with requested metadata
(e.g. ons record updates, service node staking, etc.).

This class does not handle signing the transaction; that will be handled by Keyring.


## Database

The Database class handles initializing the database schema and wraps
interactions with the underlying sqlite database.  sqlite queries belong here,
and should not be present elsewhere.


## Keyring

The Keyring class handles key usage.  It may also handle storage?

All functions that use the user's keys live here.  The user will set unlock
callback functions for the private view and spend keys, except in the case
of a hardware wallet where that functionality exists on the device itself.


## OxenMQ

The Wallet has an OxenMQ instance used for RPC as well as scheduling actions
on the Wallet's various threads.

Operations which write to the database must take place on the main Wallet thread,
but other operations can take place in the calling thread.  OxenMQ thread management
will be used for multithreading the blockchain sync process (see TransactionScanner above).


## OmqRPC

This class sets up RPC endpoints using OxenMQ which are then parsed and handed
off to RequestHandler.  The user-supplied configuration on Wallet creation will
contain which addresses and protocols to listen on.


## Legacy HTTP RPC

This is unspecified at this time.
