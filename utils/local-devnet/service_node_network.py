#!/usr/bin/python3

from daemons import Daemon, Wallet
import ethereum
from ethereum import (
    SENTContract,
    SNRewardsContract,
    SNContribContract,
    SNContribFactoryContract,
    ContractSeedServiceNode,
    ContractServiceNodeContributor,
    ContractServiceNodeStaker,
    BLSPubkey,
    BLSSignatureParams,
    ServiceNodeParams,
    ReservedContributor,
)

import enum
import json

import pathlib
import argparse
import time
import shutil
import os
import asyncio
from   datetime import datetime
import subprocess
import atexit
import concurrent.futures
import random
from typing import List

datadirectory="testdata"

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


verbose = True
def vprint(*args, timestamp=True, **kwargs):
    global verbose
    if verbose:
        if timestamp:
            print(datetime.now(), end=" ")
        print(*args, **kwargs)

def all_service_nodes_proofed(sn):
    service_nodes = sn.json_rpc("get_n_service_nodes", {"fields": {"quorumnet_port": True, "pubkey_bls": True}}).json()['result']['service_node_states']
    result = True
    vprint("  {}".format(service_nodes), timestamp=False)
    for x in service_nodes:
        if x['quorumnet_port'] <= 0 or 'pubkey_bls' not in x or x['pubkey_bls'] is None:
            result = False
    return result

class SNExitMode(enum.Enum):
    AfterWaitTime = 0
    WithSignature = 1
    Liquidation   = 2

class SNNetwork:
    all_nodes = []
    wallets   = []

    def __init__(self, datadir, *, oxen_bin_dir, anvil_path, eth_sn_contracts_dir, sns=12, nodes=3):
        begin_time = time.perf_counter()

        # Setup Ethereum ###########################################################################
        # Setup Anvil, a private Ethereum blockchain (if specified)
        if anvil_path is not None:
            if os.path.exists(anvil_path):
                self.anvil = subprocess.Popen(anvil_path,
                                              stdin=subprocess.DEVNULL,
                                              stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL)
            else:
                raise RuntimeError('Anvil path \'{}\' specified but does not exist. Exiting'.format(anvil_path))

        # Verify private Ethereum blockchain is reachable
        verify_private_blockchain_attempts = 4
        while verify_private_blockchain_attempts > 0:
            try:
                eth_chain_id = ethereum.eth_chainId()
                assert eth_chain_id == 31337, 'Private Ethereum instance did not return correct chain ID {}'.format(eth_chain_id)
            except RuntimeError:
                verify_private_blockchain_attempts -= 1
                time.sleep(0.25)
                if verify_private_blockchain_attempts == 0:
                    raise
            else:
                break

        # Deploy smart contracts from eth-sn-contracts (if specified)
        if eth_sn_contracts_dir is not None:
            eth_sn_contracts_makefile_path = eth_sn_contracts_dir / 'Makefile'
            if os.path.exists(eth_sn_contracts_makefile_path):
                subprocess.run(['make', 'deploy-local'],
                               cwd=eth_sn_contracts_dir,
                               check=True)
            else:
                raise RuntimeError('eth-sn-contracts expected file to exist \'{}\' but does not. Exiting'.format(anvil_path))

        sn_rewards_json:         dict = {}
        sn_contrib_factory_json: dict = {}
        sn_contrib_json:         dict = {}
        reward_rate_pool_json:   dict = {}
        erc20_contract_json:     dict = {}

        with open(eth_sn_contracts_dir / 'artifacts/contracts/ServiceNodeRewards.sol/ServiceNodeRewards.json', 'r') as file:
            sn_rewards_json = json.load(file)

        with open(eth_sn_contracts_dir / 'artifacts/contracts/ServiceNodeContributionFactory.sol/ServiceNodeContributionFactory.json', 'r') as file:
            sn_contrib_factory_json = json.load(file)

        with open(eth_sn_contracts_dir / 'artifacts/contracts/ServiceNodeContribution.sol/ServiceNodeContribution.json', 'r') as file:
            sn_contrib_json = json.load(file)

        with open(eth_sn_contracts_dir / 'artifacts/contracts/RewardRatePool.sol/RewardRatePool.json', 'r') as file:
            reward_rate_pool_json = json.load(file)

        with open(eth_sn_contracts_dir / 'artifacts/contracts/SENT.sol/SENT.json', 'r') as file:
            erc20_contract_json = json.load(file)

        # NOTE: Connect proxy contracts to on-chain instances
        # SENT ERC20 token
        self.sent_contract = SENTContract(contract_json=erc20_contract_json)

        # SN Rewards
        self.sn_contract = SNRewardsContract(sn_rewards_json=sn_rewards_json,
                                             reward_rate_pool_json=reward_rate_pool_json)
        contract_staking_requirement = self.sn_contract.stakingRequirement()

        self.sent_contract.approve(sender=self.sn_contract.hardhat_account0,
                                   spender=self.sn_contract.contract.address,
                                   value=int(999_999 * 1e9))

        hh1_required_sent: int = int((contract_staking_requirement / 2) * 5)

        # Multi-contrib Factory
        self.sn_contrib_factory = SNContribFactoryContract(contract_json=sn_contrib_factory_json);

        # Setup Oxen ###############################################################################
        # Nodes ####################################################################################
        # Setup directories
        self.datadir      = datadir
        self.oxen_bin_dir = oxen_bin_dir
        if not os.path.exists(self.datadir):
            os.makedirs(self.datadir)
        vprint("Using '{}' for data files and logs".format(datadir))

        nodeopts       = dict(oxend=str(self.oxen_bin_dir / 'oxend'), datadir=datadir)
        self.eth_sns   = [Daemon(service_node=True, **nodeopts) for _ in range(len(SNExitMode) * 2)]
        self.sns       = [Daemon(service_node=True, **nodeopts) for _ in range(sns)]
        self.nodes     = [Daemon(**nodeopts) for _ in range(nodes)]
        self.all_nodes = self.sns + self.nodes + self.eth_sns

        # Wallets ##################################################################################
        self.wallets = []
        for name in ('Alice', 'Bob', 'Mike'):
            self.wallets.append(Wallet(
                node=self.nodes[len(self.wallets) % len(self.nodes)],
                name=name,
                rpc_wallet=str(self.oxen_bin_dir/'oxen-wallet-rpc'),
                datadir=datadir))

        self.alice, self.bob, self.mike = self.wallets

        self.extrawallets = []
        for name in range(9):
            self.extrawallets.append(Wallet(
                node=self.nodes[len(self.extrawallets) % len(self.nodes)],
                name="extrawallet-"+str(name),
                rpc_wallet=str(self.oxen_bin_dir/'oxen-wallet-rpc'),
                datadir=datadir))

        # Interconnections
        for i in range(len(self.all_nodes)):
            for j in (2, 3, 5, 7, 11):
                k = (i + j) % len(self.all_nodes)
                if i != k:
                    self.all_nodes[i].add_peer(self.all_nodes[k])

        # Thread Pool ##############################################################################
        thread_pool                              = concurrent.futures.ThreadPoolExecutor()
        futures: List[concurrent.futures.Future] = []

        # Start Oxen SNs ###########################################################################
        vprint("Starting new oxend service nodes with RPC".format(self.sns[0].listen_ip), end="")
        for sn in self.sns:
            futures.append(thread_pool.submit(sn.start))
        for sn in self.eth_sns:
            futures.append(thread_pool.submit(sn.start))

        concurrent.futures.wait(futures)
        futures.clear()

        for sn in self.sns:
            vprint(" {}".format(sn.rpc_port), end="", flush=True, timestamp=False)

        for sn in self.eth_sns:
            vprint(" {}".format(sn.rpc_port), end="", flush=True, timestamp=False)

        # Start Oxen Nodes #########################################################################
        vprint(timestamp=False)
        vprint("Starting new regular oxend nodes with RPC on {} ports".format(self.nodes[0].listen_ip), end="")
        for d in self.nodes:
            vprint(" {}".format(d.rpc_port), end="", flush=True, timestamp=False)
            d.start()
        vprint(timestamp=False)

        vprint("Waiting for all oxend's to get ready")
        for d in self.all_nodes:
            d.wait_for_json_rpc("get_info")

        vprint("Oxends are ready. Starting wallets in parallel")
        # Start wallet executables #################################################################
        for w in self.wallets:
            vprint("Starting new RPC wallet {w.name} at {w.listen_ip}:{w.rpc_port}".format(w=w))
            thread_pool.submit(w.start)

        for w in self.extrawallets:
            vprint("Starting new RPC wallet {w.name} at {w.listen_ip}:{w.rpc_port}".format(w=w))
            thread_pool.submit(w.start)

        concurrent.futures.wait(futures)
        futures.clear()

        # Create wallets ###########################################################################
        for w in self.wallets:
            futures.append(thread_pool.submit(w.ready))

        for w in self.extrawallets:
            futures.append(thread_pool.submit(w.ready))

        concurrent.futures.wait(futures)
        futures.clear()

        # Refresh wallets ##########################################################################
        for w in self.wallets:
            w.refresh()
            vprint("Wallet {w.name} is ready: {a}".format(w=w, a=w.address()))

        for w in self.extrawallets:
            w.refresh()
            vprint("Wallet {w.name} is ready: {a}".format(w=w, a=w.address()))

        for w in self.wallets:
            w.wait_for_json_rpc("refresh")

        for w in self.extrawallets:
            w.wait_for_json_rpc("refresh")

        configfile=self.datadir+'config.py'
        with open(configfile, 'w') as filetowrite:
            filetowrite.write('#!/usr/bin/python3\n# -*- coding: utf-8 -*-\nlisten_ip=\"{}\"\nlisten_port=\"{}\"\nwallet_listen_ip=\"{}\"\nwallet_listen_port=\"{}\"\nwallet_address=\"{}\"\nexternal_address=\"{}\"'.format(self.sns[0].listen_ip,self.sns[0].rpc_port,self.mike.listen_ip,self.mike.rpc_port,self.mike.address(),self.bob.address()))

        # Start blockchain setup ###################################################################
        # Mine some blocks; we need 100 per SN registration, and we can nearly 600 on fakenet before
        # it hits HF16 and kills mining rewards.  This lets us submit the first 5 SN registrations a
        # SN (at height 40, which is the earliest we can submit them without getting an occasional
        # spurious "Not enough outputs to use" error).
        # to unlock and the rest to have enough unlocked outputs for mixins), then more some more to
        # earn SN rewards.  We need 100 per SN registration, and each mined block gives us an input
        # of 18.9, which means each registration requires 6 inputs.  Thus we need a bare minimum of
        # 6(N-5) blocks, plus the 30 lock time on coinbase TXes = 6N more blocks (after the initial
        # 5 registrations).
        self.sync_nodes(self.mine(46), timeout=120)
        vprint("Submitting first round of service node registrations:", flush=True)
        self.mike.refresh()
        for sn in self.sns[0:5]:
            self.mike.register_sn(sn, self.sns[0].get_staking_requirement())
            vprint(".", end="", flush=True, timestamp=False)
        vprint(timestamp=False)
        if len(self.sns) > 5:
            vprint("Going back to mining", flush=True)

            self.mine(6*len(self.sns))

            self.print_wallet_balances()
            self.mike.transfer(self.alice, coins(150))
            self.mike.transfer(self.bob, coins(150))
            vprint("Submitting more service node registrations: ", end="", flush=True)
            for sn in self.sns[5:-1]:
                self.mike.register_sn(sn, self.sns[0].get_staking_requirement())
                vprint(".", end="", flush=True, timestamp=False)
            vprint(timestamp=False)
            vprint("Done.")

        self.print_wallet_balances()

        vprint("Mining 30 blocks to height 149 (registrations + blink quorum lag) and waiting for nodes to sync")
        self.sync_nodes(self.mine(29), timeout=120)
        for wallet in self.extrawallets:
            self.mike.transfer(wallet, coins(11))
        self.sync_nodes(self.mine(1), timeout=120) # Height 149

        self.print_wallet_balances()

        # Register the last SN through Bobs wallet (Has not done any others)
        # and also get 9 other wallets to contribute the rest of the node with a 10% operator fee
        self.bob.register_sn_for_contributions(sn=self.sns[-1], cut=10, amount=coins(28), staking_requirement=self.sns[0].get_staking_requirement())
        self.sync_nodes(self.mine(20), timeout=120) # Height 169
        self.print_wallet_balances()
        for wallet in self.extrawallets:
            wallet.contribute_to_sn(self.sns[-1], coins(8))

        # Submit block to enter the BLS transition ##################################################
        self.sync_nodes(self.mine(1), timeout=120) # Height 170

        vprint("Sending fake lokinet/ss pings")
        for sn in self.sns:
            sn.ping()

        vprint("Send uptime proofs at height HF20 to propagate BLS pubkeys")
        for sn in self.sns:
            sn.send_uptime_proof()

        vprint("Waiting for proofs to propagate:", flush=True)
        for sn in self.sns:
            wait_for(lambda: all_service_nodes_proofed(sn), timeout=120)
        vprint(timestamp=False)

        # Pull out some useful keys to local variables
        staker_eth_addr       = self.sn_contract.hardhat_account0.address
        staker_eth_addr_no_0x = self.sn_contract.hardhat_account0.address[2:42]
        assert len(staker_eth_addr) == 42, "Expected Eth address w/ 0x prefix + 40 hex characters. Account was {} ({} chars)".format(staker_eth_addr, len(staker_eth_addr))

        beneficiary_eth_addr       = self.sn_contract.hardhat_account1.address
        beneficiary_eth_addr_no_0x = self.sn_contract.hardhat_account1.address[2:42]
        assert len(beneficiary_eth_addr) == 42, "Expected Eth address w/ 0x prefix + 40 hex characters. Account was {} ({} chars)".format(beneficiary_eth_addr, len(beneficiary_eth_addr))

        # Construct the seed list for initiating the smart contract.
        # Note all SNs up to this point (HF < feature::ETH_BLS) had a 100 OXEN staking requirement
        oxen_staking_requirement     = self.sns[0].get_staking_requirement()
        seed_node_list      = []
        for sn in self.sns:
            node         = ContractSeedServiceNode(sn.get_service_keys().bls_pubkey, sn.get_service_keys().ed25519_pubkey)
            contributors = sn.sn_status()["service_node_state"]["contributors"]
            total_staked = 0

            for entry in contributors:
                contributor = ContractServiceNodeContributor(ContractServiceNodeStaker(staker_eth_addr, beneficiary_eth_addr),
                                                             int((entry["amount"] / oxen_staking_requirement * contract_staking_requirement)))
                # Use the oxen amount proportionally as the SENT amount
                total_staked += contributor.stakedAmount
                node.contributors.append(contributor)

            # Assign any left over SENT to be staked to the operator
            left_over_to_be_staked = contract_staking_requirement - total_staked
            if left_over_to_be_staked > 0:
                node.contributors[0].stakedAmount += left_over_to_be_staked

            seed_node_list.append(node)

        self.sn_contract.seedPublicKeyList(seed_node_list)
        vprint("Seeded BLS public keys into contract. Contract has {} SNs".format(self.sn_contract.totalNodes()))

        # Start the rewards contract after seeding the BLS public keys
        self.sn_contract.start()
        prev_contract_sn_count = self.sn_contract.totalNodes()

        # Submit block to enter the BLS hardfork ###################################################
        self.sync_nodes(self.mine(1), timeout=120) # Height 171

        # Register a SN via the Ethereum smart contract, half as multi-contrib,
        # half as solo nodes.
        for index, sn in enumerate(self.eth_sns):

            sn_pubkey = sn.get_service_keys().pubkey
            reg_json  = sn.get_ethereum_registration_args(staker_eth_addr_no_0x)

            key = BLSPubkey(
                X=int(reg_json["bls_pubkey"][:64], 16),
                Y=int(reg_json["bls_pubkey"][64:128], 16)
            )

            sig = BLSSignatureParams(
                sigs0=int(reg_json["proof_of_possession"][:64], 16),
                sigs1=int(reg_json["proof_of_possession"][64:128], 16),
                sigs2=int(reg_json["proof_of_possession"][128:192], 16),
                sigs3=int(reg_json["proof_of_possession"][192:256], 16),
            )

            params = ServiceNodeParams(
                serviceNodePubkey=    int(reg_json["service_node_pubkey"], 16),
                serviceNodeSignature1=int(reg_json["service_node_signature"][:64], 16),
                serviceNodeSignature2=int(reg_json["service_node_signature"][64:128], 16),
                fee=int(0),
            )

            print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            print(vars(key))
            print(vars(sig))
            print(vars(params))

            if index > (len(self.eth_sns) / 2):
                contributors: list[ContractServiceNodeContributor] = [
                    ContractServiceNodeContributor(
                        ContractServiceNodeStaker(addr=staker_eth_addr, beneficiary=beneficiary_eth_addr),
                        stakedAmount=contract_staking_requirement,
                    )
                ]

                vprint("Preparing to submit registration to Eth w/ address {} for SN {} ({})\nContributors {}".format(staker_eth_addr, sn_pubkey, reg_json, contributors))
                self.sn_contract.addBLSPublicKey(sender=self.sn_contract.hardhat_account0,
                                                 key=key,
                                                 sig=sig,
                                                 params=params,
                                                 contributors=contributors)
            else:
                reserved: list[ReservedContributor] = [
                    ReservedContributor(addr=self.sn_contract.hardhat_account0.address, amount=int(contract_staking_requirement / 2)),
                    ReservedContributor(addr=self.sn_contract.hardhat_account1.address, amount=int(contract_staking_requirement / 2)),
                ]

                self.sn_contrib_factory.deploy(account=self.sn_contract.hardhat_account0,
                                               key=key,
                                               sig=sig,
                                               params=params,
                                               reserved=reserved,
                                               manual_finalize=False)

        # NOTE: Fund hardhat account 1 w/ enough $SENT to fund their 50% of the
        # multi-contrib contracts
        hh1_required_sent: int = int((contract_staking_requirement / 2) * len(self.sn_contrib_factory.deployedContracts))

        print("HH Account 0 Balance: {} $SENT".format(self.sent_contract.balanceOf(address=self.sn_contract.hardhat_account0.address)))
        print("HH Account 1 Balance: {} $SENT".format(self.sent_contract.balanceOf(address=self.sn_contract.hardhat_account1.address)))
        self.sent_contract.approve(sender=self.sn_contract.hardhat_account0,
                                   spender=self.sn_contract.hardhat_account0.address,
                                   value=hh1_required_sent)
        self.sent_contract.transferFrom(sender=self.sn_contract.hardhat_account0,
                                        to=self.sn_contract.hardhat_account1.address,
                                        value=hh1_required_sent)
        print("HH Account 0 Balance: {} $SENT".format(self.sent_contract.balanceOf(address=self.sn_contract.hardhat_account0.address)))
        print("HH Account 1 Balance: {} $SENT".format(self.sent_contract.balanceOf(address=self.sn_contract.hardhat_account1.address)))


        for contract_addr in self.sn_contrib_factory.deployedContracts:
            contract = SNContribContract(address=contract_addr, contract_json=sn_contrib_json)

            assert contract.operator() == self.sn_contract.hardhat_account0.address, "Operator ({}) should be deployer {}".format(contract.operator(), self.sn_contract.hardhat_account0.address)

            # NOTE: Hardhat account 0 funds the multi-contrib
            self.sent_contract.approve(sender=self.sn_contract.hardhat_account0,
                                       spender=ethereum.web3_client.to_checksum_address(contract_addr),
                                       value=int(contract_staking_requirement / 2));
            contract.contributeFunds(account=self.sn_contract.hardhat_account0,
                                     amount=int(contract_staking_requirement / 2),
                                     beneficiary=beneficiary_eth_addr)

            # NOTE: Hardhat account 1 funds the multi-contrib
            self.sent_contract.approve(sender=self.sn_contract.hardhat_account1,
                                       spender=ethereum.web3_client.to_checksum_address(contract_addr),
                                       value=int(contract_staking_requirement / 2));
            contract.contributeFunds(account=self.sn_contract.hardhat_account1,
                                     amount=int(contract_staking_requirement / 2),
                                     beneficiary=beneficiary_eth_addr)


        # Advance the Arbitrum blockchain so that the SN registration is observed in oxen
        ethereum.evm_mine()
        ethereum.evm_mine()
        ethereum.evm_mine()

        # NOTE: Log all the SNs in the contract ####################################################
        contract_sn_id_it = 0
        contract_sn_dump  = ""
        while True:
            contract_sn        = self.sn_contract.serviceNodes(contract_sn_id_it)
            contract_sn_dump  += "  SN ID {} {}\n".format(contract_sn_id_it, vars(contract_sn))
            contract_sn_id_it  = contract_sn.next
            if contract_sn_id_it == 0:
                break

        # Verify registration was successful
        contract_sn_count          = self.sn_contract.totalNodes()
        expected_contract_sn_count = prev_contract_sn_count + len(self.eth_sns)
        vprint("Added node via Eth. Contract has {} SNs\n{}".format(contract_sn_count, contract_sn_dump))
        assert contract_sn_count == expected_contract_sn_count, f"Expected {contract_sn_count} service nodes, received {expected_contract_sn_count}"

        # Sleep and let pulse quorum do work
        vprint(f"Sleeping now, awaiting pulse quorum to generate blocks (& rewards for node), blockchain height is {self.eth_sns[0].height()}");

        # Wait until the node is able to receive rewards
        total_sleep_time = 0
        sleep_time       = 8
        while self.eth_sns[0].sn_is_payable() == False:
            total_sleep_time += sleep_time
            time.sleep(sleep_time)

        # Wait 1 block to receive rewards
        target_height = self.eth_sns[0].height() + 1;
        while self.eth_sns[0].height() < target_height:
            total_sleep_time += sleep_time
            time.sleep(sleep_time)

        vprint(f"Waking up after sleeping for {total_sleep_time}s, blockchain height is {self.eth_sns[0].height()}");

        # NOTE: BLS rewards claim ##################################################################
        # Claim rewards for beneficiary
        rewards_response = self.eth_sns[0].get_bls_rewards(beneficiary_eth_addr_no_0x)
        vprint(rewards_response)
        rewardsAccount = rewards_response["result"]["address"]
        assert rewardsAccount.lower() == beneficiary_eth_addr.lower(), f"Rewards account '{rewardsAccount.lower()}' does not match beneficiary's account '{beneficiary_eth_addr_no_0x.lower()}'. We have the private key for the account and use it to claim rewards from the contract"

        vprint("Beneficiary rewards before updating has ['available', 'claimed'] respectively: ",
               self.sn_contract.recipients(beneficiary_eth_addr),
               " for ",
               beneficiary_eth_addr_no_0x)

        vprint("Foundation pool balance: {}".format(self.sent_contract.balanceOf(self.sn_contract.foundation_pool_address)))
        vprint("Rewards contract balance: {}".format(self.sent_contract.balanceOf(self.sn_contract.contract.address)))
        aggregate_pubkey = self.sn_contract.aggregatePubkey()
        vprint("Aggregate Public Key: {}, {}".format(hex(aggregate_pubkey[0]), hex(aggregate_pubkey[1])))

        # Extract binary parameters
        sig_str: str = rewards_response['result']['signature'];

        # Convert binary params to contract representation
        sig = BLSSignatureParams(
            sigs0=int(sig_str[   :64],  16),
            sigs1=int(sig_str[64 :128], 16),
            sigs2=int(sig_str[128:192], 16),
            sigs3=int(sig_str[192:256], 16),
        )

        # NOTE: Then update the rewards blaance
        self.sn_contract.updateRewardsBalance(
                recipientAddress=beneficiary_eth_addr,
                recipientAmount=rewards_response["result"]["amount"],
                blsSignature=sig,
                ids=rewards_response["result"]["non_signer_indices"])

        vprint("Beneficiary rewards update executed, has ['available', 'claimed'] now respectively: ",
               self.sn_contract.recipients(beneficiary_eth_addr),
               " for ",
               beneficiary_eth_addr_no_0x)

        vprint("Balance for '{}' before claim {}".format(beneficiary_eth_addr, self.sent_contract.balanceOf(beneficiary_eth_addr)))

        # NOTE: Now claim the rewards
        self.sn_contract.claimRewards()
        vprint("Beneficiary rewards after claim is now ['available', 'claimed'] respectively: ",
               self.sn_contract.recipients(beneficiary_eth_addr),
               " for ",
               beneficiary_eth_addr)
        vprint("Balance for '{}' after claim {}".format(beneficiary_eth_addr, self.sent_contract.balanceOf(beneficiary_eth_addr)))

        # NOTE: BLS rewards claim ##################################################################
        # Claim rewards for staker
        rewards_response = self.eth_sns[0].get_accrued_rewards([staker_eth_addr_no_0x])[0]
        vprint(vars(rewards_response))
        assert rewards_response.balance == 0, "Staker's rewards amount ({}) should be 0 because funds are being paid out to the beneficiary".format(rewards_response.balance)

        # Begin exit tests ######################################################################
        # Make a list of all the nodes, shuffle them and select 3 to remove (remove w/ wait time,
        # remove with signature and liquidate).
        sn_to_remove_indexes = []
        for i in range(len(self.eth_sns)):
            sn_to_remove_indexes.append(i)
        random.shuffle(sn_to_remove_indexes)
        sn_to_remove_indexes = sn_to_remove_indexes[:len(SNExitMode)] # First 3 (1 for each test)

        # Initiate the remove, this will put the node into a mode where it will eventually enter
        # the expired list when the L2 transaction is witnessed. (If we make the node wait long
        # enough it will also enter the liquidatable list!).
        for mode in SNExitMode:
            sn_to_remove_bls_pubkey  = self.eth_sns[sn_to_remove_indexes[mode.value]].get_service_keys().bls_pubkey
            sn_to_remove_contract_id = self.sn_contract.getServiceNodeID(sn_to_remove_bls_pubkey)

            # Initiate the remove, this will put the node into a mode where it will eventually enter
            # the expired list when the L2 transaction is witnessed. (If we make the node wait long
            # enough it will also enter the liquidatable list!).
            vprint("Initiating remove for node w/ BLS key {} (id {})".format(sn_to_remove_bls_pubkey, sn_to_remove_contract_id))
            self.sn_contract.initiateRemoveBLSPublicKey(sn_to_remove_contract_id)

            # Advance the Arbitrum blockchain so that Oxen witnesses it (remember that Oxen lags
            # behind the tip for safety! In localdev this is configured to 1 block of lag).
            ethereum.evm_mine();

        # Wait for confirmation of event(s)
        unlocks_confirmed = []
        for i in range(len(SNExitMode)):
            unlocks_confirmed.append(False)

        vprint(f"Sleeping now, waiting for confirmation of voluntary exit on Oxen, blockchain height is {self.sns[0].height()}")
        total_sleep_time            = 0
        sleep_time                  = 8
        current_height              = 0
        max_requested_unlock_height = 0
        while True:
            height = self.sns[0].height()
            if current_height != height:
                current_height = height

                unlocks_confirmed_count = 0
                for index in SNExitMode:
                    if unlocks_confirmed[index.value] == False:
                        status_json = self.eth_sns[sn_to_remove_indexes[index.value]].sn_status()
                        if status_json['service_node_state']['requested_unlock_height'] != 0:
                            max_requested_unlock_height = max(max_requested_unlock_height, status_json['service_node_state']['requested_unlock_height'])
                            unlocks_confirmed[index.value] = True

                    if unlocks_confirmed[index.value] == True:
                        unlocks_confirmed_count += 1

                if unlocks_confirmed_count >= len(SNExitMode):
                    break

            total_sleep_time += sleep_time
            time.sleep(sleep_time)

        vprint(f"Waking up after sleeping for {total_sleep_time}s, blockchain height is {self.sns[0].height()}, the latest requested unlock height is {max_requested_unlock_height}")

        vprint(f"Sleeping again until height {max_requested_unlock_height + 1} where all nodes are unlocked")
        total_sleep_time = 0
        while current_height <= max_requested_unlock_height + 1:
            current_height = self.sns[0].height()
            total_sleep_time += sleep_time
            time.sleep(sleep_time)
        vprint(f"Waking up after sleeping for {total_sleep_time}s, blockchain height is {self.sns[0].height()}, unlocks are complete")

        # Do exit via signature and liquidation, aggregate signature from network and apply it on
        # the smart contract
        for mode in SNExitMode:
            sn_to_remove_pubkey      = self.eth_sns[sn_to_remove_indexes[mode.value]].get_service_keys().pubkey
            sn_to_remove_bls_pubkey  = self.eth_sns[sn_to_remove_indexes[mode.value]].get_service_keys().bls_pubkey
            sn_to_remove_contract_id = self.sn_contract.getServiceNodeID(sn_to_remove_bls_pubkey)

            if mode == SNExitMode.WithSignature:
                exit_request = self.eth_sns[0].get_exit_liquidation_request(sn_to_remove_pubkey, liquidate=False)
                vprint("Exit request aggregated: {}".format(exit_request))
                vprint("Exit request msg to sign: {}".format(exit_request["result"]["msg_to_sign"]))

                # Extract binary parameters
                key_str: str = exit_request['result']['bls_pubkey'];
                sig_str: str = exit_request['result']['signature'];

                # Convert binary params to contract representation
                key = BLSPubkey(X=int(key_str[:64], 16), Y=int(key_str[64:128], 16))
                sig = BLSSignatureParams(
                    sigs0=int(sig_str[   :64],  16),
                    sigs1=int(sig_str[64 :128], 16),
                    sigs2=int(sig_str[128:192], 16),
                    sigs3=int(sig_str[192:256], 16),
                )

                # Invoke contract
                assert self.sn_contract.serviceNodes(sn_to_remove_contract_id).operator == staker_eth_addr
                contract_sn_count_before = self.sn_contract.totalNodes()
                self.sn_contract.removeBLSPublicKeyWithSignature(key=key,
                                                                 timestamp=exit_request["result"]["timestamp"],
                                                                 sig=sig,
                                                                 ids=exit_request["result"]["non_signer_indices"])

                contract_sn_count_after = self.sn_contract.totalNodes()
                vprint("Node count in contract after exit with signature, {} SNs (was {})".format(contract_sn_count_after, contract_sn_count_before))

                zero_account = "0x0000000000000000000000000000000000000000";
                assert self.sn_contract.serviceNodes(sn_to_remove_contract_id).operator == zero_account
                assert contract_sn_count_after  == contract_sn_count_before - 1

            elif mode == SNExitMode.Liquidation:
                # This node has initiated a voluntary leave, however if the node does not leave
                # itself, after some time period (7 days on mainnet, 1 block on localdev) the node
                # can be liquidated. This is permitted because maintaining an up-to-date SNL is
                # important for the functioning of the network.
                #
                # Hence we penalise stragglers that they should not be in the list longer than
                # necessary.
                vprint(f"Sleeping now, waiting for exit buffer to elapse to qualify node for liqudation, blockchain height is {self.sns[0].height()}")
                target_height = self.all_nodes[0].height() + 5;
                total_sleep_time = 0
                sleep_time       = 8
                while self.sns[0].height() < target_height:
                    total_sleep_time += sleep_time
                    time.sleep(sleep_time)
                vprint(f"Waking up after sleeping for {total_sleep_time}s, blockchain height is {self.sns[0].height()}")

                # Now node was supposed to exit but hasn't in a timely fashion, it can be liquidated
                exit_request = self.eth_sns[0].get_exit_liquidation_request(sn_to_remove_pubkey, liquidate=True)
                vprint("Liquidate request aggregated: {}".format(exit_request))
                vprint("Liquidate request msg to sign: {}".format(exit_request["result"]["msg_to_sign"]))

                # Extract binary parameters
                key_str: str = exit_request['result']['bls_pubkey'];
                sig_str: str = exit_request['result']['signature'];

                # Convert binary params to contract representation
                key = BLSPubkey(X=int(key_str[:64], 16), Y=int(key_str[64:128], 16))
                sig = BLSSignatureParams(
                    sigs0=int(sig_str[   :64],  16),
                    sigs1=int(sig_str[64 :128], 16),
                    sigs2=int(sig_str[128:192], 16),
                    sigs3=int(sig_str[192:256], 16),
                )

                # Advance time by 3 hrs, this is neede in the liquidation test later
                # where there's a min wait time before liquidation can occur
                ethereum.evm_increaseTime(60 * 60 * 3)
                ethereum.evm_mine();

                assert self.sn_contract.serviceNodes(sn_to_remove_contract_id).operator == staker_eth_addr
                contract_sn_count_before = self.sn_contract.totalNodes()
                self.sn_contract.liquidateBLSPublicKeyWithSignature(key=key,
                                                                    timestamp=exit_request["result"]["timestamp"],
                                                                    sig=sig,
                                                                    ids=exit_request["result"]["non_signer_indices"])
                contract_sn_count_after = self.sn_contract.totalNodes()
                vprint("Node count in contract after liquidation, {} SNs (was {})".format(contract_sn_count_after, contract_sn_count_before))

                zero_account = "0x0000000000000000000000000000000000000000";
                assert self.sn_contract.serviceNodes(sn_to_remove_contract_id).operator == zero_account
                assert contract_sn_count_after  == contract_sn_count_before - 1

            # Advance the Arbitrum blockchain so that Oxen witnesses it (remember that Oxen lags
            # behind the tip for safety! In localdev this is configured to 1 block of lag).
            ethereum.evm_mine();

        # Verify that deregistration stake is unlocked and claimable
        vprint(f"Sleeping until dereg stake is unlocked, blockchain height is {self.sns[0].height()}")
        total_sleep_time = 0
        balance_before = self.sns[0].get_accrued_rewards([staker_eth_addr_no_0x])[0].balance
        while True:
            total_sleep_time += sleep_time
            time.sleep(sleep_time)

            # TODO: Crappy heuristic to detect the stake unlock. A node
            # registered prior to the HF staked 100 $OXEN. A node after stakes
            # 120 $SENT. A deregistration (liquidation) does a tiny slash on the
            # funds so we don't exactly get the same stake back. 
            #
            # For now we just try and detect a good chunk of the funds being
            # credited by sleeping and check each height.
            balance_after     = self.sns[0].get_accrued_rewards([staker_eth_addr_no_0x])[0].balance
            change_in_balance = balance_after - balance_before
            if change_in_balance > 95:
                vprint("Stake-like change in balance {}, after {} (change {})".format(balance_before, balance_after, change_in_balance))
                break
            else:
                vprint("Balance before {}, after {} (change {})".format(balance_before, balance_after, change_in_balance))
            balance_before = balance_after

        vprint(f"Waking up after sleeping for {total_sleep_time}s, blockchain height is {self.sns[0].height()}")

        # Do remove 'after wait time' ##############################################################
        # IMPORTANT: This test must be run last because it advances the L2 blockchain by 31 days.
        # This method of exit does _not_ require a signature. The other methods require a
        # timestamp embedded in the signature. We don't have a way to manipulate timestamps on the
        # Oxen blockchain hence the signature tests are run before this test.
        #
        # This test will advance time by 31 days. A signature that is then generated by the Session
        # node will be generated but failed to be applied because the node will generate a signature
        # with the OS clock (which has _not_ been advanced by 31 days).
        days_30_in_seconds = (60 * 60 * 24 * 31)
        ethereum.evm_increaseTime(days_30_in_seconds)
        ethereum.evm_mine()


        # Remove the node from the smart contract (after 31 days has elapsed)
        for mode in SNExitMode:
            if mode == SNExitMode.AfterWaitTime:
                sn_to_remove_pubkey      = self.eth_sns[sn_to_remove_indexes[mode.value]].get_service_keys().pubkey
                sn_to_remove_bls_pubkey  = self.eth_sns[sn_to_remove_indexes[mode.value]].get_service_keys().bls_pubkey
                sn_to_remove_contract_id = self.sn_contract.getServiceNodeID(sn_to_remove_bls_pubkey)

                assert self.sn_contract.serviceNodes(sn_to_remove_contract_id).operator == staker_eth_addr
                contract_sn_count_before = self.sn_contract.totalNodes()
                self.sn_contract.removeBLSPublicKeyAfterWaitTime(sn_to_remove_contract_id)
                contract_sn_count_after = self.sn_contract.totalNodes()
                vprint("Node count in contract after wait time exit, {} SNs (was {})".format(contract_sn_count_after, contract_sn_count_before))

                zero_account = "0x0000000000000000000000000000000000000000";
                assert self.sn_contract.serviceNodes(sn_to_remove_contract_id).operator == zero_account
                assert contract_sn_count_after  == contract_sn_count_before - 1

                # Advance the Arbitrum blockchain so that Oxen witnesses it (remember that Oxen lags
                # behind the tip for safety! In localdev this is configured to 1 block of lag).
                ethereum.evm_mine();


        # Tests complete ###########################################################################
        elapsed_time = time.perf_counter() - begin_time
        vprint("Local Devnet SN network setup complete in {}s!".format(elapsed_time))
        vprint("Communicate with daemon on ip: {} port: {}".format(self.sns[0].listen_ip,self.sns[0].rpc_port))

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
        for w in self.extrawallets:
            b = w.balances(refresh=True)
            vprint("    {:5s}: {:.9f} (total) with {:.9f} (unlocked)".format(
                w.name, b[0] * 1e-9, b[1] * 1e-9))


    def __del__(self):
        for n in self.all_nodes:
            n.terminate()
        for w in self.wallets:
            w.terminate()
        if self.anvil is not None:
            self.anvil.terminate()

snn = None

def run():
    arg_parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('--oxen-bin-dir',
                            help=('Set the directory where Oxen binaries (oxend, wallet rpc, ...) '
                                  'are located.'),
                            default="../../build/bin",
                            type=pathlib.Path)
    arg_parser.add_argument('--anvil-path',
                            help=('Set the path to Foundry\'s `anvil` for launching a private '
                                  'Ethereum blockchain. If omitted a private Ethereum node must be '
                                  'running at localhost:8545.'),
                            type=pathlib.Path)
    arg_parser.add_argument('--eth-sn-contracts-dir',
                            help=('Set the path to Oxen\'s `eth-sn-contracts` repository is '
                                  'located. The script will programmatically launch and deploy the '
                                  'contracts specified via `make deploy-local`. If omitted, the '
                                  'private Ethereum blockchain must already be deployed with the '
                                  'smart contracts prior to invoking this script.'),
                            type=pathlib.Path)
    args = arg_parser.parse_args()

    if args.anvil_path is not None:
        if args.eth_sn_contracts_dir is None:
            raise RuntimeError('--eth-sn-contracts-dir must be specified when --anvil-path is set')

    atexit.register(cleanup)
    global snn, verbose
    if not snn:
        if os.path.isdir(datadirectory+'/'):
            shutil.rmtree(datadirectory+'/')
        vprint("new SNN")
        snn = SNNetwork(oxen_bin_dir=args.oxen_bin_dir,
                        anvil_path=args.anvil_path,
                        eth_sn_contracts_dir=args.eth_sn_contracts_dir,
                        datadir=datadirectory+'/')
    else:
        vprint("reusing SNN")
        snn.alice.new_wallet()
        snn.bob.new_wallet()

        # Flush pools because some tests leave behind impossible txes
        for n in snn.all_nodes:
            assert n.json_rpc("flush_txpool").json()['result']['status'] == 'OK'

        # Mine a few to clear out anything in the mempool that can be cleared
        snn.mine(5, sync=True)

        vprint("Alice has new wallet: {}".format(snn.alice.address()))
        vprint("Bob   has new wallet: {}".format(snn.bob.address()))

    input("Use Ctrl-C to exit...")
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print(f'!!! AsyncApplication.run: got KeyboardInterrupt during start')
    finally:
        loop.close()

def cleanup():
    if snn is not None and snn.anvil is not None:
        snn.anvil.terminate()

# Shortcuts for accessing the named wallets
def alice(net):
    return net.alice

def bob(net):
    return net.bob

def mike(net):
    return net.mike

if __name__ == '__main__':
    run()
