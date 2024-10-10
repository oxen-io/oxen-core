from web3 import Web3
import urllib.request
import json
from eth_typing import (
    ChecksumAddress as EthChecksumAddress,
    HexStr as EthHexStr,
)
from eth_account.types import (
    PrivateKeyType as EthPrivateKeyType
)
from eth_account.signers.local import (
    LocalAccount as EthLocalAccount,
)

PROVIDER_URL = "http://127.0.0.1:8545"

def eth_chainId():
    method = "eth_chainId"
    data = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": [],
        "id": 1
    }).encode('utf-8')

    try:
        req = urllib.request.Request(PROVIDER_URL, data=data, headers={'content-type': 'application/json'}, )
        with urllib.request.urlopen(req, timeout=2) as response:
            response      = response.read()
            response_json = json.loads(response)
            result        = int(response_json["result"], 16) # Parse chain ID from hex
    except Exception as e:
        raise RuntimeError("Failed to query {} from {}: {}".format(method, PROVIDER_URL, e))

    return result

def evm_increaseTime(web3, seconds):
    web3.provider.make_request('evm_increaseTime', [seconds])

def evm_mine(web3):
    web3.provider.make_request('evm_mine', [])

class ContractServiceNodeStaker:
    addr:        EthChecksumAddress
    beneficiary: EthChecksumAddress

class ContractServiceNodeContributor:
    staker:       ContractServiceNodeStaker = ContractServiceNodeStaker()
    stakedAmount: int = 0

class ContractServiceNode:
    next: int
    prev: int
    operator = None
    pubkey_x = None
    pubkey_y = None
    addedTimestamp: int
    leaveRequestTimestamp = None
    deposit: int
    contributors: list[ContractServiceNodeContributor] = []
    ed25519Pubkey: int

class ContractSeedServiceNode:
    def __init__(self, bls_pubkey_hex, ed25519_pubkey):
        assert len(bls_pubkey_hex) == 128, "BLS pubkey must be 128 hex characters consisting of a 64 byte X & Y component"
        assert len(ed25519_pubkey) == 64, "Ed25519 pubkey must be 64 hex characters consisting of a 32 byte X & Y component"
        self.bls_pubkey     = bls_pubkey_hex
        self.ed25519_pubkey = ed25519_pubkey
        self.contributors   = []

class ServiceNodeRewardContract:
    def __init__(self,
                 sn_rewards_json:       dict,
                 reward_rate_pool_json: dict,
                 erc20_contract_json:   dict):

        assert 'abi' in sn_rewards_json,       "JSON missing ABI: {}".format(sn_rewards_json)
        assert 'abi' in reward_rate_pool_json, "JSON missing ABI: {}".format(reward_rate_pool_json)
        assert 'abi' in erc20_contract_json,   "JSON missing ABI: {}".format(erc20_contract_json)

        self.provider_url = PROVIDER_URL
        self.web3         = Web3(Web3.HTTPProvider(self.provider_url))

        self.hardhat_skey0:    EthPrivateKeyType = EthHexStr('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
        self.hardhat_skey1:    EthPrivateKeyType = EthHexStr('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
        self.hardhat_account0: EthLocalAccount   = self.web3.eth.account.from_key(self.hardhat_skey0)
        self.hardhat_account1: EthLocalAccount   = self.web3.eth.account.from_key(self.hardhat_skey1)

        self.contract_address = self.getContractDeployedInLatestBlock()
        self.contract         = self.web3.eth.contract(address=self.contract_address, abi=sn_rewards_json["abi"])

        self.foundation_pool_address  = self.contract.functions.foundationPool().call();
        self.foundation_pool_contract = self.web3.eth.contract(address=self.foundation_pool_address, abi=reward_rate_pool_json["abi"])

        # NOTE: Setup ERC20 contract
        self.erc20_address  = self.contract.functions.designatedToken().call()
        self.erc20_contract = self.web3.eth.contract(address=self.erc20_address, abi=erc20_contract_json["abi"])

        # NOTE: Approve an amount to be sent from the hardhat account to the contract
        unsent_tx = self.erc20_contract.functions.approve(self.contract_address, 1_5001_000_000_000_000_000_000).build_transaction({
            'from': self.hardhat_account0.address,
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        # SENT Contract Address deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3
        address_check_err_msg = ('If this assert triggers, the rewards contract ABI has been '
        'changed OR we\'re reusing a wallet and creating the contract with a different nonce. The '
        'ABI in this script is hardcoded to the instance of the contract with that hash. Verify '
        'and re-update the ABI if necessary and any auxiliary contracts if the ABI has changed or '
        'that the wallets are _not_ being reused.')

        assert self.contract_address.lower()        == '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707'.lower(), (f'{address_check_err_msg}\n\nAddress was: {self.contract_address}')
        assert self.foundation_pool_address.lower() == '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0'.lower(), (f'{address_check_err_msg}\n\nAddress was: {self.foundation_pool_address}')

    def call_function(self, function_name, *args, **kwargs):
        contract_function = self.contract.functions[function_name](*args)
        return contract_function.call(**kwargs)

    def start(self):
        unsent_tx = self.contract.functions.start().build_transaction({
            "from": self.hardhat_account0.address,
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)

    # Add more methods as needed to interact with the smart contract
    def getContractDeployedInLatestBlock(self):
        latest_block = self.web3.eth.get_block('latest')

        for tx_hash in latest_block['transactions']:
            try:
                tx_receipt = self.web3.eth.get_transaction_receipt(tx_hash)
                if tx_receipt.contractAddress:
                    return tx_receipt.contractAddress
            except TransactionNotFound:
                continue

        raise RuntimeError("No contracts deployed in latest block")

    def erc20balance(self, address):
        return self.erc20_contract.functions.balanceOf(Web3.to_checksum_address(address)).call()

    def stakingRequirement(self):
        return self.contract.functions.stakingRequirement().call()

    def aggregatePubkey(self):
        return self.contract.functions.aggregatePubkey().call()

    def submitSignedTX(self, tx_label, signed_tx):
        result     = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(result)
        self.web3.eth.wait_for_transaction_receipt(result)

        if tx_receipt["status"] == 0:
            # build a new transaction to replay:
            tx_to_replay = self.web3.eth.get_transaction(result)
            replay_tx = {
                'to':    tx_to_replay['to'],
                'from':  tx_to_replay['from'],
                'value': tx_to_replay['value'],
                'data':  tx_to_replay['input'],
            }

            try: # replay the transaction locally:
                self.web3.eth.call(replay_tx, tx_to_replay.blockNumber - 1)
            except Exception as e:
                print(f"{tx_label} TX {result} reverted {e}")

        return result

    def addBLSPublicKey(self, bls_pubkey: dict, bls_sig: dict, sn_params: dict, contributors: list[dict]):
        # function addBLSPublicKey(BN256G1.G1Point blsPubkey, BLSSignatureParams blsSignature, ServiceNodeParams serviceNodeParams, Contributor[] contributors)
        unsent_tx = self.contract.functions.addBLSPublicKey(bls_pubkey,
                                                            bls_sig,
                                                            sn_params,
                                                            contributors).build_transaction({
                        "from": self.hardhat_account0.address,
                        'gas': 2000000,
                        'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = self.submitSignedTX("Add BLS public key", signed_tx)
        return tx_hash

    def initiateRemoveBLSPublicKey(self, service_node_id):
        # function initiateRemoveBLSPublicKey(uint64 serviceNodeID) public
        unsent_tx = self.contract.functions.initiateRemoveBLSPublicKey(service_node_id
                    ).build_transaction({
                        "from": self.hardhat_account0.address,
                        'gas': 2000000,
                        'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = self.submitSignedTX("Remove BLS public key", signed_tx)
        return tx_hash

    def removeBLSPublicKeyWithSignature(self, bls_pubkey, timestamp, blsSig, ids):
        bls_pubkey = {
            'X': int(bls_pubkey[:64],    16),
            'Y': int(bls_pubkey[64:128], 16),
        }

        bls_signature = {
            'sigs0': int(blsSig[   :64],  16),
            'sigs1': int(blsSig[64 :128], 16),
            'sigs2': int(blsSig[128:192], 16),
            'sigs3': int(blsSig[192:256], 16),
        }

        unsent_tx = self.contract.functions.removeBLSPublicKeyWithSignature(bls_pubkey, timestamp, bls_signature, ids).build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = self.submitSignedTX("Remove BLS public key w/ signature", signed_tx)
        return tx_hash

    def removeBLSPublicKeyAfterWaitTime(self, serviceNodeID: int):
        unsent_tx = self.contract.functions.removeBLSPublicKeyAfterWaitTime(serviceNodeID).build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = self.submitSignedTX("Remove BLS public key after wait time", signed_tx)
        return tx_hash

    def liquidateBLSPublicKeyWithSignature(self, bls_pubkey, timestamp, bls_sig, ids):
        contract_bls_pubkey = {
            'X': int(bls_pubkey[:64],    16),
            'Y': int(bls_pubkey[64:128], 16),
        }

        contract_bls_sig = {
            'sigs0': int(bls_sig[   :64],  16),
            'sigs1': int(bls_sig[64 :128], 16),
            'sigs2': int(bls_sig[128:192], 16),
            'sigs3': int(bls_sig[192:256], 16),
        }

        unsent_tx = self.contract.functions.liquidateBLSPublicKeyWithSignature(
            contract_bls_pubkey,
            timestamp,
            contract_bls_sig,
            ids
        ).build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = self.submitSignedTX("Liquidate BLS public key w/ signature", signed_tx)
        return tx_hash

    def seedPublicKeyList(self, seed_nodes):
        contract_seed_nodes = []
        for item in seed_nodes:
            entry = {
                'blsPubkey': {
                    'X': int(item.bls_pubkey[:64],    16),
                    'Y': int(item.bls_pubkey[64:128], 16),
                },
                'ed25519Pubkey': int(item.ed25519_pubkey[:32], 16),
                'contributors': [],
            }

            for contributor in item.contributors:
                use_contributor_v1 = False

                if use_contributor_v1:
                    entry['contributors'].append({
                        'addr':         contributor.staker.addr,
                        'stakedAmount': contributor.stakedAmount,
                    })

                else:
                    entry['contributors'].append({
                        'staker': {
                            'addr':        contributor.staker.addr,
                            'beneficiary': contributor.staker.beneficiary,
                        },
                        'stakedAmount': contributor.stakedAmount,
                    })

            contract_seed_nodes.append(entry)

        print(contract_seed_nodes)

        unsent_tx = self.contract.functions.seedPublicKeyList(contract_seed_nodes).build_transaction({
            "from":  self.hardhat_account0.address,
            'gas':   6000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash   = self.submitSignedTX("Seed public key list", signed_tx)
        return tx_hash

    def numberServiceNodes(self):
        return self.contract.functions.serviceNodesLength().call()

    def recipients(self, address):
        return self.contract.functions.recipients(address).call()

    def updateRewardsBalance(self, recipientAddress, recipientAmount, blsSig, ids):
        sig_param = {
                'sigs0': int(blsSig[:64], 16),
                'sigs1': int(blsSig[64:128], 16),
                'sigs2': int(blsSig[128:192], 16),
                'sigs3': int(blsSig[192:256], 16),
        }
        unsent_tx = self.contract.functions.updateRewardsBalance(
            Web3.to_checksum_address(recipientAddress),
            recipientAmount,
            sig_param,
            ids
        ).build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = self.submitSignedTX("Update rewards balance", signed_tx)
        return tx_hash


    def claimRewards(self):
        unsent_tx = self.contract.functions.claimRewards().build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 2000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = self.submitSignedTX("Claim rewards", signed_tx)
        return tx_hash

    def getServiceNodeID(self, bls_public_key):
        service_node_end_id = 2**64-1
        service_node_end = self.contract.functions.serviceNodes(service_node_end_id).call()
        service_node_id = service_node_end[0]
        while True:
            service_node = self.contract.functions.serviceNodes(service_node_id).call()
            if hex(service_node[3][0])[2:].zfill(64) + hex(service_node[3][1])[2:].zfill(64) == bls_public_key:
                return service_node_id
            service_node_id = service_node[0]
            if service_node_id == service_node_end_id:
                raise Exception("Iterated through smart contract list and could not find bls key")

    def getNonSigners(self, bls_public_keys):
        service_node_end_id = 0
        service_node_end = self.contract.functions.serviceNodes(service_node_end_id).call()
        service_node_id = service_node_end[0]
        non_signers = []
        while service_node_id != service_node_end_id:
            service_node = self.contract.functions.serviceNodes(service_node_id).call()
            bls_key = hex(service_node[3][0])[2:].zfill(64) + hex(service_node[3][1])[2:].zfill(64)
            if bls_key not in bls_public_keys:
                non_signers.append(service_node_id)
            service_node_id = service_node[0]
        return non_signers

    def serviceNodes(self, u64_id):
        call_result                  = self.contract.functions.serviceNodes(u64_id).call()
        result                       = ContractServiceNode()
        index                        = 0;

        result.next                  = call_result[index]
        index += 1;

        result.prev                  = call_result[index]
        index += 1;

        result.operator              = call_result[index]
        index += 1;

        result.pubkey_x              = call_result[index][0]
        result.pubkey_y              = call_result[index][1]
        index += 1;

        result.addedTimestamp        = call_result[index]
        index += 1;

        result.leaveRequestTimestamp = call_result[index]
        index += 1;

        result.deposit               = call_result[index]
        index += 1;

        result.contributors          = call_result[index]
        index += 1;

        result.ed25519Pubkey         = call_result[index]
        index += 1;

        return result

