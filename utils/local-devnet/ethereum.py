import web3
from web3.types import (
    TxParams as EthTxParams
)
import urllib.request
import json
from eth_typing import (
    ChecksumAddress as EthChecksumAddress,
    HexStr as EthHexStr,
    HexAddress as EthHexAddress,
)
from eth_account.datastructures import (
    SignedTransaction as EthSignedTransaction,
)
from eth_account.signers.local import (
    LocalAccount as EthLocalAccount,
)

# Globals ##########################################################################################
provider_url = "http://127.0.0.1:8545"
web3_client  = web3.Web3(web3.Web3.HTTPProvider(provider_url))

# PODs #############################################################################################
class ContractServiceNodeStaker:
    addr:        EthChecksumAddress
    beneficiary: EthChecksumAddress
    def __init__(self, addr, beneficiary):
        self.addr        = addr
        self.beneficiary = beneficiary

class ContractServiceNodeContributor:
    staker:       ContractServiceNodeStaker
    stakedAmount: int = 0
    def __init__(self, staker, stakedAmount):
        self.staker       = staker
        self.stakedAmount = stakedAmount

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

class BLSPubkey:
    X: int
    Y: int
    def __init__(self, X: int, Y: int):
        self.X = X
        self.Y = Y

class BLSSignatureParams:
    sigs0: int
    sigs1: int
    sigs2: int
    sigs3: int
    def __init__(self, sigs0: int, sigs1: int, sigs2: int, sigs3: int):
        self.sigs0 = sigs0
        self.sigs1 = sigs1
        self.sigs2 = sigs2
        self.sigs3 = sigs3

class ServiceNodeParams:
    serviceNodePubkey:     int # 32 bytes of ed25519 public key
    serviceNodeSignature1: int # Bytes [ 0:32] of ed25519 signature
    serviceNodeSignature2: int # Bytes [32:64] of ed25519 signature
    fee:                   int # Operator fee [0,1000]
    def __init__(self, serviceNodePubkey: int, serviceNodeSignature1: int, serviceNodeSignature2: int, fee: int):
        assert fee >= 0 and fee <= 1000
        self.serviceNodePubkey     = serviceNodePubkey
        self.serviceNodeSignature1 = serviceNodeSignature1
        self.serviceNodeSignature2 = serviceNodeSignature2
        self.fee                   = fee


class ReservedContributor:
    addr:   EthHexAddress # Address to reserve a contribution slot for
    amount: int           # Amount that the contributor has reserved
    def __init__(self, addr: EthHexAddress, amount: int):
        self.addr   = addr
        self.amount = amount

class ContractSeedServiceNode:
    def __init__(self, bls_pubkey_hex, ed25519_pubkey):
        assert len(bls_pubkey_hex) == 128, "BLS pubkey must be 128 hex characters consisting of a 64 byte X & Y component"
        assert len(ed25519_pubkey) == 64, "Ed25519 pubkey must be 64 hex characters consisting of a 32 byte X & Y component"
        self.bls_pubkey     = bls_pubkey_hex
        self.ed25519_pubkey = ed25519_pubkey
        self.contributors   = []

# Helper Functions #################################################################################
def basic_build_tx_params(account: EthLocalAccount, gas=3000000) -> EthTxParams:
    result: EthTxParams = {
        "from":  account.address,
        'gas':   gas,
        'nonce': web3_client.eth.get_transaction_count(account.address)
    }
    return result

def submit_signed_tx(tx_label: str, signed_tx: EthSignedTransaction):
    tx_hash    = web3_client.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_receipt = web3_client.eth.wait_for_transaction_receipt(tx_hash)
    web3_client.eth.wait_for_transaction_receipt(tx_hash)

    # NOTE: If the TX failed, replay the TX locally and catch the error to log
    # to the user
    if tx_receipt["status"] == 0:
        # build a new transaction to replay:
        tx_to_replay = web3_client.eth.get_transaction(result)
        replay_tx = {
            'to':    tx_to_replay['to'],
            'from':  tx_to_replay['from'],
            'value': tx_to_replay['value'],
            'data':  tx_to_replay['input'],
        }

        try: # replay the transaction locally:
            web3_client.eth.call(replay_tx, tx_to_replay.blockNumber - 1)
        except Exception as e:
            print(f"{tx_label} TX {result} reverted {e}")

    return tx_hash

def submit_unsigned_tx(tx_label: str, account: EthLocalAccount, built_tx):
    signed_tx = web3_client.eth.account.sign_transaction(built_tx, private_key=account.key)
    return submit_signed_tx(tx_label, signed_tx)

def eth_chainId():
    method = "eth_chainId"
    data = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": [],
        "id": 1
    }).encode('utf-8')

    try:
        req = urllib.request.Request(provider_url, data=data, headers={'content-type': 'application/json'}, )
        with urllib.request.urlopen(req, timeout=2) as response:
            response      = response.read()
            response_json = json.loads(response)
            result        = int(response_json["result"], 16) # Parse chain ID from hex
    except Exception as e:
        raise RuntimeError("Failed to query {} from {}: {}".format(method, provider_url, e))

    return result

def evm_increaseTime(seconds):
    web3_client.provider.make_request('evm_increaseTime', [seconds])

def evm_mine():
    web3_client.provider.make_request('evm_mine', [])

# Classes ##########################################################################################
class ServiceNodeContributionFactoryContract:
    deployedContracts: list[EthHexAddress] = []

    def __init__(self, contract_json: dict): # NOTE: Load the (deterministically hardhat deployed) contract
        self.contract = web3_client.eth.contract(address=web3_client.to_checksum_address(EthHexStr('0x0165878A594ca255338adfa4d48449f69242Eb8F')), abi=contract_json["abi"])

    def deploy(self,
               account:         EthLocalAccount,
               key:             BLSPubkey,
               sig:             BLSSignatureParams,
               params:          ServiceNodeParams,
               reserved:        list[ReservedContributor],
               manual_finalize: bool) -> EthChecksumAddress:

        reserved_array: list[tuple[EthHexAddress, int]] = []
        for item in reserved:
            reserved_array.append(
                (item.addr, int(item.amount))
            )

        unsent_tx = self.contract.functions.deploy(
            (key.X, key.Y),
            (sig.sigs0, sig.sigs1, sig.sigs2, sig.sigs3),
            (params.serviceNodePubkey, params.serviceNodeSignature1, params.serviceNodeSignature2, params.fee),
            reserved_array,
            manual_finalize
        ).build_transaction(basic_build_tx_params(account=account, gas=6000000));

        tx_hash    = submit_unsigned_tx("Deploy multi-contribution contract", account, unsent_tx)
        tx_receipt = web3_client.eth.wait_for_transaction_receipt(tx_hash)
        event_logs = self.contract.events.NewServiceNodeContributionContract().process_receipt(tx_receipt)

        assert len(event_logs) == 1, "Deploy generated {} events, {}".format(len(event_logs), tx_receipt)
        for event in event_logs:
            print("New event found! ".format(event))
            print(f"  Contract Address: {event['args']['contributorContract']}")
            print(f"  Service Node Public Key: {event['args']['serviceNodePubkey']}")

        result = web3_client.to_checksum_address(event_logs[0]['args']['contributorContract'])
        self.deployedContracts.append(result)
        return result

class ServiceNodeContributionContract:
    def __init__(self, address: EthHexAddress, contract_json: dict): # NOTE: Load the (deterministically hardhat deployed) contract
        self.contract = web3_client.eth.contract(address=web3_client.to_checksum_address(address), abi=contract_json["abi"])

    def updateFee(self, account: EthLocalAccount, fee: int):
        unsent_tx = self.contract.functions.updateFee(fee).build_transaction(basic_build_tx_params(account))
        tx_hash   = submit_unsigned_tx("Update fee", account, unsent_tx)
        return tx_hash

    def updateBeneficiary(self, account: EthLocalAccount, newBeneficiary: EthChecksumAddress):
        unsent_tx = self.contract.functions.updateBeneficiary(newBeneficiary).build_transaction(basic_build_tx_params(account))
        tx_hash   = submit_unsigned_tx("Update beneficiary, ", account, unsent_tx);
        return tx_hash

    def contributeFunds(self, account: EthLocalAccount, amount: int, beneficiary: EthChecksumAddress):
        unsent_tx = self.contract.functions.contributeFunds(amount, beneficiary).build_transaction(basic_build_tx_params(account))
        tx_hash   = submit_unsigned_tx("Contribute funds", account, unsent_tx)
        return tx_hash

    def finalize(self, account: EthLocalAccount):
        unsent_tx = self.contract.functions.finalize().build_transaction(basic_build_tx_params(account))
        tx_hash   = submit_unsigned_tx("Finalize", account, unsent_tx)
        return tx_hash

    def reset(self, account: EthLocalAccount):
        unsent_tx = self.contract.functions.reset().build_transaction(basic_build_tx_params(account))
        tx_hash   = submit_unsigned_tx("Reset", account, unsent_tx)
        return tx_hash

    def withdrawContribution(self, account: EthLocalAccount):
        unsent_tx = self.contract.functions.reset().build_transaction(basic_build_tx_params(account))
        tx_hash   = submit_unsigned_tx("Reset", account, unsent_tx)
        return tx_hash

class SENTContract:
    def __init__(self,
                 contract_json: dict):
        assert 'abi' in contract_json, "JSON missing ABI: {}".format(contract_json)
        self.contract = web3_client.eth.contract(address=web3_client.to_checksum_address('0x5FbDB2315678afecb367f032d93F642f64180aa3'), abi=contract_json["abi"])

    def approve(self,
                sender: EthLocalAccount,
                address: EthChecksumAddress,
                amount: int):
        unsent_tx = self.contract.functions.approve(address, amount).build_transaction(basic_build_tx_params(sender))
        submit_unsigned_tx("SENT approval", sender, unsent_tx);

    def balanceOf(self, address: EthChecksumAddress):
        return self.contract.functions.balanceOf(web3_client.to_checksum_address(address)).call()

class ServiceNodeRewardContract:
    def __init__(self,
                 sn_rewards_json:       dict,
                 reward_rate_pool_json: dict):

        assert 'abi' in sn_rewards_json,       "JSON missing ABI: {}".format(sn_rewards_json)
        assert 'abi' in reward_rate_pool_json, "JSON missing ABI: {}".format(reward_rate_pool_json)

        self.hardhat_skey0:    EthHexStr       = EthHexStr('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
        self.hardhat_skey1:    EthHexStr       = EthHexStr('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
        self.hardhat_account0: EthLocalAccount = web3_client.eth.account.from_key(self.hardhat_skey0)
        self.hardhat_account1: EthLocalAccount = web3_client.eth.account.from_key(self.hardhat_skey1)

        # NOTE: Load the rewards contract ##########################################################
        # NOTE: Deterministic contract address
        self.contract = web3_client.eth.contract(address=EthChecksumAddress(EthHexAddress(EthHexStr('0x5FC8d32690cc91D4c39d9d3abcBD16989F875707'))),
                                                 abi=sn_rewards_json["abi"])

        self.foundation_pool_address  = self.contract.functions.foundationPool().call();
        self.foundation_pool_contract = web3_client.eth.contract(address=self.foundation_pool_address, abi=reward_rate_pool_json["abi"])


        address_check_err_msg = ('If this assert triggers, the rewards contract ABI has been '
        'changed OR we\'re reusing a wallet and creating the contract with a different nonce. The '
        'ABI in this script is hardcoded to the instance of the contract with that hash. Verify '
        'and re-update the ABI if necessary and any auxiliary contracts if the ABI has changed or '
        'that the wallets are _not_ being reused.')
        assert self.foundation_pool_address.lower() == '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0'.lower(), (f'{address_check_err_msg}\n\nAddress was: {self.foundation_pool_address}')

    def start(self):
        unsent_tx = self.contract.functions.start().build_transaction(basic_build_tx_params(self.hardhat_account0))
        submit_unsigned_tx("Start SN rewards", self.hardhat_account0, unsent_tx);

    def stakingRequirement(self):
        return self.contract.functions.stakingRequirement().call()

    def aggregatePubkey(self):
        return self.contract.functions.aggregatePubkey().call()

    def addBLSPublicKey(self,
                        key:          BLSPubkey,
                        sig:          BLSSignatureParams,
                        params:       ServiceNodeParams,
                        contributors: list[ContractServiceNodeContributor]):
        # function addBLSPublicKey(BN256G1.G1Point blsPubkey, BLSSignatureParams blsSignature, ServiceNodeParams serviceNodeParams, Contributor[] contributors)
        contributors_array: list[tuple[tuple[EthHexAddress, EthHexAddress], int]] = []
        for item in contributors:
            contributors_array.append(
                (
                    (item.staker.addr, item.staker.beneficiary),
                    item.stakedAmount
                )
            )

        unsent_tx = self.contract.functions.addBLSPublicKey(
            (key.X, key.Y),
            (sig.sigs0, sig.sigs1, sig.sigs2, sig.sigs3),
            (params.serviceNodePubkey, params.serviceNodeSignature1, params.serviceNodeSignature2, params.fee),
            contributors_array
        ).build_transaction(basic_build_tx_params(self.hardhat_account0))

        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = submit_signed_tx("Add BLS public key", signed_tx)
        return tx_hash

    def initiateRemoveBLSPublicKey(self, service_node_id):
        # function initiateRemoveBLSPublicKey(uint64 serviceNodeID) public
        unsent_tx = self.contract.functions.initiateRemoveBLSPublicKey(service_node_id
                    ).build_transaction({
                        "from": self.hardhat_account0.address,
                        'gas': 2000000,
                        'nonce': web3_client.eth.get_transaction_count(self.hardhat_account0.address)})
        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = submit_signed_tx("Remove BLS public key", signed_tx)
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
            'nonce': web3_client.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = submit_signed_tx("Remove BLS public key w/ signature", signed_tx)
        return tx_hash

    def removeBLSPublicKeyAfterWaitTime(self, serviceNodeID: int):
        unsent_tx = self.contract.functions.removeBLSPublicKeyAfterWaitTime(serviceNodeID).build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': web3_client.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = submit_signed_tx("Remove BLS public key after wait time", signed_tx)
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
            'nonce': web3_client.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = submit_signed_tx("Liquidate BLS public key w/ signature", signed_tx)
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
            'nonce': web3_client.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash   = submit_signed_tx("Seed public key list", signed_tx)
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
            web3_client.to_checksum_address(recipientAddress),
            recipientAmount,
            sig_param,
            ids
        ).build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': web3_client.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = submit_signed_tx("Update rewards balance", signed_tx)
        return tx_hash


    def claimRewards(self):
        unsent_tx = self.contract.functions.claimRewards().build_transaction({
            "from": self.hardhat_account0.address,
            'gas': 2000000,  # Adjust gas limit as necessary
            'nonce': web3_client.eth.get_transaction_count(self.hardhat_account0.address)
        })
        signed_tx = web3_client.eth.account.sign_transaction(unsent_tx, private_key=self.hardhat_account0.key)
        tx_hash = submit_signed_tx("Claim rewards", signed_tx)
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

