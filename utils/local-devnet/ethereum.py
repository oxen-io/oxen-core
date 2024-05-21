from web3 import Web3
import json

class ServiceNodeRewardContract:
    def __init__(self):
        self.provider_url = "http://127.0.0.1:8545"
        self.private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Hardhat account #0
        self.web3 = Web3(Web3.HTTPProvider(self.provider_url))
        self.contract_address = self.getContractDeployedInLatestBlock()
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=contract_abi)
        self.acc = self.web3.eth.account.from_key(self.private_key)
        unsent_tx = self.contract.functions.start().build_transaction({
            "from": self.acc.address,
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.erc20_address = self.contract.functions.designatedToken().call()
        self.erc20_contract = self.web3.eth.contract(address=self.erc20_address, abi=erc20_contract_abi)
        unsent_tx = self.erc20_contract.functions.approve(self.contract_address, 15001000000000000000000).build_transaction({
            "from": self.acc.address,
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)

    def call_function(self, function_name, *args, **kwargs):
        contract_function = self.contract.functions[function_name](*args)
        return contract_function.call(**kwargs)

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

    def hardhatAccountAddress(self):
        return self.acc.address

    def erc20balance(self, address):
        return self.erc20_contract.functions.balanceOf(Web3.to_checksum_address(address)).call()

    def addBLSPublicKey(self, args):
        # function addBLSPublicKey(uint256 pkX, uint256 pkY, uint256 sigs0, uint256 sigs1, uint256 sigs2, uint256 sigs3, uint256 serviceNodePubkey, uint256 serviceNodeSignature) public {
        bls_param = {
                'X': int(args["bls_pubkey"][:64], 16),
                'Y': int(args["bls_pubkey"][64:128], 16),
        }
        sig_param = {
                'sigs0': int(args["proof_of_possession"][:64], 16),
                'sigs1': int(args["proof_of_possession"][64:128], 16),
                'sigs2': int(args["proof_of_possession"][128:192], 16),
                'sigs3': int(args["proof_of_possession"][192:256], 16),
        }
        service_node_params = {
                'serviceNodePubkey': int(args["service_node_pubkey"], 16),
                'serviceNodeSignature1': int(args["service_node_signature"][:64], 16),
                'serviceNodeSignature2': int(args["service_node_signature"][64:128], 16),
                'fee': int(0),
                }
        contributors = []
        unsent_tx = self.contract.functions.addBLSPublicKey(bls_param, sig_param, service_node_params, contributors).build_transaction({
                        "from": self.acc.address,
                        'gas': 2000000,
                        'nonce': self.web3.eth.get_transaction_count(self.acc.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash

    def initiateRemoveBLSPublicKey(self, service_node_id):
        # function initiateRemoveBLSPublicKey(uint64 serviceNodeID) public {

        unsent_tx = self.contract.functions.initiateRemoveBLSPublicKey(service_node_id
                    ).build_transaction({
                        "from": self.acc.address,
                        'gas': 2000000,
                        'nonce': self.web3.eth.get_transaction_count(self.acc.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash

    def removeBLSPublicKeyWithSignature(self, blsKey, blsSig, ids):
        unsent_tx = self.contract.functions.removeBLSPublicKeyWithSignature(
            self.getServiceNodeID(blsKey),
            int(blsKey[:64], 16),
            int(blsKey[64:128], 16),
            int(blsSig[:64], 16),
            int(blsSig[64:128], 16),
            int(blsSig[128:192], 16),
            int(blsSig[192:256], 16),
            ids
        ).build_transaction({
            "from": self.acc.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash

    def liquidateBLSPublicKeyWithSignature(self, blsKey, blsSig, ids):
        unsent_tx = self.contract.functions.liquidateBLSPublicKeyWithSignature(
            self.getServiceNodeID(blsKey),
            int(blsKey[:64], 16),
            int(blsKey[64:128], 16),
            int(blsSig[:64], 16),
            int(blsSig[64:128], 16),
            int(blsSig[128:192], 16),
            int(blsSig[192:256], 16),
            ids
        ).build_transaction({
            "from": self.acc.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash

    def seedPublicKeyList(self, args):
        pkX = []
        pkY = []
        amounts = []
        for item in args:
            pkX.append(int(item[0][:64], 16))  # First 32 bytes as pkX
            pkY.append(int(item[0][64:], 16))  # Last 32 bytes as pkY
            amounts.append(item[1])  # Corresponding amount

        unsent_tx = self.contract.functions.seedPublicKeyList(pkX, pkY, amounts).build_transaction({
            "from": self.acc.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash

    def numberServiceNodes(self):
        return self.contract.functions.serviceNodesLength().call()

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
            "from": self.acc.address,
            'gas': 3000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash

    def claimRewards(self):
        unsent_tx = self.contract.functions.claimRewards().build_transaction({
            "from": self.acc.address,
            'gas': 2000000,  # Adjust gas limit as necessary
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)
        })
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
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
        return non_signers;





contract_abi = json.loads("""
[
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "target",
          "type": "address"
        }
      ],
      "name": "AddressEmptyCode",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "AddressInsufficientBalance",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "ArrayLengthMismatch",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "BLSPubkeyAlreadyExists",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "BLSPubkeyDoesNotMatch",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "ContractAlreadyActive",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "ContractNotActive",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "required",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "provided",
          "type": "uint256"
        }
      ],
      "name": "ContributionTotalMismatch",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "DeleteSentinelNodeNotAllowed",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        }
      ],
      "name": "EarlierLeaveRequestMade",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "EnforcedPause",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "ExpectedPause",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "FailedInnerCall",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "operator",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "contributor",
          "type": "address"
        }
      ],
      "name": "FirstContributorMismatch",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "numSigners",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "requiredSigners",
          "type": "uint256"
        }
      ],
      "name": "InsufficientBLSSignatures",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "InvalidBLSProofOfPossession",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "InvalidBLSSignature",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "InvalidInitialization",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "internalType": "uint256",
          "name": "timestamp",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "currenttime",
          "type": "uint256"
        }
      ],
      "name": "LeaveRequestTooEarly",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "NotInitializing",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "NullRecipient",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "owner",
          "type": "address"
        }
      ],
      "name": "OwnableInvalidOwner",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "OwnableUnauthorizedAccount",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "expectedRecipient",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "providedRecipient",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "serviceNodeID",
          "type": "uint256"
        }
      ],
      "name": "RecipientAddressDoesNotMatch",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "RecipientRewardsTooLow",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "token",
          "type": "address"
        }
      ],
      "name": "SafeERC20FailedOperation",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "ServiceNodeDoesntExist",
      "type": "error"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "newMax",
          "type": "uint256"
        }
      ],
      "name": "BLSNonSignerThresholdMaxUpdated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "version",
          "type": "uint64"
        }
      ],
      "name": "Initialized",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "NewSeededServiceNode",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "serviceNodePubkey",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "serviceNodeSignature1",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "serviceNodeSignature2",
              "type": "uint256"
            },
            {
              "internalType": "uint16",
              "name": "fee",
              "type": "uint16"
            }
          ],
          "indexed": false,
          "internalType": "struct IServiceNodeRewards.ServiceNodeParams",
          "name": "serviceNode",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "address",
              "name": "addr",
              "type": "address"
            },
            {
              "internalType": "uint256",
              "name": "stakedAmount",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct IServiceNodeRewards.Contributor[]",
          "name": "contributors",
          "type": "tuple[]"
        }
      ],
      "name": "NewServiceNode",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "previousOwner",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "newOwner",
          "type": "address"
        }
      ],
      "name": "OwnershipTransferStarted",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "previousOwner",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "newOwner",
          "type": "address"
        }
      ],
      "name": "OwnershipTransferred",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "Paused",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "recipientAddress",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "previousBalance",
          "type": "uint256"
        }
      ],
      "name": "RewardsBalanceUpdated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "recipientAddress",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        }
      ],
      "name": "RewardsClaimed",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "ServiceNodeLiquidated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "returnedAmount",
          "type": "uint256"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "ServiceNodeRemoval",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "ServiceNodeRemovalRequest",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "newRequirement",
          "type": "uint256"
        }
      ],
      "name": "StakingRequirementUpdated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "Unpaused",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "IsActive",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "LIST_SENTINEL",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "MAX_SERVICE_NODE_REMOVAL_WAIT_TIME",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_aggregatePubkey",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "X",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "Y",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "acceptOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "internalType": "struct BN256G1.G1Point",
          "name": "blsPubkey",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "sigs0",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs1",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs2",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs3",
              "type": "uint256"
            }
          ],
          "internalType": "struct IServiceNodeRewards.BLSSignatureParams",
          "name": "blsSignature",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "serviceNodePubkey",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "serviceNodeSignature1",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "serviceNodeSignature2",
              "type": "uint256"
            },
            {
              "internalType": "uint16",
              "name": "fee",
              "type": "uint16"
            }
          ],
          "internalType": "struct IServiceNodeRewards.ServiceNodeParams",
          "name": "serviceNodeParams",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "address",
              "name": "addr",
              "type": "address"
            },
            {
              "internalType": "uint256",
              "name": "stakedAmount",
              "type": "uint256"
            }
          ],
          "internalType": "struct IServiceNodeRewards.Contributor[]",
          "name": "contributors",
          "type": "tuple[]"
        }
      ],
      "name": "addBLSPublicKey",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "aggregatePubkey",
      "outputs": [
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "internalType": "struct BN256G1.G1Point",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "blsNonSignerThreshold",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "blsNonSignerThresholdMax",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "claimRewards",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "designatedToken",
      "outputs": [
        {
          "internalType": "contract IERC20",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "foundationPool",
      "outputs": [
        {
          "internalType": "contract IERC20",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "token_",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "foundationPool_",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "stakingRequirement_",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "liquidatorRewardRatio_",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "poolShareOfLiquidationRatio_",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "recipientRatio_",
          "type": "uint256"
        }
      ],
      "name": "initialize",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "initiateRemoveBLSPublicKey",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "internalType": "struct BN256G1.G1Point",
          "name": "blsPubkey",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "sigs0",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs1",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs2",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs3",
              "type": "uint256"
            }
          ],
          "internalType": "struct IServiceNodeRewards.BLSSignatureParams",
          "name": "blsSignature",
          "type": "tuple"
        },
        {
          "internalType": "uint64[]",
          "name": "ids",
          "type": "uint64[]"
        }
      ],
      "name": "liquidateBLSPublicKeyWithSignature",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "liquidateTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "liquidatorRewardRatio",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "nextServiceNodeID",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "owner",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "pause",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "paused",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "pendingOwner",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "poolShareOfLiquidationRatio",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "proofOfPossessionTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "recipientRatio",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "recipients",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "rewards",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "claimed",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "removalTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "removeBLSPublicKeyAfterWaitTime",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "internalType": "struct BN256G1.G1Point",
          "name": "blsPubkey",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "sigs0",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs1",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs2",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs3",
              "type": "uint256"
            }
          ],
          "internalType": "struct IServiceNodeRewards.BLSSignatureParams",
          "name": "blsSignature",
          "type": "tuple"
        },
        {
          "internalType": "uint64[]",
          "name": "ids",
          "type": "uint64[]"
        }
      ],
      "name": "removeBLSPublicKeyWithSignature",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "renounceOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "rewardTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256[]",
          "name": "pkX",
          "type": "uint256[]"
        },
        {
          "internalType": "uint256[]",
          "name": "pkY",
          "type": "uint256[]"
        },
        {
          "internalType": "uint256[]",
          "name": "amounts",
          "type": "uint256[]"
        }
      ],
      "name": "seedPublicKeyList",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes",
          "name": "",
          "type": "bytes"
        }
      ],
      "name": "serviceNodeIDs",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "serviceNodes",
      "outputs": [
        {
          "components": [
            {
              "internalType": "uint64",
              "name": "next",
              "type": "uint64"
            },
            {
              "internalType": "uint64",
              "name": "prev",
              "type": "uint64"
            },
            {
              "internalType": "address",
              "name": "operator",
              "type": "address"
            },
            {
              "components": [
                {
                  "internalType": "uint256",
                  "name": "X",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "Y",
                  "type": "uint256"
                }
              ],
              "internalType": "struct BN256G1.G1Point",
              "name": "pubkey",
              "type": "tuple"
            },
            {
              "internalType": "uint256",
              "name": "leaveRequestTimestamp",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "deposit",
              "type": "uint256"
            },
            {
              "components": [
                {
                  "internalType": "address",
                  "name": "addr",
                  "type": "address"
                },
                {
                  "internalType": "uint256",
                  "name": "stakedAmount",
                  "type": "uint256"
                }
              ],
              "internalType": "struct IServiceNodeRewards.Contributor[]",
              "name": "contributors",
              "type": "tuple[]"
            }
          ],
          "internalType": "struct IServiceNodeRewards.ServiceNode",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "serviceNodesLength",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "count",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "newMax",
          "type": "uint256"
        }
      ],
      "name": "setBLSNonSignerThresholdMax",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "newRequirement",
          "type": "uint256"
        }
      ],
      "name": "setStakingRequirement",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "stakingRequirement",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "start",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "totalNodes",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "newOwner",
          "type": "address"
        }
      ],
      "name": "transferOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "unpause",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "recipientAddress",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "recipientRewards",
          "type": "uint256"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "sigs0",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs1",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs2",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "sigs3",
              "type": "uint256"
            }
          ],
          "internalType": "struct IServiceNodeRewards.BLSSignatureParams",
          "name": "blsSignature",
          "type": "tuple"
        },
        {
          "internalType": "uint64[]",
          "name": "ids",
          "type": "uint64[]"
        }
      ],
      "name": "updateRewardsBalance",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "updateServiceNodesLength",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
]
""")
erc20_contract_abi = json.loads("""
[
{
  "anonymous": false,
  "inputs": [
    {
      "indexed": true,
      "internalType": "address",
      "name": "owner",
      "type": "address"
    },
    {
      "indexed": true,
      "internalType": "address",
      "name": "spender",
      "type": "address"
    },
    {
      "indexed": false,
      "internalType": "uint256",
      "name": "value",
      "type": "uint256"
    }
  ],
  "name": "Approval",
  "type": "event"
},
{
  "anonymous": false,
  "inputs": [
    {
      "indexed": true,
      "internalType": "address",
      "name": "from",
      "type": "address"
    },
    {
      "indexed": true,
      "internalType": "address",
      "name": "to",
      "type": "address"
    },
    {
      "indexed": false,
      "internalType": "uint256",
      "name": "value",
      "type": "uint256"
    }
  ],
  "name": "Transfer",
  "type": "event"
},
{
  "inputs": [
    {
      "internalType": "address",
      "name": "owner",
      "type": "address"
    },
    {
      "internalType": "address",
      "name": "spender",
      "type": "address"
    }
  ],
  "name": "allowance",
  "outputs": [
    {
      "internalType": "uint256",
      "name": "",
      "type": "uint256"
    }
  ],
  "stateMutability": "view",
  "type": "function"
},
{
  "inputs": [
    {
      "internalType": "address",
      "name": "spender",
      "type": "address"
    },
    {
      "internalType": "uint256",
      "name": "value",
      "type": "uint256"
    }
  ],
  "name": "approve",
  "outputs": [
    {
      "internalType": "bool",
      "name": "",
      "type": "bool"
    }
  ],
  "stateMutability": "nonpayable",
  "type": "function"
},
{
  "inputs": [
    {
      "internalType": "address",
      "name": "account",
      "type": "address"
    }
  ],
  "name": "balanceOf",
  "outputs": [
    {
      "internalType": "uint256",
      "name": "",
      "type": "uint256"
    }
  ],
  "stateMutability": "view",
  "type": "function"
},
{
  "inputs": [],
  "name": "totalSupply",
  "outputs": [
    {
      "internalType": "uint256",
      "name": "",
      "type": "uint256"
    }
  ],
  "stateMutability": "view",
  "type": "function"
},
{
  "inputs": [
    {
      "internalType": "address",
      "name": "to",
      "type": "address"
    },
    {
      "internalType": "uint256",
      "name": "value",
      "type": "uint256"
    }
  ],
  "name": "transfer",
  "outputs": [
    {
      "internalType": "bool",
      "name": "",
      "type": "bool"
    }
  ],
  "stateMutability": "nonpayable",
  "type": "function"
},
{
  "inputs": [
    {
      "internalType": "address",
      "name": "from",
      "type": "address"
    },
    {
      "internalType": "address",
      "name": "to",
      "type": "address"
    },
    {
      "internalType": "uint256",
      "name": "value",
      "type": "uint256"
    }
  ],
  "name": "transferFrom",
  "outputs": [
    {
      "internalType": "bool",
      "name": "",
      "type": "bool"
    }
  ],
  "stateMutability": "nonpayable",
  "type": "function"
}
]
""")
