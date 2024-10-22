import Web3
import urllib.request
import json

class ContractServiceNode:
    next: int
    prev: int
    operator: int # Ed25519
    pubkey_x: int
    pubkey_y: int
    addedTimestamp: int
    leaveRequestTimestamp: int
    deposit: int
    contributors = []

class SNRewardsContract:
    def __init(self, contract_json: dict):
        self.web3_client = Web3.HTTPProvider('https://sepolia-rollup.arbitrum.io/rpc')
        self.contract    = self.web3_client.eth.contract(address='0x5FC8d32690cc91D4c39d9d3abcBD16989F875707', abi=contract_json['abi'])


    def service_node(self, id: int):
        call_result                  = self.contract.functions.serviceNodes(id).call()
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

        return result

def rpc_get_service_nodes():
    data = json.dumps({
        "jsonrpc": "2.0",
        "method": 'get_service_nodes',
        "params": [],
        "id": 1
    }).encode('utf-8')

    try:
        req = urllib.request.Request('http://localhost:6787/json_rpc', data=data, headers={'content-type': 'application/json'}, )
        with urllib.request.urlopen(req, timeout=2) as response:
            response      = response.read()
            response_json = json.loads(response)
            result        = int(response_json["result"], 16) # Parse chain ID from hex
    except Exception as e:
        raise RuntimeError("Failed to query {} from {}: {}".format(method, PROVIDER_URL, e))

    return result

get_sn_json = rpc_get_service_nodes();
with open()

sn_rewards = SNRewardsContract()
node       = sn_rewards.service_node(0)
while node.next != 0:
    sn_id: int = node.next
    node       = sn_rewards.service_node(sn_id)

    node_pubkey_bls = hex(node.pubkey_x) + hex(node.pubkey_y)
    # for sn_info in get_sn_json['result']['service_node_states']:
    #     if sn_info['pubkey_bls'] == 

    print("SN {} BLS {}".format(sn_id, node_pubkey_bls))
