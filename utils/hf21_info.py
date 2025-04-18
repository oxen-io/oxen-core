#!/usr/bin/env python3

import requests

#url_base = 'http://127.0.0.1:38157/'
url_base = 'http://127.0.0.1:38857/'

def json_rpc(method, params=None, timeout=50):
    json = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
    }
    if params:
        json["params"] = params

    return requests.post('{}/json_rpc'.format(url_base), json=json, timeout=timeout)

def get_service_nodes():
    return json_rpc('get_service_nodes').json()

addresses = {
    'dV3jKVomABtGr2cB75CvMciVoBsgUukBwQxdX586Q7pPKr3ohPBpH2h6QQDBG5j1D7CJBAWWamTTpbaRyPDTXFPW2nWRkwJg8': '0xB0CefD61ddB88176Fb972955341adC6c1d05230e',
    'dV22dkgs6Tgb1YiqwBzq8URRQ8gjzGJMd13bEt3CySkC6AVx6cnH35TSHHtHCnMf68jXHMpW68ZQ93ZxRBbUyAC929rGKPM8n': '0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF',
    'dV1ttpi6U815NHxh8QqK5LGNfWKHzhhxoWYAznsfiQtZWuxD44Jrw4uCAXZgPGw96zB7WPsNdcBRdWx7c8ANvzDx15sNugT7G': '0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e',
    'dV33LyGNcFQhqe84oiMUy9SAy1suyHNEJ53prwv18iBt6Kh5cejcHZ9W842SdQZ1izaMubG6Qg7P9fjxLagV8rsj18nfVvc46': '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'dV3YWiufwPxKFmpGbyVmQjHCyTTHeQc3ATW8XFNPymYKcoBa9Rbfj4nAaGihf4XJoqdsYnLNLSFWpJC5GJMMHyvs1Q75JiKai': '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'dV1owP8ZZmGQqeDDnwGCJVTCCRPwkDZTLPDqybnsdQHLCmb7c5H5hQ5XJ7QybPT83Za3YtMm325DhN7vNvJqU3ia1GetGj3tT': '',  # wallet6, not registered
    'dV2y4ThUjQKdKvCKVbwW5Ni9JBjEuYb7B66Qa6AaReVX6hXKDYsabJZ1xr9w3AKtXZNHZkKsbaN5Bi3dLyrZgyDJ1VnYRqvMS': '0xcccccccccccccccccccccccccccccccccccccccc',
    'dV1uNumdfREEvgUhZi91frgBrApRBB7QHeuVmi6eiZSx16LXxFkkxR5DDQYV2f4VkwH19kYLuxr6g7QDd6C7zwBU1pmDCY5mP': '0xdddddddddddddddddddddddddddddddddddddddd',
    'dV2pBi3wvr39EH8V9izJAtMDL6J9PS4i8ApRLJWD5LcxGc2uf5ADBJ84d1pTKWu2Kt1bJ5KuaA69ncxiyiS6eaGb35f5HD84P': '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    'dV1jxf26zLYZ9B34enQtDnLngpoLqNXxQMSM3RJvDyB4b8N6Mnjw7v4Sc9m13Jf6MfPWNcDEvwbGK93MirdHTnBH2F5Ednii9': '0xffffffffffffffffffffffffffffffffffffffff',
}

transition_bonus = {
    '0xB0CefD61ddB88176Fb972955341adC6c1d05230e': 64035886857040, # wallet1
    '0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e': 1658571428520,  # wallet2
    '0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF': 3577714285680,  # wallet3
    '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': 0,              # wallet4
    '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb': 0,              # wallet5
    '0xcccccccccccccccccccccccccccccccccccccccc': 6434285714320,   # wallet7
    '0xdddddddddddddddddddddddddddddddddddddddd': 0,              # wallet8
    '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee': 76368521000000,  # wallet9
    '0xffffffffffffffffffffffffffffffffffffffff': 12345123450,    # wallet10 (registered, but staked nothing)
}

conversion_ratio = 200 # testnet SENT stake is 200x testnet OXEN stake
staking_requirement = 20000000000000

# added for testnet to get all contributor addresses to put in the
# list above, as I did not have a list.
def get_addresses():

    addrs = {}
    for res in get_service_nodes()['result']['service_node_states']:
        for contributor in res['contributors']:
            addrs[contributor['address']] = 1

    for addr in addrs:
        print(addr)

def get_migration():
    bls_map = {}
    edkey_map = {}
    seed_list = []
    for res in get_service_nodes()['result']['service_node_states']:
        edkey = res['pubkey_ed25519']

        if not res['active']:
            print(f"Not migrating {edkey} because it's not active")
            continue

        if 'pubkey_bls' not in res:
            print(f"Not migrating {edkey} because it somehow does not have a bls pubkey set")
            continue

        if res['operator_address'] not in addresses:
            print(f"Not migrating {edkey} because its operator address is not registered to convert")
            continue

        if res['operator_address'] != res['contributors'][0]['address']:
            print(f"operator_address != first contributor address -- ({res['operator_address']} != {res['contributors'][0]['address']}")
            continue

        ok = True
        contributors = []
        contribution_sum = 0
        for cont in res['contributors']:
            if cont['address'] not in addresses or len(addresses[cont['address']]) == 0:
                ok = False
                break
            contributors.append({'address': addresses[cont['address']], 'amount': cont['amount'] * conversion_ratio})
            contribution_sum += cont['amount'] * conversion_ratio

        if not ok:
            print(f"Not migrating {edkey} because a contributor address is not registered to convert")
            continue

        # TODO: normalize if sum > req for the few nodes on mainnet with a higher stake sum
        if contribution_sum != staking_requirement:
            new_sum = 0
            for c in contributors:
                c['amount'] = int(c['amount'] / (contribution_sum + 1) * staking_requirement)
                new_sum += c['amount']
            if new_sum < staking_requirement:
                contributors[0]['amount'] += staking_requirement - new_sum

        seed_list.append({
            'bls_pubkey': res['pubkey_bls'],
            'ed25519_pubkey': edkey,
            'contributors': contributors,
        })

        bls_map[edkey] = res['pubkey_bls']

        if res['service_node_pubkey'] != edkey:
            edkey_map[res['service_node_pubkey']] = edkey

    return [bls_map, edkey_map, seed_list]

def print_address_migration():
    print("Printing C++ for oxen -> eth mapping\n")
    for addr in addresses:
        if len(addresses[addr]):
            print(f"{{\"{addr}\"s, tools::make_from_hex_guts<eth::address>(\"{addresses[addr]}\"s)}},")
    print("")

def print_migration():
    bls_map, edkey_map, seed_list = get_migration()

    print_address_migration()

    print("Printing C++ for monero key -> ed25519 key mapping\n")
    for monero_key in edkey_map:
        print(f"{{tools::make_from_hex_guts<crypto::public_key>(\"{monero_key}\"s), tools::make_from_hex_guts<crypto::ed25519_public_key>(\"{edkey_map[monero_key]}\"s)}},")
    print("")

    print("Printing C++ for ed -> bls mapping\n")
    for edkey in bls_map:
        print(f"{{tools::make_from_hex_guts<crypto::ed25519_public_key>(\"{edkey}\"s), tools::make_from_hex_guts<eth::bls_public_key>(\"{bls_map[edkey]}\"s)}},")
    print("")

    print("Printing C++ for transition bonus\n")
    for addr in transition_bonus:
        print(f"{{tools::make_from_hex_guts<eth::address>(\"{addr}\"s), {transition_bonus[addr]}}},")
    print("")

    print("Printing python for seeding contract\n")
    from pprint import pp
    pp(seed_list)

print_migration()
#print_address_migration()
#get_addresses()
